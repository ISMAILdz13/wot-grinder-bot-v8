#!/usr/bin/env python3
"""WoT Bot v36 — RSA-encrypted LoginRequest

Server said: "Unencrypted login prohibited by server configuration"
→ Second LoginRequest must be RSA-encrypted with OAEP-SHA1

From wg-toolkit-rs:
  - RsaWriter uses Oaep::new::<Sha1>() 
  - clear_block_cap = key.size() - 41 - 1 = 214 bytes (RSA-2048)
  - LoginRequest body: [protocol(4B)] [encrypted_flag(1B)] [RSA_encrypted(LogOnParams)]
  - LogOnParams: [flags] [username] [password] [bf_key] [context] [digest?] [nonce]
"""
import socket, struct, os, hashlib, time, array

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1

exec(open('/root/wot-grinder-bot-v8/bw_bot_v3.py' if os.path.exists('/root/wot-grinder-bot-v8/bw_bot_v3.py') else '/tmp/bw_bot_v3.py').read().split('def run(')[0])

def pack_u24(n):
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[:3]
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_u24(len(b)) + b

def build_message_v16(elem_id, body):
    return struct.pack("<BH", elem_id, len(body)) + body

def build_request_v16(elem_id, rid, body):
    return struct.pack("<BH", elem_id, len(body)) + struct.pack("<IH", rid, 0) + body

def build_unencrypted_login_body(protocol):
    """Unencrypted: [protocol(4B)] [encrypted_flag=0(1B)] [LogOnParams]"""
    bf = os.urandom(16)
    # LogOnParams: [flags=0] [username] [password] [bf_key] [context] [nonce]
    logon = struct.pack("<B", 0)
    logon += pack_str("guest")      # username
    logon += pack_str("")           # password
    logon += pack_str(bf)           # blowfish_key
    logon += pack_str("")           # context (empty)
    logon += struct.pack("<I", 0)   # nonce
    return struct.pack("<I", protocol) + struct.pack("<B", 0) + logon, bf

def build_encrypted_login_body(protocol, bf_key, rsa_key_pem):
    """Encrypted: [protocol(4B)] [encrypted_flag=1(1B)] [RSA_OAEP_SHA1(LogOnParams)]"""
    # LogOnParams: [flags=0] [username] [password] [bf_key] [context] [nonce]
    logon = struct.pack("<B", 0)
    logon += pack_str("guest")
    logon += pack_str("")
    logon += pack_str(bf_key)
    logon += pack_str("")           # context
    logon += struct.pack("<I", 0)   # nonce
    
    # RSA-OAEP-SHA1 encrypt
    key = RSA.importKey(rsa_key_pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    encrypted = cipher.encrypt(logon)  # 256 bytes for RSA-2048
    
    return struct.pack("<I", protocol) + struct.pack("<B", 1) + encrypted

def parse_reply_full(data):
    if len(data) < 6: return None
    content = data[6:]
    if len(content) < 5 or content[0] != 0xFF: return None
    length = struct.unpack_from("<I", content, 1)[0]
    rdata = content[5:5+length]
    if len(rdata) < 5: return None
    rid = struct.unpack_from("<I", rdata, 0)[0]
    status = rdata[4]
    extra = rdata[5:]
    return (status, rid, extra)

def parse_cuckoo_challenge(extra):
    pos = 0
    first = extra[pos]; pos += 1
    if first >= 255: slen = int.from_bytes(extra[pos:pos+3], 'little'); pos += 3
    else: slen = first
    challenge_type = extra[pos:pos+slen].decode('utf-8', errors='replace'); pos += slen
    first = extra[pos]; pos += 1
    if first >= 255: klen = int.from_bytes(extra[pos:pos+3], 'little'); pos += 3
    else: klen = first
    key_prefix = extra[pos:pos+klen]; pos += klen
    max_nonce = struct.unpack_from("<Q", extra, pos)[0] if pos + 8 <= len(extra) else 65536; pos += 8
    return challenge_type, key_prefix, max_nonce

# ============ SipHash-2-4 + Cuckoo ============
SIZESHIFT = 20; PROOFSIZE = 42; SIZE = 1 << SIZESHIFT
HALFSIZE = SIZE // 2; NODEMASK = HALFSIZE - 1; MAXPATHLEN = 8192
MASK64 = 0xFFFFFFFFFFFFFFFF

def setheader(header):
    hdrkey = hashlib.sha256(header.encode() if isinstance(header, str) else header).digest()
    k0 = struct.unpack_from("<Q", hdrkey, 0)[0]
    k1 = struct.unpack_from("<Q", hdrkey, 8)[0]
    return [(k0 ^ 0x736f6d6570736575) & MASK64, (k1 ^ 0x646f72616e646f6d) & MASK64,
            (k0 ^ 0x6c7967656e657261) & MASK64, (k1 ^ 0x7465646279746573) & MASK64]

def rotl64(x, b): return ((x << b) | (x >> (64 - b))) & MASK64

def sipround(v0, v1, v2, v3):
    v0=(v0+v1)&MASK64; v2=(v2+v3)&MASK64; v1=rotl64(v1,13); v3=rotl64(v3,16)
    v1^=v0; v3^=v2; v0=rotl64(v0,32); v2=(v2+v1)&MASK64; v0=(v0+v3)&MASK64
    v1=rotl64(v1,17); v3=rotl64(v3,21); v1^=v2; v3^=v0; v2=rotl64(v2,32)
    return v0,v1,v2,v3

def siphash24(ctx, nonce):
    v0,v1,v2,v3 = ctx; v3=(v3^nonce)&MASK64
    v0,v1,v2,v3=sipround(v0,v1,v2,v3); v0,v1,v2,v3=sipround(v0,v1,v2,v3)
    v0=(v0^nonce)&MASK64; v2=(v2^0xFF)&MASK64
    for _ in range(4): v0,v1,v2,v3=sipround(v0,v1,v2,v3)
    return (v0^v1^v2^v3)&MASK64

def sipnode(ctx, nonce, uorv): return siphash24(ctx, 2*nonce+uorv) & NODEMASK
def sipedge(ctx, nonce): return sipnode(ctx,nonce,0), sipnode(ctx,nonce,1)

def solve_cuckoo(header, easiness, attempt=1):
    ctx = setheader(header)
    cuckoo = array.array('I', [0]*(SIZE+1))
    us = array.array('I', [0]*MAXPATHLEN); vs = array.array('I', [0]*MAXPATHLEN)
    t0 = time.time(); cycles = 0
    for nonce in range(easiness):
        u0,v0 = sipedge(ctx,nonce); u0+=1; v0+=1+HALFSIZE
        u=cuckoo[u0]; v=cuckoo[v0]
        if u==v0 or v==u0: continue
        us[0]=u0; vs[0]=v0
        nu=0; node=u
        while node:
            nu+=1
            if nu>=MAXPATHLEN: return None, 0
            us[nu]=node; node=cuckoo[node]
        nv=0; node=v
        while node:
            nv+=1
            if nv>=MAXPATHLEN: return None, 0
            vs[nv]=node; node=cuckoo[node]
        if us[nu]==vs[nv]:
            m=min(nu,nv); nu-=m; nv-=m
            while us[nu]!=vs[nv]: nu+=1; nv+=1
            cl=nu+nv+1; cycles+=1
            if cl==PROOFSIZE:
                print(f"    [{attempt}] FOUND 42-cycle at {nonce} ({nonce*100//easiness}%)!")
                sol = find_sol(ctx, us, nu, vs, nv, easiness)
                print(f"    Solved in {time.time()-t0:.1f}s, {cycles} cycles")
                return sol, time.time()-t0
            continue
        if nu<nv:
            while nu: nu-=1; cuckoo[us[nu+1]]=us[nu]
            cuckoo[u0]=v0
        else:
            while nv: nv-=1; cuckoo[vs[nv+1]]=vs[nv]
            cuckoo[v0]=u0
        if nonce%100000==0 and nonce>0:
            print(f"    ... {nonce}/{easiness} ({nonce*100//easiness}%), {time.time()-t0:.1f}s, {cycles}c")
    print(f"    [{attempt}] No 42-cycle after {time.time()-t0:.1f}s, {cycles} cycles")
    return None, 0

def find_sol(ctx, us, nu, vs, nv, easiness):
    cycle = {(us[0], vs[0])}
    i = nu
    while i > 0: i -= 1; cycle.add((us[(i+1)&~1], us[i|1]))
    i = nv
    while i > 0: i -= 1; cycle.add((vs[i|1], vs[(i+1)&~1]))
    print(f"    Cycle: {len(cycle)} edges")
    sol = []
    for n in range(easiness):
        u = sipnode(ctx,n,0)+1; v = sipnode(ctx,n,1)+1+HALFSIZE
        if (u,v) in cycle:
            sol.append(n)
            cycle.discard((u,v))
            if not cycle:
                break
    print(f"    Found {len(sol)} nonces")
    return sol

# ============ RSA Keys ============
KEY_WOT = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyjeVAXWfhj02sEGd8BnK
Z2y8Twnwefea2R3QulJurdD0lmFPyczP2Z54Lju7TAMYtJ4o02MTkm2BKtmd7WOt
yFxyVEDdRH65D2PK2bEzptve6JoBQD9uZQZn3Vi4MmMzrlWkkF9NkJ84A45ZxocN
M8oLTjfhdkLvDMvvG1h8oc4KAD9uGv3FRgQSkIZtD5ro+stOvQiiDj4OQd5o9+M0
JS36ks1C69vjMsOWC+gFH/rdDEEoFOwGIM6Q8iTYb2rjHeyAP2fNPGf+X7l73+yV
s7lm2Bh2WezlZSDikycb1r3FvB4wUhohahwfuORGdMtxidzIQzNdcFo0Gg+dg7wc
hwIDAQAB
-----END PUBLIC KEY-----"""

KEY_BW = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7/MNyWDdFpXhpFTO9LHz
CUQPYv2YP5rqJjUoxAFa3uKiPKbRvVFjUQ9lGHyjCmtixBbBqCTvDWu6Zh9Imu3x
KgCJh6NPSkddH3l+C+51FNtu3dGntbSLWuwi6Au1ErNpySpdx+Le7YEcFviY/ClZ
ayvVdA0tcb5NVJ4Axu13NvsuOUMqHxzCZRXCe6nyp6phFP2dQQZj8QZp0VsMFvhh
MsZ4srdFLG0sd8qliYzSqIyEQkwO8TQleHzfYYZ90wPTCOvMnMe5+zCH0iPJMisP
YB60u6lK9cvDEeuhPH95TPpzLNUFgmQIu9FU8PkcKA53bj0LWZR7v86Oco6vFg6V
sQIDAQAB
-----END PUBLIC KEY-----"""

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=10, max_attempts=15):
    PROTOCOL = 285278213
    
    print(f"\n{'='*55}")
    print(f"  WoT Bot v36 — RSA Encrypted Login")
    print(f"  Protocol: 17.1.0 (5) = {PROTOCOL}")
    print(f"  RSA: OAEP-SHA1 (from wg-toolkit-rs source)")
    print(f"  Max attempts: {max_attempts}")
    print(f"  {server}:{port}")
    print(f"{'='*55}")
    
    seen_headers = set()
    
    for attempt in range(1, max_attempts + 1):
        # Fresh socket each attempt to get new challenge
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        rid = 1
        
        # PING
        if attempt == 1:
            print(f"\n[1] PING...")
        sock.sendto(ping_packet(rid=rid), (server, port))
        try:
            sock.recvfrom(4096)
            if attempt == 1: print(f"    PING OK")
            rid += 1
        except socket.timeout:
            sock.close()
            # Try p2
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            server, port = "login.p2.worldoftanks.eu", 20018
            sock.sendto(ping_packet(rid=rid), (server, port))
            try:
                sock.recvfrom(4096); rid += 1
            except:
                print(f"    PING failed"); sock.close(); continue
        
        # Get challenge
        print(f"\n[{attempt+1}] Attempt {attempt}/{max_attempts}...")
        login_body, bf_key = build_unencrypted_login_body(PROTOCOL)
        elem = build_request_v16(0x00, rid, login_body)
        pkt = _pkt(elem, first_req=0)
        sock.sendto(pkt, (server, port))
        rid += 1
        
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            print(f"    Timeout"); sock.close(); continue
        
        result = parse_reply_full(data)
        if not result: print(f"    Parse failed"); sock.close(); continue
        status, _, extra = result
        if status != 0x42: print(f"    Status: 0x{status:02X}"); sock.close(); continue
        
        challenge_type, key_prefix, max_nonce = parse_cuckoo_challenge(extra)
        header = key_prefix.decode('utf-8', errors='replace')
        
        # Skip duplicate challenges
        if header in seen_headers:
            print(f"    Duplicate challenge: {header} — skipping (reconnect for new)")
            sock.close()
            continue
        seen_headers.add(header)
        
        print(f"    Header: {header}")
        print(f"    Max nonce: {max_nonce}")
        
        # Solve
        print(f"    Solving Cuckoo Cycle...")
        solution, solve_duration = solve_cuckoo(header, max_nonce, attempt)
        if solution is None:
            print(f"    No 42-cycle, retry with new challenge...")
            sock.close(); continue
        if len(solution) != 42:
            print(f"    Wrong count"); sock.close(); continue
        print(f"    Solution: {len(solution)} nonces")
        
        # Build combined packet with ENCRYPTED login
        cr_body = struct.pack("<f", solve_duration)
        cr_body += pack_str(key_prefix)
        cr_body += b''.join(struct.pack("<I", n) for n in solution)
        cr_elem = build_message_v16(0x03, cr_body)
        
        # Try both RSA keys
        for key_name, key_pem in [("KEY_WOT", KEY_WOT), ("KEY_BW", KEY_BW)]:
            print(f"\n    Trying {key_name} with RSA-OAEP-SHA1...")
            enc_login_body = build_encrypted_login_body(PROTOCOL, bf_key, key_pem)
            login_elem = build_request_v16(0x00, rid, enc_login_body)
            content = cr_elem + login_elem
            first_req = len(cr_elem)
            pkt = _pkt(content, first_req=first_req)
            
            print(f"    Packet: {len(pkt)}B (CR={len(cr_elem)}B msg + Login={len(login_elem)}B req)")
            sock.sendto(pkt, (server, port))
            
            try:
                data, _ = sock.recvfrom(4096)
                result = parse_reply_full(data)
                if result:
                    status, reply_rid, extra = result
                    print(f"\n    *** Response with {key_name}: 0x{status:02X} ***")
                    if extra:
                        print(f"    Extra ({len(extra)} bytes): {extra[:120].hex()}")
                        try:
                            msg = extra.decode('utf-8', errors='replace')[:200]
                            if msg.strip(): print(f"    Message: {msg}")
                        except: pass
                    
                    if status == 0x01:
                        print(f"\n    === LOGIN SUCCESS! ===")
                        print(f"    BF key: {bf_key.hex()}")
                        if len(extra) >= 10:
                            ip = '.'.join(str(b) for b in extra[:4])
                            p = struct.unpack_from("<H", extra, 4)[0]
                            lk = struct.unpack_from("<I", extra, 6)[0]
                            print(f"    Base app: {ip}:{p}")
                            print(f"    Login key: {lk}")
                    elif status == 0x40:
                        if b"Unencrypted" in extra:
                            print(f"    -> Wrong RSA key")
                        else:
                            print(f"    -> Different MalformedRequest")
                    elif status == 0x47:
                        print(f"    -> Invalid User — RSA ACCEPTED! Need real WG credentials")
                    elif status == 0x48:
                        print(f"    -> Invalid Password — RSA ACCEPTED!")
                    elif status == 0x42:
                        print(f"    -> New challenge — solution expired")
                    elif status == 0x55:
                        print(f"    -> ChallengeError — solution rejected")
                    else:
                        print(f"    -> Status: 0x{status:02X}")
                    
                    sock.close()
                    return  # Done!
                else:
                    print(f"    No reply parsed")
                    sock.close()
                    return
            except socket.timeout:
                print(f"    Timeout with {key_name}")
                continue
        
        sock.close()
    
    print(f"\nExhausted {max_attempts} attempts. Seen {len(seen_headers)} unique challenges.")

if __name__ == "__main__":
    run()

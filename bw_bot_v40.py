#!/usr/bin/env python3
"""WoT Bot v40 — COMPLETE REWRITE, no old imports

Fixes from wg-toolkit-rs deep research:
1. 56-byte Blowfish key (not 16)
2. Random nonce (not 0)
3. Context = version string (not empty)
4. SEPARATE packets: ChallengeResponse (msg) then LoginRequest (req)
5. Correct packet format: prefix + flags + body + footer
6. Correct element format: length = body only (not rid+next+body)
7. first_request_offset = offset + 2 (PACKET_FLAGS_LEN)
8. RSA-OAEP-SHA1 (confirmed from source)
9. packed_u24 string encoding (wg-toolkit-rs format)
"""
import socket, struct, os, hashlib, time, array, random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1

# ============ Constants ============
MASK64 = 0xFFFFFFFFFFFFFFFF
SIZESHIFT = 20; PROOFSIZE = 42; SIZE = 1 << SIZESHIFT
HALFSIZE = SIZE // 2; NODEMASK = HALFSIZE - 1; MAXPATHLEN = 8192

FLAG_HAS_REQUESTS = 0x0001

# ============ Packet Builder (from wg-toolkit-rs, self-contained) ============
def _prefix(raw):
    """XorShift prefix from bytes 4-12 of raw packet"""
    p0 = struct.unpack_from("<I", raw, 4)[0] if len(raw) >= 8 else 0
    p1 = struct.unpack_from("<I", raw, 8)[0] if len(raw) >= 12 else 0
    a = (p0 + p1) & 0xFFFFFFFF
    b = (a << 13) & 0xFFFFFFFF
    c = ((b ^ a) >> 17) & 0xFFFFFFFF
    return (c ^ b ^ a ^ ((c ^ b ^ a) << 5)) & 0xFFFFFFFF

def build_packet(content, first_req=None):
    """Build a complete packet: [prefix(4B)] [flags(2B)] [content] [footer]"""
    flags = 0
    footer = b""
    if first_req is not None:
        flags |= FLAG_HAS_REQUESTS
        footer = struct.pack("<H", first_req + 2)  # +2 = PACKET_FLAGS_LEN
    raw = struct.pack("<IH", 0, flags) + content + footer
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def build_message_v16(elem_id, body):
    """MESSAGE element: [id(1B)] [len(2B)] [body]"""
    return struct.pack("<BH", elem_id, len(body)) + body

def build_request_v16(elem_id, rid, body):
    """REQUEST element: [id(1B)] [len(2B)] [rid(4B)] [next(2B=0)] [body]"""
    return struct.pack("<BH", elem_id, len(body)) + struct.pack("<IH", rid, 0) + body

def build_ping(rid):
    """PING: element 0x02, Fixed(1)"""
    return build_request_v16(0x02, rid, struct.pack("<B", 0))

# ============ Packed string encoding ============
def pack_u24(n):
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[:3]
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_u24(len(b)) + b

# ============ LogOnParams ============
def build_login_body(protocol, bf_key, encrypted=False, rsa_key_pem=None, context=""):
    """Build login request body
    [protocol(4B)] [encrypted_flag(1B)] [LogOnParams or RSA(LogOnParams)]
    LogOnParams: [flags(1B)] [username] [password] [bf_key] [context] [nonce]
    """
    # LogOnParams (packed_u24 encoding from wg-toolkit-rs)
    logon = struct.pack("<B", 0)          # flags (no digest)
    logon += pack_str("guest")            # username
    logon += pack_str("")                 # password (empty for guest/token login)
    logon += pack_str(bf_key)            # blowfish_key
    logon += pack_str(context)           # context (version string)
    logon += struct.pack("<I", random.randint(1, 0xFFFFFFFF))  # nonce (random!)
    
    if encrypted and rsa_key_pem:
        key = RSA.importKey(rsa_key_pem)
        cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
        encrypted_data = cipher.encrypt(logon)
        return struct.pack("<I", protocol) + struct.pack("<B", 1) + encrypted_data
    else:
        return struct.pack("<I", protocol) + struct.pack("<B", 0) + logon

# ============ ChallengeResponse ============
def build_challenge_response(duration, key_prefix, solution):
    """ChallengeResponse body: [duration(f32)] [key: packed_blob] [42×u32]"""
    body = struct.pack("<f", duration)
    body += pack_str(key_prefix)
    body += b''.join(struct.pack("<I", n) for n in solution)
    return body

# ============ Reply parser ============
def parse_reply(data):
    if len(data) < 6: return None
    content = data[6:]
    # Parse footer
    pos = len(content)
    # Check for HAS_REQUESTS footer
    flags = struct.unpack_from("<H", data, 4)[0]
    if flags & FLAG_HAS_REQUESTS:
        pos -= 2
    # Find reply element (0xFF)
    elem = content[:pos]
    if not elem or elem[0] != 0xFF: return None
    length = struct.unpack_from("<I", elem, 1)[0]
    rdata = elem[5:5+length]
    if len(rdata) < 5: return None
    rid = struct.unpack_from("<I", rdata, 0)[0]
    status = rdata[4]
    extra = rdata[5:]
    return (status, rid, extra)

def parse_challenge(extra):
    """Parse Cuckoo challenge from login response"""
    pos = 0
    # challenge type string
    first = extra[pos]; pos += 1
    if first >= 255: slen = int.from_bytes(extra[pos:pos+3], 'little'); pos += 3
    else: slen = first
    pos += slen
    # key_prefix blob
    first = extra[pos]; pos += 1
    if first >= 255: klen = int.from_bytes(extra[pos:pos+3], 'little'); pos += 3
    else: klen = first
    key_prefix = extra[pos:pos+klen]; pos += klen
    # max_nonce (u64)
    max_nonce = struct.unpack_from("<Q", extra, pos)[0] if pos + 8 <= len(extra) else 65536
    return key_prefix, max_nonce

# ============ SipHash-2-4 + Cuckoo ============
def setheader(header):
    hk = hashlib.sha256(header.encode() if isinstance(header, str) else header).digest()
    k0 = struct.unpack_from("<Q", hk, 0)[0]; k1 = struct.unpack_from("<Q", hk, 8)[0]
    return [(k0^0x736f6d6570736575)&MASK64, (k1^0x646f72616e646f6d)&MASK64,
            (k0^0x6c7967656e657261)&MASK64, (k1^0x7465646279746573)&MASK64]

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

def sipnode(ctx, n, u): return siphash24(ctx, 2*n+u) & NODEMASK

def solve_cuckoo(header, easiness, attempt=1):
    ctx = setheader(header)
    ck = array.array('I', [0]*(SIZE+1))
    us = array.array('I', [0]*MAXPATHLEN); vs = array.array('I', [0]*MAXPATHLEN)
    t0 = time.time(); c = 0
    for n in range(easiness):
        u0 = sipnode(ctx,n,0)+1; v0 = sipnode(ctx,n,1)+1+HALFSIZE
        u = ck[u0]; v = ck[v0]
        if u==v0 or v==u0: continue
        us[0]=u0; vs[0]=v0; nu=0; node=u
        while node:
            nu+=1
            if nu>=MAXPATHLEN: return None,0
            us[nu]=node; node=ck[node]
        nv=0; node=v
        while node:
            nv+=1
            if nv>=MAXPATHLEN: return None,0
            vs[nv]=node; node=ck[node]
        if us[nu]==vs[nv]:
            m=min(nu,nv); nu-=m; nv-=m
            while us[nu]!=vs[nv]: nu+=1; nv+=1
            cl=nu+nv+1; c+=1
            if cl==PROOFSIZE:
                print(f"    [{attempt}] FOUND 42-cycle at {n} ({n*100//easiness}%)!")
                sol=find_sol(ctx,us,nu,vs,nv,easiness)
                print(f"    Solved in {time.time()-t0:.1f}s, {c} cycles")
                return sol, time.time()-t0
            continue
        if nu<nv:
            while nu: nu-=1; ck[us[nu+1]]=us[nu]
            ck[u0]=v0
        else:
            while nv: nv-=1; ck[vs[nv+1]]=vs[nv]
            ck[v0]=u0
        if n%100000==0 and n>0: print(f"    ... {n}/{easiness} ({n*100//easiness}%), {time.time()-t0:.1f}s, {c}c")
    print(f"    [{attempt}] No 42-cycle after {time.time()-t0:.1f}s, {c} cycles")
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
            sol.append(n); cycle.discard((u,v))
            if not cycle: break
    print(f"    Found {len(sol)} nonces")
    return sol

# ============ RSA Keys ============
KEY_BW = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7/MNyWDdFpXhpFTO9LHz
CUQPYv2YP5rqJjUoxAFa3uKiPKbRvVFjUQ9lGHyjCmtixBbBqCTvDWu6Zh9Imu3x
KgCJh6NPSkddH3l+C+51FNtu3dGntbSLWuwi6Au1ErNpySpdx+Le7YEcFviY/ClZ
ayvVdA0tcb5NVJ4Axu13NvsuOUMqHxzCZRXCe6nyp6phFP2dQQZj8QZp0VsMFvhh
MsZ4srdFLG0sd8qliYzSqIyEQkwO8TQleHzfYYZ90wPTCOvMnMe5+zCH0iPJMisP
YB60u6lK9cvDEeuhPH95TPpzLNUFgmQIu9FU8PkcKA53bj0LWZR7v86Oco6vFg6V
sQIDAQAB
-----END PUBLIC KEY-----"""

KEY_WOT = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyjeVAXWfhj02sEGd8BnK
Z2y8Twnwefea2R3QulJurdD0lmFPyczP2Z54Lju7TAMYtJ4o02MTkm2BKtmd7WOt
yFxyVEDdRH65D2PK2bEzptve6JoBQD9uZQZn3Vi4MmMzrlWkkF9NkJ84A45ZxocN
M8oLTjfhdkLvDMvvG1h8oc4KAD9uGv3FRgQSkIZtD5ro+stOvQiiDj4OQd5o9+M0
JS36ks1C69vjMsOWC+gFH/rdDEEoFOwGIM6Q8iTYb2rjHeyAP2fNPGf+X7l73+yV
s7lm2Bh2WezlZSDikycb1r3FvB4wUhohahwfuORGdMtxidzIQzNdcFo0Gg+dg7wc
hwIDAQAB
-----END PUBLIC KEY-----"""

# Context strings to try (from wg-toolkit-rs: "eu_1.19.1_4")
CONTEXTS = ["", "eu_1.19.1_4", "17.1.0 (5)"]

KEYS = [("KEY_BW", KEY_BW), ("KEY_WOT", KEY_WOT)]

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=15, max_attempts=15):
    PROTOCOL = 285278213
    print(f"\n{'='*55}")
    print(f"  WoT Bot v40 — COMPLETE REWRITE")
    print(f"  Protocol: 17.1.0 (5) = {PROTOCOL}")
    print(f"  BF key: 56 bytes, nonce: random")
    print(f"  Separate CR + Login packets")
    print(f"  RSA: OAEP-SHA1, packed_u24+context")
    print(f"{'='*55}")
    
    seen_headers = set()
    combo_idx = 0
    
    for attempt in range(1, max_attempts + 1):
        if attempt > 1: time.sleep(30)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        rid = 1
        
        # PING
        sock.sendto(build_ping(rid), (server, port))
        try:
            sock.recvfrom(4096); rid += 1
        except socket.timeout:
            sock.close()
            server, port = "login.p2.worldoftanks.eu", 20018
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(build_ping(rid), (server, port))
            try: sock.recvfrom(4096); rid += 1
            except: sock.close(); continue
        
        # Step 1: Unencrypted login to get challenge
        bf_key = os.urandom(56)  # 56-BYTE KEY!
        login_body = build_login_body(PROTOCOL, bf_key, encrypted=False, context="")
        elem = build_request_v16(0x00, rid, login_body)
        pkt = build_packet(elem, first_req=0)
        sock.sendto(pkt, (server, port))
        rid += 1
        
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            sock.close(); continue
        
        result = parse_reply(data)
        if not result: sock.close(); continue
        status, _, extra = result
        if status != 0x42: sock.close(); continue
        
        key_prefix, max_nonce = parse_challenge(extra)
        header = key_prefix.decode('utf-8', errors='replace')
        if header in seen_headers: sock.close(); continue
        seen_headers.add(header)
        
        print(f"\n[{attempt}] Challenge: {header}")
        
        # Step 2: Solve Cuckoo
        solution, duration = solve_cuckoo(header, max_nonce, attempt)
        if solution is None or len(solution) != 42:
            print(f"    No 42-cycle, retry..."); sock.close(); continue
        print(f"    Solution: {len(solution)} nonces")
        
        # Step 3: Send ChallengeResponse as SEPARATE packet (MESSAGE, no request)
        cr_body = build_challenge_response(duration, key_prefix, solution)
        cr_elem = build_message_v16(0x03, cr_body)  # MESSAGE: no rid/next
        cr_pkt = build_packet(cr_elem, first_req=None)  # No HAS_REQUESTS
        sock.sendto(cr_pkt, (server, port))
        print(f"    Sent ChallengeResponse ({len(cr_pkt)}B)")
        
        # Step 4: Send encrypted LoginRequest as SEPARATE packet (REQUEST)
        key_name, key_pem = KEYS[combo_idx % 2]
        context = CONTEXTS[(combo_idx // 2) % 3]
        combo_idx += 1
        
        print(f"    Key: {key_name} | Context: '{context}'")
        enc_login = build_login_body(PROTOCOL, bf_key, encrypted=True, rsa_key_pem=key_pem, context=context)
        login_elem = build_request_v16(0x00, rid, enc_login)
        login_pkt = build_packet(login_elem, first_req=0)
        sock.sendto(login_pkt, (server, port))
        rid += 1
        print(f"    Sent LoginRequest ({len(login_pkt)}B)")
        
        try:
            data, _ = sock.recvfrom(4096)
            result = parse_reply(data)
            if result:
                status, _, extra = result
                print(f"    Response: 0x{status:02X}")
                if extra:
                    try: msg = extra.decode('utf-8', errors='replace')[:200]
                    except: msg = ""
                    if msg.strip(): print(f"    Message: {msg}")
                    else: print(f"    Extra: {extra[:60].hex()}")
                
                if status == 0x01:
                    print(f"\n    === LOGIN SUCCESS! ===")
                    sock.close(); return
                elif status == 0x47:
                    print(f"    -> Invalid User — KEY + FORMAT CORRECT!")
                    sock.close(); return
                elif status == 0x48:
                    print(f"    -> Invalid Password — KEY + FORMAT CORRECT!")
                    sock.close(); return
                elif b"destream" in extra:
                    print(f"    -> destream (wrong key or format)")
                elif b"Unencrypted" in extra:
                    print(f"    -> Unencrypted (encryption not detected)")
                else:
                    print(f"    -> NEW: 0x{status:02X}")
            else:
                print(f"    No reply")
        except socket.timeout:
            print(f"    Timeout")
        
        sock.close()
    
    print(f"\nExhausted {max_attempts} attempts, tried {combo_idx} combos.")

if __name__ == "__main__":
    run()

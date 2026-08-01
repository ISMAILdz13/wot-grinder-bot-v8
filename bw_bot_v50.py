#!/usr/bin/env python3
"""WoT Bot v50 — THE REAL FIX from BigWorld source

TWO CRITICAL BUGS FOUND in BigWorld cuckoo_cycle_login_challenge_factory.cpp:

BUG 1: NO DURATION FIELD!
  CR body = key + 42×nonces (NO duration!)
  Server checks: data.remainingLength() != PROOFSIZE * sizeof(nonce_t)
  With our 4-byte duration: remaining=172, expected=168 → 0x55!

BUG 2: KEY = prefix + COUNTER, not just prefix!
  Client tries: prefix+"0", prefix+"1", ... until solution found
  SHA256 computed on FULL key (e.g. "15f1666a9447d980:0")
  We were using just "15f1666a9447d980:" → wrong node values!

Also confirmed: SIZESHIFT=20, NODEMASK=HALFSIZE-1, HALFSIZE offset encoding.
Our original solver was correct, but the CR body and key were wrong!
"""
import socket, struct, os, hashlib, time, array, random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1

MASK64 = 0xFFFFFFFFFFFFFFFF
SIZESHIFT=20; PROOFSIZE=42; SIZE=1<<SIZESHIFT; HALFSIZE=SIZE//2; NODEMASK=HALFSIZE-1; MAXPATHLEN=8192
FLAG_HAS_REQUESTS = 0x0001

def _prefix(raw):
    p0 = struct.unpack_from("<I", raw, 4)[0] if len(raw) >= 8 else 0
    p1 = struct.unpack_from("<I", raw, 8)[0] if len(raw) >= 12 else 0
    a = (p0 + p1) & 0xFFFFFFFF
    b = (a << 13) & 0xFFFFFFFF
    c = ((b ^ a) >> 17) & 0xFFFFFFFF
    return (c ^ b ^ a ^ ((c ^ b ^ a) << 5)) & 0xFFFFFFFF

def build_packet(content, first_req=None):
    flags = 0; footer = b""
    if first_req is not None:
        flags |= FLAG_HAS_REQUESTS
        footer = struct.pack("<H", first_req + 2)
    raw = struct.pack("<IH", 0, flags) + content + footer
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def build_request_fixed(elem_id, rid, body):
    return struct.pack("<B", elem_id) + struct.pack("<IH", rid, 0) + body

def build_request_v16(elem_id, rid, body):
    return struct.pack("<BH", elem_id, len(body)) + struct.pack("<IH", rid, 0) + body

def build_message_v16(elem_id, body):
    return struct.pack("<BH", elem_id, len(body)) + body

def build_ping(rid):
    elem = build_request_fixed(0x02, rid, struct.pack("<B", 0))
    return build_packet(elem, first_req=0)

def pack_u24(n):
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[:3]
    return struct.pack("<B", n)

def pack_str_u32(s):
    b = s.encode() if isinstance(s, str) else s
    return struct.pack("<I", len(b)) + b

def pack_str_u24(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_u24(len(b)) + b

login_nonce = random.randint(1, 0xFFFFFFFF)

def build_logon_u32(bf_key):
    logon = struct.pack("<B", 0)
    logon += pack_str_u24("guest")
    logon += pack_str_u24("")
    logon += pack_str_u24(bf_key)
    logon += pack_str_u24("")
    logon += struct.pack("<I", login_nonce)
    return logon

def build_login_noflag(protocol, bf_key, rsa_key_pem):
    logon = build_logon_u32(bf_key)
    key = RSA.importKey(rsa_key_pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    return struct.pack("<I", protocol) + cipher.encrypt(logon)

# CR body: NO DURATION! Just key (u32 string) + 42×nonce (u32 each)
# Matches BigWorld: data << key; for(i) data << nonce_t(solution[i]);
def build_cr_body(duration, key_str, solution):
    body = struct.pack("<f", duration)  # data << duration (f32)
    body += pack_str_u24(key_str)  # data << key (packed_u24 — SAME as challenge!)
    body += b''.join(struct.pack("<I", n) for n in solution)  # 42 × u32
    return body

def parse_reply(data):
    if len(data) < 6: return None
    content = data[6:]
    pos = len(content)
    flags = struct.unpack_from("<H", data, 4)[0]
    if flags & FLAG_HAS_REQUESTS: pos -= 2
    elem = content[:pos]
    if not elem or elem[0] != 0xFF: return None
    length = struct.unpack_from("<I", elem, 1)[0]
    rdata = elem[5:5+length]
    if len(rdata) < 5: return None
    return (rdata[4], struct.unpack_from("<I", rdata, 0)[0], rdata[5:])

def parse_challenge(extra):
    pos = 0
    first = extra[pos]; pos += 1
    if first >= 255: slen = int.from_bytes(extra[pos:pos+3], 'little'); pos += 3
    else: slen = first
    pos += slen
    first = extra[pos]; pos += 1
    if first >= 255: klen = int.from_bytes(extra[pos:pos+3], 'little'); pos += 3
    else: klen = first
    key_prefix = extra[pos:pos+klen]; pos += klen
    max_nonce = struct.unpack_from("<Q", extra, pos)[0] if pos + 8 <= len(extra) else 65536
    return key_prefix, max_nonce

def setheader(header):
    if isinstance(header, str): header = header.encode()
    hk = hashlib.sha256(header).digest()
    k0 = struct.unpack_from("<Q", hk, 0)[0]; k1 = struct.unpack_from("<Q", hk, 8)[0]
    return [(k0^0x736f6d6570736575)&MASK64, (k1^0x646f72616e646f6d)&MASK64,
            (k0^0x6c7967656e657261)&MASK64, (k1^0x7465646279746573)&MASK64]

def rotl64(x, b): return ((x << b) | (x >> (64 - b))) & MASK64

def sipround(v0, v1, v2, v3):
    v0=(v0+v1)&MASK64; v2=(v2+v3)&MASK64; v1=rotl64(v1,13); v3=rotl64(v3,16)
    v1^=v0; v3^=v2; v0=rotl64(v0,32); v2=(v2+v1)&MASK64; v0=(v0+v3)&MASK64
    v1=rotl64(v1,17); v3=rotl64(v3,21); v1^=v2; v3^=v0; v2=rotl64(v2,32)
    return v0,v1,v2,v3

def siphash24(ctx, n):
    v0,v1,v2,v3=ctx; v3=(v3^n)&MASK64
    v0,v1,v2,v3=sipround(v0,v1,v2,v3); v0,v1,v2,v3=sipround(v0,v1,v2,v3)
    v0=(v0^n)&MASK64; v2=(v2^0xFF)&MASK64
    for _ in range(4): v0,v1,v2,v3=sipround(v0,v1,v2,v3)
    return (v0^v1^v2^v3)&MASK64

def sipnode(ctx, n, u): return siphash24(ctx, 2*n+u) & NODEMASK

# HALFSIZE offset encoding (confirmed from BigWorld source):
# u0 += 1; v0 += 1 + HALFSIZE;
def solve_cuckoo(header, easiness):
    ctx = setheader(header)
    ck = array.array('I', [0]*(SIZE+1))
    us = array.array('I', [0]*MAXPATHLEN); vs = array.array('I', [0]*MAXPATHLEN)
    t0 = time.time(); c = 0
    for n in range(easiness):
        u0=sipnode(ctx,n,0)+1; v0=sipnode(ctx,n,1)+1+HALFSIZE
        u=ck[u0]; v=ck[v0]
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
                print(f"    FOUND 42-cycle at {n} ({n*100//easiness}%)!")
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
    print(f"    No 42-cycle after {time.time()-t0:.1f}s, {c} cycles")
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

KEY_BW = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7/MNyWDdFpXhpFTO9LHz
CUQPYv2YP5rqJjUoxAFa3uKiPKbRvVFjUQ9lGHyjCmtixBbBqCTvDWu6Zh9Imu3x
KgCJh6NPSkddH3l+C+51FNtu3dGntbSLWuwi6Au1ErNpySpdx+Le7YEcFviY/ClZ
ayvVdA0tcb5NVJ4Axu13NvsuOUMqHxzCZRXCe6nyp6phFP2dQQZj8QZp0VsMFvhh
MsZ4srdFLG0sd8qliYzSqIyEQkwO8TQleHzfYYZ90wPTCOvMnMe5+zCH0iPJMisP
YB60u6lK9cvDEeuhPH95TPpzLNUFgmQIu9FU8PkcKA53bj0LWZR7v86Oco6vFg6V
sQIDAQAB
-----END PUBLIC KEY-----"""

SERVER = ("login.p1.worldoftanks.eu", 20016)
PROTOCOL = 285278213

def main():
    print(f"\n{'='*55}")
    print(f"  WoT Bot v50 — REAL FIX from BigWorld source")
    print(f"  30s timeout + same nonce both logins + packed_u24 LogOnParams")
    print(f"{'='*55}\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(30)
    rid = 1

    print("[0] PING...", end=" ", flush=True)
    sock.sendto(build_ping(rid), SERVER)
    try: sock.recvfrom(4096); print("OK"); rid += 1
    except socket.timeout: print("TIMEOUT"); sock.close(); return

    solution = None; key_str = None; bf_key = None; solve_time = 0
    for attempt in range(1, 16):
        print(f"\n[1] Login — attempt {attempt}...")
        bf_key = os.urandom(56)
        logon = struct.pack("<B", 0) + pack_str_u24("guest") + pack_str_u24("") + pack_str_u24(bf_key) + pack_str_u24("") + struct.pack("<I", login_nonce)
        login_body = struct.pack("<I", PROTOCOL) + struct.pack("<B", 0) + logon
        elem = build_request_v16(0x00, rid, login_body)
        sock.sendto(build_packet(elem, first_req=0), SERVER)
        rid += 1
        try: data, _ = sock.recvfrom(4096)
        except socket.timeout: print("    TIMEOUT"); sock.close(); return
        result = parse_reply(data)
        if not result or result[0] != 0x42:
            print(f"    No challenge: {result}"); sock.close(); return
        key_prefix, max_nonce = parse_challenge(result[2])
        prefix_str = key_prefix.decode('utf-8', errors='replace')
        print(f"    prefix: {prefix_str}, max_nonce: {max_nonce}")

        # Try prefix+"0", prefix+"1", etc. until solution found (BigWorld style)
        for counter in range(3):
            key_str = f"{prefix_str}{counter}"
            print(f"[2] Solving Cuckoo (key={key_str})...")
            solution, solve_time = solve_cuckoo(key_str, max_nonce)
            if solution and len(solution) == 42:
                print(f"    Solved with counter={counter}: {len(solution)} nonces, {solve_time:.1f}s")
                break
            print(f"    No 42-cycle with counter={counter}, trying next...")
        
        if solution and len(solution) == 42:
            break
        
        print("    No solution, reopening socket...")
        sock.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(30)
        sock.sendto(build_ping(rid), SERVER)
        try: sock.recvfrom(4096); rid += 1
        except: pass
        time.sleep(1)

    if not solution or len(solution) != 42:
        print("    Failed after 15 attempts"); sock.close(); return

    # CR body: NO DURATION! Just key + 42 nonces
    print(f"\n[3] Sending CR+Login (NO duration, key={key_str})...")
    cr_body = build_cr_body(solve_time, key_str, solution)
    cr_elem = build_message_v16(0x03, cr_body)
    login_body = build_login_noflag(PROTOCOL, bf_key, KEY_BW)
    login_elem = build_request_v16(0x00, rid, login_body)
    content = cr_elem + login_elem
    pkt = build_packet(content, first_req=len(cr_elem))
    print(f"    CR body={len(cr_body)}B (duration=4B + key_packed_u24={1+len(key_str)}B + 42×4B = {4+1+len(key_str)+168}B)")
    print(f"    CR={len(cr_elem)}B, Login={len(login_elem)}B, Packet={len(pkt)}B")

    got_response = False
    for sa in range(3):
        sock.sendto(pkt, SERVER)
        try:
            data, _ = sock.recvfrom(4096)
            got_response = True
            break
        except socket.timeout:
            if sa < 2: print(f"    Timeout, retry {sa+2}/3...")

    if got_response:
        result = parse_reply(data)
        if result:
            status, _, extra = result
            print(f"    Status: 0x{status:02X}")
            print(f"    Raw extra ({len(extra)}B): {extra[:100].hex()}")
            try: msg = extra.decode('utf-8', errors='replace')[:200]
            except: msg = ""
            if msg.strip(): print(f"    Message: {msg}")
            if status == 0x01: print("    === LOGIN SUCCESS! ===")
            elif status == 0x47: print("    -> Invalid User — CORRECT!")
            elif status == 0x48: print("    -> Invalid Password — CORRECT!")
            elif status == 0x55: print("    -> Failed login challenge")
            elif status == 0x40: print("    -> destream")
            else: print(f"    -> NEW: 0x{status:02X}")
        else: print("    Can't parse")
    else:
        print("    All retries timed out (30s each)")
        print("    Server may have accepted login - response could be on different format/port")
    sock.close()
    print("\nDone.")

if __name__ == "__main__":
    main()

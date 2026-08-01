#!/usr/bin/env python3
"""WoT Bot v44 — NO encrypted_flag byte (pure C++ BigWorld format)

v42 got "destream" WITH encrypted_flag byte (0x01).
C++ BigWorld has NO encrypted_flag — server RSA-decrypts ALL remaining bytes.
If we send [flag(1B) + RSA(256B)] = 257B, RSA-2048 fails (expects 256B) → destream!
FIX: send [protocol(4B)] [RSA(256B)] — no flag byte.

Test 3 LogOnParams formats inside RSA:
1. u32 strings, no context (pure C++ BigWorld)
2. packed_u24 strings, no context (hybrid)
3. packed_u24 strings, with context (wg-toolkit-rs)
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
    flags = 0
    footer = b""
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

# String encodings
def pack_u24(n):
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[:3]
    return struct.pack("<B", n)

def pack_str_u32(s):  # C++ BigWorld: u32 length + data
    b = s.encode() if isinstance(s, str) else s
    return struct.pack("<I", len(b)) + b

def pack_str_u24(s):  # wg-toolkit-rs: packed_u24 length + data
    b = s.encode() if isinstance(s, str) else s
    return pack_u24(len(b)) + b

def build_logon(bf_key, encoding="u32", context=None):
    """Build LogOnParams (the plaintext inside RSA)"""
    pack = pack_str_u32 if encoding == "u32" else pack_str_u24
    logon = struct.pack("<B", 0)          # flags (no digest)
    logon += pack("guest")                # username
    logon += pack("")                     # password
    logon += pack(bf_key)                 # encryptionKey (blowfish)
    if context is not None:               # context field (wg-toolkit-rs only)
        logon += pack(context)
    logon += struct.pack("<I", random.randint(1, 0xFFFFFFFF))  # nonce
    return logon

def build_login_body_noflag(protocol, bf_key, rsa_key_pem, encoding="u32", context=None):
    """C++ BigWorld format: NO encrypted_flag byte
    [protocol(4B)] [RSA_OAEP_SHA1(LogOnParams)(256B)]
    """
    logon = build_logon(bf_key, encoding, context)
    key = RSA.importKey(rsa_key_pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    encrypted = cipher.encrypt(logon)
    print(f"    LogOnParams: {len(logon)}B, RSA block: {len(encrypted)}B")
    return struct.pack("<I", protocol) + encrypted  # NO encrypted_flag!

def build_login_body_withflag(protocol, bf_key, rsa_key_pem, encoding="u24", context="eu_1.19.1_4"):
    """wg-toolkit-rs format: WITH encrypted_flag byte (for comparison)"""
    logon = build_logon(bf_key, encoding, context)
    key = RSA.importKey(rsa_key_pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    encrypted = cipher.encrypt(logon)
    return struct.pack("<I", protocol) + struct.pack("<B", 1) + encrypted

def build_cr_body(duration, key_prefix, solution):
    body = struct.pack("<f", duration)
    body += pack_str_u24(key_prefix)  # CR always uses packed_u24
    body += b''.join(struct.pack("<I", n) for n in solution)
    return body

def parse_reply(data):
    if len(data) < 6: return None
    content = data[6:]
    pos = len(content)
    flags = struct.unpack_from("<H", data, 4)[0]
    if flags & FLAG_HAS_REQUESTS:
        pos -= 2
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

def siphash24(ctx, n):
    v0,v1,v2,v3=ctx; v3=(v3^n)&MASK64
    v0,v1,v2,v3=sipround(v0,v1,v2,v3); v0,v1,v2,v3=sipround(v0,v1,v2,v3)
    v0=(v0^n)&MASK64; v2=(v2^0xFF)&MASK64
    for _ in range(4): v0,v1,v2,v3=sipround(v0,v1,v2,v3)
    return (v0^v1^v2^v3)&MASK64

def sipnode(ctx, n, u): return siphash24(ctx, 2*n+u) & NODEMASK

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
    print(f"  WoT Bot v44 — NO encrypted_flag (C++ format)")
    print(f"  Test: no-flag × u32/packed_u24 × no-ctx/ctx")
    print(f"{'='*55}\n")

    # PING
    print("[0] PING...", end=" ", flush=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    rid = 1
    sock.sendto(build_ping(rid), SERVER)
    try:
        sock.recvfrom(4096); print("OK"); rid += 1
    except socket.timeout:
        print("TIMEOUT"); sock.close(); return

    # Retry loop for Cuckoo (sometimes no 42-cycle found)
    solution = None
    duration = 0
    key_prefix = None
    for cuckoo_attempt in range(1, 6):
        print(f"\n[1] Login (unencrypted) — attempt {cuckoo_attempt}...")
        bf_key = os.urandom(56)
        logon = struct.pack("<B", 0) + pack_str_u24("guest") + pack_str_u24("") + pack_str_u24(bf_key) + pack_str_u24("") + struct.pack("<I", random.randint(1, 0xFFFFFFFF))
        login_body = struct.pack("<I", PROTOCOL) + struct.pack("<B", 0) + logon
        elem = build_request_v16(0x00, rid, login_body)
        sock.sendto(build_packet(elem, first_req=0), SERVER)
        rid += 1
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            print("    TIMEOUT"); sock.close(); return
        result = parse_reply(data)
        if not result or result[0] != 0x42:
            print(f"    No challenge: {result}"); sock.close(); return
        key_prefix, max_nonce = parse_challenge(result[2])
        header = key_prefix.decode('utf-8', errors='replace')
        print(f"    Challenge: {header}, max_nonce: {max_nonce}")

        print(f"[2] Solving Cuckoo — attempt {cuckoo_attempt}...")
        solution, duration = solve_cuckoo(header, max_nonce)
        if solution and len(solution) == 42:
            print(f"    Solved: {len(solution)} nonces, {duration:.1f}s")
            break
        print(f"    No 42-cycle, retrying with new challenge...")
        time.sleep(1)

    if not solution or len(solution) != 42:
        print("    Failed after 5 attempts"); sock.close(); return

    # CR element (shared)
    cr_body = build_cr_body(duration, key_prefix, solution)
    cr_elem = build_message_v16(0x03, cr_body)

    # Test combos — NO encrypted_flag byte!
    combos = [
        ("NO-FLAG u32 no-ctx",  "u32", None),
        ("NO-FLAG u24 no-ctx",  "u24", None),
        ("NO-FLAG u24 +ctx",    "u24", "eu_1.19.1_4"),
        ("NO-FLAG u32 +ctx",    "u32", "eu_1.19.1_4"),
    ]

    for name, encoding, context in combos:
        print(f"\n[3] {name}...")
        login_body = build_login_body_noflag(PROTOCOL, bf_key, KEY_BW, encoding, context)
        login_elem = build_request_v16(0x00, rid, login_body)
        content = cr_elem + login_elem
        pkt = build_packet(content, first_req=len(cr_elem))
        print(f"    Body: {len(login_body)}B, Packet: {len(pkt)}B")
        sock.sendto(pkt, SERVER)
        rid += 1
        try:
            data, _ = sock.recvfrom(4096)
            result = parse_reply(data)
            if result:
                status, _, extra = result
                print(f"    Status: 0x{status:02X}")
                try: msg = extra.decode('utf-8', errors='replace')[:200]
                except: msg = ""
                if msg.strip(): print(f"    Message: {msg}")
                if status == 0x01: print("    === LOGIN SUCCESS! ==="); sock.close(); return
                elif status == 0x47: print("    -> Invalid User — CORRECT!"); sock.close(); return
                elif status == 0x48: print("    -> Invalid Password — CORRECT!"); sock.close(); return
                elif status == 0x42: print("    -> New challenge (CR not linked)")
                elif status == 0x40:
                    if b"destream" in extra: print("    -> destream")
                    elif b"Unencrypted" in extra: print("    -> Unencrypted prohibited")
                    else: print(f"    -> Malformed: {msg}")
                else: print(f"    -> NEW: 0x{status:02X}")
            else: print("    Can't parse")
        except socket.timeout:
            print("    Timeout")
        time.sleep(2)

    sock.close()
    print("\nDone — tested all no-flag combos.")

if __name__ == "__main__":
    main()

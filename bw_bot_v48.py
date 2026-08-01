#!/usr/bin/env python3
"""WoT Bot v48 — Standard Cuckoo verification + SIZESHIFT=20

v47 with SIZESHIFT=21 found 0 cycles (55% density too low for 42-cycles).
Revert to SIZESHIFT=20 where cycles exist.

Key question: does our solution pass John Tromp's standard verification?
Standard: (1) all u[i] distinct, (2) all v[i] distinct, (3) edges form cycle via v[i]-HALFSIZE=u[j]
Our v46 verification (degree-2 check) passed, but that's the WRONG check!
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

def build_logon_u32(bf_key):
    logon = struct.pack("<B", 0)
    logon += pack_str_u32("guest")
    logon += pack_str_u32("")
    logon += pack_str_u32(bf_key)
    logon += struct.pack("<I", random.randint(1, 0xFFFFFFFF))
    return logon

def build_login_noflag(protocol, bf_key, rsa_key_pem):
    logon = build_logon_u32(bf_key)
    key = RSA.importKey(rsa_key_pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    return struct.pack("<I", protocol) + cipher.encrypt(logon)

def build_cr_body_u32(duration, key_prefix, solution):
    body = struct.pack("<f", duration)
    body += struct.pack("<I", len(key_prefix)) + key_prefix
    body += b''.join(struct.pack("<I", n) for n in solution)
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

def verify_standard(key_prefix_bytes, solution):
    """John Tromp's standard Cuckoo verification:
    1. All u[i] distinct
    2. All v[i] distinct
    3. Edges form cycle: v[i]-HALFSIZE = u[j] for next edge
    """
    ctx = setheader(key_prefix_bytes)
    us = [sipnode(ctx, n, 0) for n in solution]
    vs = [sipnode(ctx, n, 1) + HALFSIZE for n in solution]
    
    # Check 1: all u distinct
    u_set = set(us)
    if len(u_set) != PROOFSIZE:
        dups = len(us) - len(u_set)
        return False, f"{dups} duplicate U-nodes (only {len(u_set)} unique out of {PROOFSIZE})"
    
    # Check 2: all v distinct
    v_set = set(vs)
    if len(v_set) != PROOFSIZE:
        dups = len(vs) - len(v_set)
        return False, f"{dups} duplicate V-nodes (only {len(v_set)} unique out of {PROOFSIZE})"
    
    # Check 3: cycle connectivity
    # Build map: u -> v, and v-HALFSIZE -> u
    # The cycle: v[i]-HALFSIZE should equal u[j] for some j, following the chain
    u_to_v = {}
    v_minus_half_to_u = {}
    for i in range(PROOFSIZE):
        u_to_v[us[i]] = vs[i]
        v_minus_half_to_u[vs[i] - HALFSIZE] = us[i]
    
    # Follow cycle from first edge
    start_u = us[0]
    current_v = u_to_v[start_u]
    next_u = v_minus_half_to_u.get(current_v - HALFSIZE)
    if next_u is None:
        return False, f"V-node {current_v} doesn't map to any U-node"
    
    length = 1
    visited = {start_u}
    while next_u != start_u:
        if next_u in visited:
            return False, f"Cycle revisit at U-node {next_u} (length {length})"
        visited.add(next_u)
        current_v = u_to_v[next_u]
        next_u = v_minus_half_to_u.get(current_v - HALFSIZE)
        if next_u is None:
            return False, f"V-node {current_v} doesn't map to any U-node (length {length})"
        length += 1
        if length > PROOFSIZE:
            return False, f"Cycle too long (> {PROOFSIZE})"
    
    if length != PROOFSIZE:
        return False, f"Cycle length {length} != {PROOFSIZE}"
    
    return True, f"Valid Cuckoo cycle! {PROOFSIZE} edges, {len(u_set)} U-nodes, {len(v_set)} V-nodes (84 total)"

def verify_degree2(key_prefix_bytes, solution):
    """Old (wrong) verification — degree 2 check"""
    ctx = setheader(key_prefix_bytes)
    edges = []
    for nonce in solution:
        u = sipnode(ctx, nonce, 0)
        v = sipnode(ctx, nonce, 1) + HALFSIZE
        edges.append((u, v))
    adj = {}
    for u, v in edges:
        adj.setdefault(u, []).append(v)
        adj.setdefault(v, []).append(u)
    for node, neighbors in adj.items():
        if len(neighbors) != 2:
            return False, f"Node {node} has degree {len(neighbors)}"
    return True, f"Degree-2 cycle: {len(edges)} edges, {len(adj)} nodes"

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
    print(f"  WoT Bot v48 — Standard Cuckoo verification")
    print(f"  SIZESHIFT=20 (reverted from 21)")
    print(f"{'='*55}\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(15)
    rid = 1

    print("[0] PING...", end=" ", flush=True)
    sock.sendto(build_ping(rid), SERVER)
    try: sock.recvfrom(4096); print("OK"); rid += 1
    except socket.timeout: print("TIMEOUT"); sock.close(); return

    solution = None; duration = 0; key_prefix = None; bf_key = None
    for attempt in range(1, 6):
        print(f"\n[1] Login — attempt {attempt}...")
        bf_key = os.urandom(56)
        logon = struct.pack("<B", 0) + pack_str_u24("guest") + pack_str_u24("") + pack_str_u24(bf_key) + pack_str_u24("") + struct.pack("<I", random.randint(1, 0xFFFFFFFF))
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
        print(f"    key_prefix: {key_prefix} ({len(key_prefix)}B), max_nonce: {max_nonce}")

        print(f"[2] Solving Cuckoo — attempt {attempt}...")
        solution, duration = solve_cuckoo(key_prefix, max_nonce)
        if solution and len(solution) == 42:
            print(f"    Solved: {len(solution)} nonces, {duration:.1f}s")
            
            # Standard verification (John Tromp)
            print(f"[2b] Standard verification (distinctness + cycle)...")
            valid, msg = verify_standard(key_prefix, solution)
            print(f"    Standard: {valid} — {msg}")
            
            # Old verification (degree 2)
            valid2, msg2 = verify_degree2(key_prefix, solution)
            print(f"    Degree-2: {valid2} — {msg2}")
            
            if valid:
                break
            else:
                print("    STANDARD VERIFICATION FAILED — solution is NOT a valid Cuckoo cycle!")
                print("    The solver finds bipartite cycles (degree 2) not Cuckoo cycles (distinct nodes)")
                solution = None
        else:
            print("    No 42-cycle, retrying...")
        time.sleep(1)

    if not solution:
        print("    Failed after 5 attempts"); sock.close(); return

    # Send CR+Login
    print(f"\n[3] Sending CR+Login...")
    cr_body = build_cr_body_u32(duration, key_prefix, solution)
    cr_elem = build_message_v16(0x03, cr_body)
    login_body = build_login_noflag(PROTOCOL, bf_key, KEY_BW)
    login_elem = build_request_v16(0x00, rid, login_body)
    content = cr_elem + login_elem
    pkt = build_packet(content, first_req=len(cr_elem))
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
            try: msg = extra.decode('utf-8', errors='replace')[:200]
            except: msg = ""
            if msg.strip(): print(f"    Message: {msg}")
            if status == 0x01: print("    === LOGIN SUCCESS! ===")
            elif status == 0x47: print("    -> Invalid User — CORRECT!")
            elif status == 0x55: print("    -> Failed login challenge")
            elif status == 0x40: print("    -> destream")
            else: print(f"    -> NEW: 0x{status:02X}")
        else: print("    Can't parse")
    else:
        print("    All retries timed out")
    sock.close()
    print("\nDone.")

if __name__ == "__main__":
    main()

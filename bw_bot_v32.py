#!/usr/bin/env python3
"""WoT Bot v32 — Fixed SIPROUND order (was scrambled in v31)

The SIPROUND macro in C does operations in a specific interleaved order.
v31 had them in wrong order → wrong SipHash → wrong edges → no cycles found.

Correct SIPROUND order (from C source):
  v0 += v1; v2 += v3; v1 = ROTL(v1,13); v3 = ROTL(v3,16);
  v1 ^= v0; v3 ^= v2; v0 = ROTL(v0,32); v2 += v1; v0 += v3;
  v1 = ROTL(v1,17); v3 = ROTL(v3,21); v1 ^= v2; v3 ^= v0;
  v2 = ROTL(v2,32);
"""
import socket, struct, os, hashlib, time, array

exec(open('/root/wot-grinder-bot-v8/bw_bot_v3.py' if os.path.exists('/root/wot-grinder-bot-v8/bw_bot_v3.py') else '/tmp/bw_bot_v3.py').read().split('def run(')[0])

def pack_u24(n):
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[:3]
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_u24(len(b)) + b

def build_element_v16(elem_id, rid, body):
    return struct.pack("<BH", elem_id, len(body)) + struct.pack("<IH", rid, 0) + body

def build_login_body(protocol):
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
    return struct.pack("<I", protocol) + logon, bf

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
    if first >= 255:
        slen = int.from_bytes(extra[pos:pos+3], 'little')
        pos += 3
    else:
        slen = first
    challenge_type = extra[pos:pos+slen].decode('utf-8', errors='replace')
    pos += slen
    first = extra[pos]; pos += 1
    if first >= 255:
        klen = int.from_bytes(extra[pos:pos+3], 'little')
        pos += 3
    else:
        klen = first
    key_prefix = extra[pos:pos+klen]
    pos += klen
    max_nonce = struct.unpack_from("<I", extra, pos)[0] if pos + 4 <= len(extra) else 65536
    pos += 4
    return challenge_type, key_prefix, max_nonce

# ============ EXACT BigWorld SipHash-2-4 ============
SIZESHIFT = 20
PROOFSIZE = 42
SIZE = 1 << SIZESHIFT
HALFSIZE = SIZE // 2
NODEMASK = HALFSIZE - 1
MAXPATHLEN = 8192
MASK64 = 0xFFFFFFFFFFFFFFFF

def setheader(header):
    hdrkey = hashlib.sha256(header.encode() if isinstance(header, str) else header).digest()
    k0 = struct.unpack_from("<Q", hdrkey, 0)[0]
    k1 = struct.unpack_from("<Q", hdrkey, 8)[0]
    return [
        (k0 ^ 0x736f6d6570736575) & MASK64,
        (k1 ^ 0x646f72616e646f6d) & MASK64,
        (k0 ^ 0x6c7967656e657261) & MASK64,
        (k1 ^ 0x7465646279746573) & MASK64,
    ]

def rotl64(x, b):
    return ((x << b) | (x >> (64 - b))) & MASK64

def siphash24(ctx, nonce):
    """SipHash-2-4 for single 8-byte nonce — EXACT C code order"""
    v0, v1, v2, v3 = ctx
    v3 = (v3 ^ nonce) & MASK64
    
    # SIPROUND #1 (EXACT order from C macro)
    v0 = (v0 + v1) & MASK64
    v2 = (v2 + v3) & MASK64
    v1 = rotl64(v1, 13)
    v3 = rotl64(v3, 16)
    v1 ^= v0
    v3 ^= v2
    v0 = rotl64(v0, 32)
    v2 = (v2 + v1) & MASK64
    v0 = (v0 + v3) & MASK64
    v1 = rotl64(v1, 17)
    v3 = rotl64(v3, 21)
    v1 ^= v2
    v3 ^= v0
    v2 = rotl64(v2, 32)
    
    # SIPROUND #2
    v0 = (v0 + v1) & MASK64
    v2 = (v2 + v3) & MASK64
    v1 = rotl64(v1, 13)
    v3 = rotl64(v3, 16)
    v1 ^= v0
    v3 ^= v2
    v0 = rotl64(v0, 32)
    v2 = (v2 + v1) & MASK64
    v0 = (v0 + v3) & MASK64
    v1 = rotl64(v1, 17)
    v3 = rotl64(v3, 21)
    v1 ^= v2
    v3 ^= v0
    v2 = rotl64(v2, 32)
    
    v0 = (v0 ^ nonce) & MASK64
    v2 = (v2 ^ 0xFF) & MASK64
    
    # SIPROUND #3
    v0 = (v0 + v1) & MASK64
    v2 = (v2 + v3) & MASK64
    v1 = rotl64(v1, 13)
    v3 = rotl64(v3, 16)
    v1 ^= v0
    v3 ^= v2
    v0 = rotl64(v0, 32)
    v2 = (v2 + v1) & MASK64
    v0 = (v0 + v3) & MASK64
    v1 = rotl64(v1, 17)
    v3 = rotl64(v3, 21)
    v1 ^= v2
    v3 ^= v0
    v2 = rotl64(v2, 32)
    
    # SIPROUND #4
    v0 = (v0 + v1) & MASK64
    v2 = (v2 + v3) & MASK64
    v1 = rotl64(v1, 13)
    v3 = rotl64(v3, 16)
    v1 ^= v0
    v3 ^= v2
    v0 = rotl64(v0, 32)
    v2 = (v2 + v1) & MASK64
    v0 = (v0 + v3) & MASK64
    v1 = rotl64(v1, 17)
    v3 = rotl64(v3, 21)
    v1 ^= v2
    v3 ^= v0
    v2 = rotl64(v2, 32)
    
    # SIPROUND #5
    v0 = (v0 + v1) & MASK64
    v2 = (v2 + v3) & MASK64
    v1 = rotl64(v1, 13)
    v3 = rotl64(v3, 16)
    v1 ^= v0
    v3 ^= v2
    v0 = rotl64(v0, 32)
    v2 = (v2 + v1) & MASK64
    v0 = (v0 + v3) & MASK64
    v1 = rotl64(v1, 17)
    v3 = rotl64(v3, 21)
    v1 ^= v2
    v3 ^= v0
    v2 = rotl64(v2, 32)
    
    # SIPROUND #6
    v0 = (v0 + v1) & MASK64
    v2 = (v2 + v3) & MASK64
    v1 = rotl64(v1, 13)
    v3 = rotl64(v3, 16)
    v1 ^= v0
    v3 ^= v2
    v0 = rotl64(v0, 32)
    v2 = (v2 + v1) & MASK64
    v0 = (v0 + v3) & MASK64
    v1 = rotl64(v1, 17)
    v3 = rotl64(v3, 21)
    v1 ^= v2
    v3 ^= v0
    v2 = rotl64(v2, 32)
    
    return (v0 ^ v1 ^ v2 ^ v3) & MASK64

def sipnode(ctx, nonce, uorv):
    return siphash24(ctx, 2 * nonce + uorv) & NODEMASK

def sipedge(ctx, nonce):
    return sipnode(ctx, nonce, 0), sipnode(ctx, nonce, 1)

# ============ Cuckoo "mean" solver ============
def solve_cuckoo(header, easiness):
    print(f"    Header: {header}")
    print(f"    Easiness: {easiness}")
    
    ctx = setheader(header)
    k0 = ctx[0] ^ 0x736f6d6570736575
    k1 = ctx[1] ^ 0x646f72616e646f6d
    print(f"    SipHash key: {struct.pack('<QQ', k0, k1).hex()}")
    
    # Quick test: print first few edges to verify
    for n in range(3):
        u, v = sipedge(ctx, n)
        print(f"    edge[{n}]: u={u}, v={v}")
    
    cuckoo = array.array('I', [0] * (SIZE + 1))
    us = array.array('I', [0] * MAXPATHLEN)
    vs = array.array('I', [0] * MAXPATHLEN)
    
    t0 = time.time()
    cycles_found = 0
    
    for nonce in range(easiness):
        u0, v0 = sipedge(ctx, nonce)
        u0 += 1
        v0 += 1 + HALFSIZE
        
        u = cuckoo[u0]
        v = cuckoo[v0]
        
        if u == v0 or v == u0:
            continue
        
        us[0] = u0
        vs[0] = v0
        
        # Follow path from u
        nu = 0
        node = u
        while node:
            nu += 1
            if nu >= MAXPATHLEN:
                return None
            us[nu] = node
            node = cuckoo[node]
        
        # Follow path from v
        nv = 0
        node = v
        while node:
            nv += 1
            if nv >= MAXPATHLEN:
                return None
            vs[nv] = node
            node = cuckoo[node]
        
        if us[nu] == vs[nv]:
            # Cycle found!
            min_len = min(nu, nv)
            nu -= min_len
            nv -= min_len
            while us[nu] != vs[nv]:
                nu += 1
                nv += 1
            
            cycle_len = nu + nv + 1
            cycles_found += 1
            
            if cycle_len == PROOFSIZE:
                print(f"    FOUND 42-cycle at nonce {nonce} ({nonce*100//easiness}%)!")
                sol = find_solution_nonces(ctx, us, nu, vs, nv, easiness)
                print(f"    Solve time: {time.time()-t0:.1f}s, {cycles_found} cycles checked")
                return sol
            continue
        
        # Connect paths
        if nu < nv:
            while nu:
                nu -= 1
                cuckoo[us[nu + 1]] = us[nu]
            cuckoo[u0] = v0
        else:
            while nv:
                nv -= 1
                cuckoo[vs[nv + 1]] = vs[nv]
            cuckoo[v0] = u0
        
        if nonce % 50000 == 0 and nonce > 0:
            elapsed = time.time() - t0
            print(f"    ... {nonce}/{easiness} ({nonce*100//easiness}%), {elapsed:.1f}s, {cycles_found} cycles")
    
    print(f"    No 42-cycle found after {time.time()-t0:.1f}s, {cycles_found} cycles found")
    return None

def find_solution_nonces(ctx, us, nu, vs, nv, easiness):
    cycle = set()
    cycle.add((us[0], vs[0]))
    
    i = nu
    while i > 0:
        i -= 1
        cycle.add((us[(i + 1) & ~1], us[i | 1]))
    
    i = nv
    while i > 0:
        i -= 1
        cycle.add((vs[i | 1], vs[(i + 1) & ~1]))
    
    print(f"    Cycle has {len(cycle)} edges")
    
    sol = []
    for nonce in range(easiness):
        u = sipnode(ctx, nonce, 0) + 1
        v = sipnode(ctx, nonce, 1) + 1 + HALFSIZE
        if (u, v) in cycle:
            sol.append(nonce)
            cycle.discard((u, v))
            if not cycle:
                break
    
    print(f"    Found {len(sol)} nonces")
    return sol

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=10):
    PROTOCOL = 285278213
    
    print(f"\n{'='*55}")
    print(f"  WoT Bot v32 — Fixed SIPROUND order")
    print(f"  Protocol: 17.1.0 (5) = {PROTOCOL}")
    print(f"  {server}:{port}")
    print(f"{'='*55}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1
    
    print(f"\n[1] PING...")
    sock.sendto(ping_packet(rid=rid), (server, port))
    try:
        sock.recvfrom(4096); print(f"    PING OK"); rid += 1
    except socket.timeout:
        sock.close(); sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        server, port = "login.p2.worldoftanks.eu", 20018
        sock.sendto(ping_packet(rid=rid), (server, port))
        try: sock.recvfrom(4096); print(f"    p2 PING OK"); rid += 1
        except: print(f"    PING failed"); sock.close(); return
    
    print(f"\n[2] LoginRequest...")
    login_body, bf_key = build_login_body(PROTOCOL)
    elem = build_element_v16(0x00, rid, login_body)
    pkt = _pkt(elem, first_req=0)
    sock.sendto(pkt, (server, port))
    rid += 1
    
    try:
        data, _ = sock.recvfrom(4096)
        result = parse_reply_full(data)
        if not result:
            print(f"    Parse failed"); sock.close(); return
        
        status, reply_rid, extra = result
        print(f"    Status: 0x{status:02X}")
        
        if status == 0x42:
            print(f"\n[3] Cuckoo Challenge!")
            challenge_type, key_prefix, max_nonce = parse_cuckoo_challenge(extra)
            header = key_prefix.decode('utf-8', errors='replace')
            print(f"    Type: {challenge_type}")
            print(f"    Header: {header}")
            print(f"    Max nonce: {max_nonce}")
            
            print(f"\n[4] Solving Cuckoo Cycle...")
            solution = solve_cuckoo(header, max_nonce)
            
            if solution is None:
                print(f"    FAILED!")
                sock.close(); return
            
            if len(solution) != 42:
                print(f"    Wrong count: {len(solution)}")
                sock.close(); return
            
            print(f"    Solution: {len(solution)} nonces")
            print(f"    First 5: {solution[:5]}")
            print(f"    Last 5: {solution[-5:]}")
            
            print(f"\n[5] Sending ChallengeResponse...")
            duration = 5.0
            solution_blob = b''.join(struct.pack("<I", n) for n in solution)
            challenge_body = struct.pack("<f", duration) + pack_str(solution_blob)
            
            elem = build_element_v16(0x03, rid, challenge_body)
            pkt = _pkt(elem, first_req=0)
            sock.sendto(pkt, (server, port))
            rid += 1
            
            try:
                data, _ = sock.recvfrom(4096)
                result = parse_reply_full(data)
                if result:
                    status, reply_rid, extra = result
                    print(f"    Response: 0x{status:02X}")
                    if extra:
                        print(f"    Extra ({len(extra)} bytes): {extra[:64].hex()}")
                    
                    if status == 0x01: print(f"    LOGIN SUCCESS!")
                    elif status == 0x42: print(f"    Another challenge")
                    elif status == 0x40: print(f"    Malformed")
                    elif status == 0x53: print(f"    Rate limited")
                    else: print(f"    Status: 0x{status:02X}")
            except socket.timeout:
                print(f"    Timeout")
            
            print(f"\n[6] Sending NEW LoginRequest...")
            new_body, _ = build_login_body(PROTOCOL)
            elem = build_element_v16(0x00, rid, new_body)
            pkt = _pkt(elem, first_req=0)
            sock.sendto(pkt, (server, port))
            rid += 1
            
            try:
                data, _ = sock.recvfrom(4096)
                result = parse_reply_full(data)
                if result:
                    status, reply_rid, extra = result
                    print(f"    Status: 0x{status:02X}")
                    if extra:
                        print(f"    Extra ({len(extra)} bytes): {extra[:64].hex()}")
                    
                    if status == 0x01: print(f"\n    *** LOGIN SUCCESS! ***")
                    elif status == 0x42: print(f"    Challenge again")
                    elif status == 0x47: print(f"    Invalid User")
                    elif status == 0x48: print(f"    Invalid Password")
                    else: print(f"    Status: 0x{status:02X}")
                else:
                    print(f"    No reply")
            except socket.timeout:
                print(f"    Timeout")
        elif status == 0x41: print(f"    BadProtocolVersion")
        elif status == 0x40: print(f"    MalformedRequest")
        else: print(f"    Status: 0x{status:02X}")
    except socket.timeout:
        print(f"    Timeout")
    
    sock.close()
    print(f"\nDone.")

if __name__ == "__main__":
    run()

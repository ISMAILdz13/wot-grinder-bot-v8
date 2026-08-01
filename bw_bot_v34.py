#!/usr/bin/env python3
"""WoT Bot v34 — Retry loop + cycle length debugging

v32 found a 42-cycle (15.4s), v33 didn't (different key, 575 cycles but none=42).
Fix: retry with new challenges up to 5 times.
Also: log cycle lengths to understand the distribution.
"""
import socket, struct, os, hashlib, time, array, collections

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

# ============ SipHash-2-4 ============
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

def sipround(v0, v1, v2, v3):
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
    return v0, v1, v2, v3

def siphash24(ctx, nonce):
    v0, v1, v2, v3 = ctx
    v3 = (v3 ^ nonce) & MASK64
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0 = (v0 ^ nonce) & MASK64
    v2 = (v2 ^ 0xFF) & MASK64
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    return (v0 ^ v1 ^ v2 ^ v3) & MASK64

def sipnode(ctx, nonce, uorv):
    return siphash24(ctx, 2 * nonce + uorv) & NODEMASK

def sipedge(ctx, nonce):
    return sipnode(ctx, nonce, 0), sipnode(ctx, nonce, 1)

def solve_cuckoo(header, easiness, attempt=1):
    ctx = setheader(header)
    
    cuckoo = array.array('I', [0] * (SIZE + 1))
    us = array.array('I', [0] * MAXPATHLEN)
    vs = array.array('I', [0] * MAXPATHLEN)
    
    t0 = time.time()
    cycles_found = 0
    cycle_lengths = collections.Counter()
    
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
        
        nu = 0
        node = u
        while node:
            nu += 1
            if nu >= MAXPATHLEN: return None, 0
            us[nu] = node
            node = cuckoo[node]
        
        nv = 0
        node = v
        while node:
            nv += 1
            if nv >= MAXPATHLEN: return None, 0
            vs[nv] = node
            node = cuckoo[node]
        
        if us[nu] == vs[nv]:
            min_len = min(nu, nv)
            nu -= min_len
            nv -= min_len
            while us[nu] != vs[nv]:
                nu += 1
                nv += 1
            
            cycle_len = nu + nv + 1
            cycles_found += 1
            cycle_lengths[cycle_len] += 1
            
            if cycle_len == PROOFSIZE:
                print(f"    [Attempt {attempt}] FOUND 42-cycle at nonce {nonce} ({nonce*100//easiness}%)!")
                sol = find_solution_nonces(ctx, us, nu, vs, nv, easiness)
                elapsed = time.time() - t0
                print(f"    Solve time: {elapsed:.1f}s, {cycles_found} cycles checked")
                return sol, elapsed
            continue
        
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
        
        if nonce % 100000 == 0 and nonce > 0:
            elapsed = time.time() - t0
            print(f"    ... {nonce}/{easiness} ({nonce*100//easiness}%), {elapsed:.1f}s, {cycles_found} cycles")
    
    elapsed = time.time() - t0
    print(f"    [Attempt {attempt}] No 42-cycle after {elapsed:.1f}s, {cycles_found} cycles")
    # Print cycle length distribution (top 10)
    top = cycle_lengths.most_common(10)
    print(f"    Cycle lengths: {', '.join(f'{l}:{c}' for l, c in sorted(top))}")
    return None, elapsed

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

def get_challenge(sock, server, port, protocol, rid):
    """Send LoginRequest and get Cuckoo challenge"""
    login_body, bf_key = build_login_body(protocol)
    elem = build_request_v16(0x00, rid, login_body)
    pkt = _pkt(elem, first_req=0)
    sock.sendto(pkt, (server, port))
    
    data, _ = sock.recvfrom(4096)
    result = parse_reply_full(data)
    if not result:
        return None, None, None, rid + 1
    
    status, reply_rid, extra = result
    if status != 0x42:
        return None, None, None, rid + 1
    
    challenge_type, key_prefix, max_nonce = parse_cuckoo_challenge(extra)
    header = key_prefix.decode('utf-8', errors='replace')
    return header, max_nonce, bf_key, rid + 1

def send_challenge_response_and_login(sock, server, port, solution, solve_duration, protocol, bf_key, rid):
    """Send combined packet: ChallengeResponse (message) + LoginRequest (request)"""
    # ChallengeResponse body: [duration(f32)] [addBlob: u32_len + solution]
    solution_data = b''.join(struct.pack("<I", n) for n in solution)
    challenge_body = struct.pack("<f", solve_duration) + struct.pack("<I", len(solution_data)) + solution_data
    
    # New LoginRequest body (same BF key!)
    new_login_body, _ = build_login_body(protocol)
    
    # Build combined packet
    cr_elem = build_message_v16(0x03, challenge_body)
    login_elem = build_request_v16(0x00, rid, new_login_body)
    content = cr_elem + login_elem
    first_req = len(cr_elem)
    
    pkt = _pkt(content, first_req=first_req)
    
    print(f"    Packet: CR({len(cr_elem)}B, msg) + Login({len(login_elem)}B, req) = {len(pkt)}B total")
    
    sock.sendto(pkt, (server, port))
    return rid + 1

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=10, max_attempts=5):
    PROTOCOL = 285278213
    
    print(f"\n{'='*55}")
    print(f"  WoT Bot v34 — Retry Loop + Debug")
    print(f"  Protocol: 17.1.0 (5) = {PROTOCOL}")
    print(f"  Max attempts: {max_attempts}")
    print(f"  {server}:{port}")
    print(f"{'='*55}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1
    
    # PING
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
    
    # Retry loop
    for attempt in range(1, max_attempts + 1):
        print(f"\n[{attempt+1}] Attempt {attempt}/{max_attempts}: Get challenge...")
        
        try:
            header, max_nonce, bf_key, rid = get_challenge(sock, server, port, PROTOCOL, rid)
        except socket.timeout:
            print(f"    Timeout getting challenge, retrying...")
            continue
        
        if header is None:
            print(f"    Failed to get challenge")
            continue
        
        print(f"    Header: {header}")
        print(f"    Max nonce: {max_nonce}")
        
        # Solve
        print(f"\n    Solving Cuckoo Cycle...")
        solution, solve_duration = solve_cuckoo(header, max_nonce, attempt)
        
        if solution is None:
            print(f"    No 42-cycle found, retrying with new challenge...")
            continue
        
        if len(solution) != 42:
            print(f"    Wrong nonce count: {len(solution)}")
            continue
        
        print(f"    Solution: {len(solution)} nonces")
        print(f"    First 5: {solution[:5]}")
        print(f"    Last 5: {solution[-5:]}")
        
        # Send ChallengeResponse + Login in same packet
        print(f"\n    Sending combined ChallengeResponse + Login...")
        rid = send_challenge_response_and_login(sock, server, port, solution, solve_duration, PROTOCOL, bf_key, rid)
        
        try:
            data, _ = sock.recvfrom(4096)
            result = parse_reply_full(data)
            if result:
                status, reply_rid, extra = result
                print(f"\n    Response: 0x{status:02X}")
                if extra:
                    print(f"    Extra ({len(extra)} bytes): {extra[:80].hex()}")
                
                if status == 0x01:
                    print(f"\n    *** LOGIN SUCCESS! ***")
                    print(f"    BF key: {bf_key.hex()}")
                    # Parse login success data (Blowfish-encrypted)
                    # [addr(4B IP + 2B port)] [login_key(4B)] [msg(str)]
                elif status == 0x42:
                    print(f"    New challenge — solution may have been accepted, need to solve again")
                    # Maybe the solution was accepted and this is a new challenge for the next step?
                    # Or the solution was rejected
                    continue
                elif status == 0x40:
                    print(f"    MalformedRequest — format still wrong")
                    if extra:
                        for i in range(0, min(len(extra), 64), 16):
                            print(f"      {i:4d}: {extra[i:i+16].hex()}")
                elif status == 0x47:
                    print(f"    Invalid User — need real WG credentials")
                elif status == 0x48:
                    print(f"    Invalid Password")
                elif status == 0x53:
                    print(f"    Rate Limited")
                else:
                    print(f"    Status: 0x{status:02X}")
            else:
                print(f"    No reply parsed")
            break  # Got a response, stop retrying
        except socket.timeout:
            print(f"    Timeout — trying separate packets...")
            
            # Fallback: send CR alone, then login
            cr_elem = build_message_v16(0x03, struct.pack("<f", solve_duration) + struct.pack("<I", len(solution_data)) + solution_data)
            pkt2 = _pkt(cr_elem, first_req=0)
            sock.sendto(pkt2, (server, port))
            time.sleep(0.5)
            
            login_body, _ = build_login_body(PROTOCOL)
            login_elem = build_request_v16(0x00, rid, login_body)
            pkt3 = _pkt(login_elem, first_req=0)
            sock.sendto(pkt3, (server, port))
            rid += 1
            
            try:
                data, _ = sock.recvfrom(4096)
                result = parse_reply_full(data)
                if result:
                    status, _, extra = result
                    print(f"    Fallback response: 0x{status:02X}")
                    if extra:
                        print(f"    Extra: {extra[:80].hex()}")
            except socket.timeout:
                print(f"    Fallback also timed out")
            break
    
    sock.close()
    print(f"\nDone.")

if __name__ == "__main__":
    run()

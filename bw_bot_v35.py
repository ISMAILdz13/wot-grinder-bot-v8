#!/usr/bin/env python3
"""WoT Bot v35 — Correct ChallengeResponse format from wg-toolkit-rs

ChallengeResponse body (from Rust source):
  [duration(f32)] [key: write_blob_variable] [42×nonce: write_u32 each]

- key = key_prefix bytes (packed_u24 length + data)
- 42 nonces written as raw u32 (NO blob wrapper, NO length prefix)

ChallengeResponse is a MESSAGE (element 0x03, no rid/next)
LoginRequest is a REQUEST (element 0x00, with rid/next)
Both in SAME UDP packet.
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
    """MESSAGE: [id(1B)] [len(2B)] [body] — no rid, no next"""
    return struct.pack("<BH", elem_id, len(body)) + body

def build_request_v16(elem_id, rid, body):
    """REQUEST: [id(1B)] [len(2B)] [rid(4B)] [next(2B)] [body]"""
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
        slen = int.from_bytes(extra[pos:pos+3], 'little'); pos += 3
    else:
        slen = first
    challenge_type = extra[pos:pos+slen].decode('utf-8', errors='replace'); pos += slen
    first = extra[pos]; pos += 1
    if first >= 255:
        klen = int.from_bytes(extra[pos:pos+3], 'little'); pos += 3
    else:
        klen = first
    key_prefix = extra[pos:pos+klen]; pos += klen
    # max_nonce is u64 (8 bytes) in wg-toolkit-rs
    max_nonce = struct.unpack_from("<Q", extra, pos)[0] if pos + 8 <= len(extra) else 65536; pos += 8
    return challenge_type, key_prefix, max_nonce

# ============ SipHash-2-4 ============
SIZESHIFT = 20; PROOFSIZE = 42; SIZE = 1 << SIZESHIFT
HALFSIZE = SIZE // 2; NODEMASK = HALFSIZE - 1; MAXPATHLEN = 8192
MASK64 = 0xFFFFFFFFFFFFFFFF

def setheader(header):
    hdrkey = hashlib.sha256(header.encode() if isinstance(header, str) else header).digest()
    k0 = struct.unpack_from("<Q", hdrkey, 0)[0]
    k1 = struct.unpack_from("<Q", hdrkey, 8)[0]
    return [(k0 ^ 0x736f6d6570736575) & MASK64, (k1 ^ 0x646f72616e646f6d) & MASK64,
            (k0 ^ 0x6c7967656e657261) & MASK64, (k1 ^ 0x7465646279746573) & MASK64]

def rotl64(x, b):
    return ((x << b) | (x >> (64 - b))) & MASK64

def sipround(v0, v1, v2, v3):
    v0 = (v0 + v1) & MASK64; v2 = (v2 + v3) & MASK64
    v1 = rotl64(v1, 13); v3 = rotl64(v3, 16)
    v1 ^= v0; v3 ^= v2; v0 = rotl64(v0, 32)
    v2 = (v2 + v1) & MASK64; v0 = (v0 + v3) & MASK64
    v1 = rotl64(v1, 17); v3 = rotl64(v3, 21)
    v1 ^= v2; v3 ^= v0; v2 = rotl64(v2, 32)
    return v0, v1, v2, v3

def siphash24(ctx, nonce):
    v0, v1, v2, v3 = ctx
    v3 = (v3 ^ nonce) & MASK64
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0 = (v0 ^ nonce) & MASK64; v2 = (v2 ^ 0xFF) & MASK64
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

    for nonce in range(easiness):
        u0, v0 = sipedge(ctx, nonce)
        u0 += 1; v0 += 1 + HALFSIZE
        u = cuckoo[u0]; v = cuckoo[v0]
        if u == v0 or v == u0: continue
        us[0] = u0; vs[0] = v0
        nu = 0; node = u
        while node:
            nu += 1
            if nu >= MAXPATHLEN: return None, 0
            us[nu] = node; node = cuckoo[node]
        nv = 0; node = v
        while node:
            nv += 1
            if nv >= MAXPATHLEN: return None, 0
            vs[nv] = node; node = cuckoo[node]
        if us[nu] == vs[nv]:
            min_len = min(nu, nv); nu -= min_len; nv -= min_len
            while us[nu] != vs[nv]: nu += 1; nv += 1
            cycle_len = nu + nv + 1; cycles_found += 1
            if cycle_len == PROOFSIZE:
                print(f"    [{attempt}] FOUND 42-cycle at nonce {nonce} ({nonce*100//easiness}%)!")
                sol = find_solution_nonces(ctx, us, nu, vs, nv, easiness)
                elapsed = time.time() - t0
                print(f"    Solve time: {elapsed:.1f}s, {cycles_found} cycles")
                return sol, elapsed
            continue
        if nu < nv:
            while nu: nu -= 1; cuckoo[us[nu + 1]] = us[nu]
            cuckoo[u0] = v0
        else:
            while nv: nv -= 1; cuckoo[vs[nv + 1]] = vs[nv]
            cuckoo[v0] = u0
        if nonce % 100000 == 0 and nonce > 0:
            print(f"    ... {nonce}/{easiness} ({nonce*100//easiness}%), {time.time()-t0:.1f}s, {cycles_found} cycles")
    print(f"    [{attempt}] No 42-cycle after {time.time()-t0:.1f}s, {cycles_found} cycles")
    return None, 0

def find_solution_nonces(ctx, us, nu, vs, nv, easiness):
    cycle = {(us[0], vs[0])}
    i = nu
    while i > 0: i -= 1; cycle.add((us[(i + 1) & ~1], us[i | 1]))
    i = nv
    while i > 0: i -= 1; cycle.add((vs[i | 1], vs[(i + 1) & ~1]))
    print(f"    Cycle has {len(cycle)} edges")
    sol = []
    for nonce in range(easiness):
        u = sipnode(ctx, nonce, 0) + 1; v = sipnode(ctx, nonce, 1) + 1 + HALFSIZE
        if (u, v) in cycle:
            sol.append(nonce); cycle.discard((u, v))
            if not cycle: break
    print(f"    Found {len(sol)} nonces")
    return sol

def build_combined_packet(key_prefix_bytes, solution, solve_duration, protocol, rid):
    """Build combined packet: ChallengeResponse (message) + LoginRequest (request)
    
    From wg-toolkit-rs CuckooCycleResponse::write:
      [duration(f32)] [key: write_blob_variable] [42×nonce: write_u32]
    
    write_blob_variable = packed_u24 length + data
    write_u32 = 4 bytes LE
    """
    # ChallengeResponse body: [duration] [key_packed_blob] [42×u32_nonces]
    challenge_body = struct.pack("<f", solve_duration)
    challenge_body += pack_str(key_prefix_bytes)  # key as packed blob
    challenge_body += b''.join(struct.pack("<I", n) for n in solution)  # 42 nonces as raw u32
    
    # Build MESSAGE element (no rid, no next)
    cr_elem = build_message_v16(0x03, challenge_body)
    
    # Build LoginRequest (same BF key!)
    login_body, bf_key = build_login_body(protocol)
    login_elem = build_request_v16(0x00, rid, login_body)
    
    # Combined content
    content = cr_elem + login_elem
    first_req = len(cr_elem)
    
    # Build packet with HAS_REQUESTS footer
    pkt = _pkt(content, first_req=first_req)
    
    return pkt, bf_key, len(cr_elem), len(login_elem)

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=10, max_attempts=5):
    PROTOCOL = 285278213
    
    print(f"\n{'='*55}")
    print(f"  WoT Bot v35 — Correct ChallengeResponse format")
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
    
    for attempt in range(1, max_attempts + 1):
        print(f"\n[{attempt+1}] Attempt {attempt}/{max_attempts}: Get challenge...")
        
        # Get challenge
        login_body, bf_key = build_login_body(PROTOCOL)
        elem = build_request_v16(0x00, rid, login_body)
        pkt = _pkt(elem, first_req=0)
        sock.sendto(pkt, (server, port))
        rid += 1
        
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            print(f"    Timeout, retrying..."); continue
        
        result = parse_reply_full(data)
        if not result:
            print(f"    Parse failed"); continue
        
        status, reply_rid, extra = result
        if status != 0x42:
            print(f"    Status: 0x{status:02X} (expected 0x42)"); continue
        
        challenge_type, key_prefix, max_nonce = parse_cuckoo_challenge(extra)
        header = key_prefix.decode('utf-8', errors='replace')
        print(f"    Header: {header}")
        print(f"    Max nonce: {max_nonce}")
        
        # Solve
        print(f"\n    Solving Cuckoo Cycle...")
        solution, solve_duration = solve_cuckoo(header, max_nonce, attempt)
        
        if solution is None:
            print(f"    No 42-cycle, retrying..."); continue
        
        if len(solution) != 42:
            print(f"    Wrong count: {len(solution)}"); continue
        
        print(f"    Solution: {len(solution)} nonces")
        print(f"    First 5: {solution[:5]}")
        print(f"    Last 5: {solution[-5:]}")
        
        # Build combined packet
        print(f"\n    Building combined packet...")
        pkt, bf_key, cr_size, login_size = build_combined_packet(
            key_prefix, solution, solve_duration, PROTOCOL, rid
        )
        print(f"    CR element: {cr_size}B (MESSAGE, elem 0x03)")
        print(f"    Login element: {login_size}B (REQUEST, elem 0x00)")
        print(f"    Total packet: {len(pkt)}B")
        print(f"    CR body: [duration({solve_duration:.1f}s)] [key:{len(key_prefix)}B] [42×u32]")
        
        sock.sendto(pkt, (server, port))
        rid += 1
        
        try:
            data, _ = sock.recvfrom(4096)
            result = parse_reply_full(data)
            if result:
                status, reply_rid, extra = result
                print(f"\n    *** Response: 0x{status:02X} ***")
                if extra:
                    print(f"    Extra ({len(extra)} bytes): {extra[:80].hex()}")
                    try:
                        msg = extra.decode('utf-8', errors='replace')[:100]
                        if msg.strip(): print(f"    Message: {msg}")
                    except: pass
                
                if status == 0x01:
                    print(f"\n    === LOGIN SUCCESS! ===")
                    print(f"    BF key: {bf_key.hex()}")
                    # Parse login success
                    # [addr: 4B IP + 2B port] [login_key: 4B] [msg: packed_str]
                    if len(extra) >= 10:
                        ip = '.'.join(str(b) for b in extra[:4])
                        port_val = struct.unpack_from("<H", extra, 4)[0]
                        login_key = struct.unpack_from("<I", extra, 6)[0]
                        print(f"    Base app: {ip}:{port_val}")
                        print(f"    Login key: {login_key}")
                        if len(extra) > 10:
                            msg = extra[10:].decode('utf-8', errors='replace')
                            print(f"    Server message: {msg}")
                elif status == 0x42:
                    print(f"    New challenge — solution accepted, need another round?")
                elif status == 0x40:
                    print(f"    MalformedRequest — format still wrong")
                elif status == 0x47:
                    print(f"    Invalid User — need real WG credentials")
                elif status == 0x48:
                    print(f"    Invalid Password")
                elif status == 0x53:
                    print(f"    Rate Limited")
                elif status == 0x55:
                    print(f"    ChallengeError — solution rejected!")
                else:
                    print(f"    Status: 0x{status:02X}")
            else:
                print(f"    No reply parsed")
            break
        except socket.timeout:
            print(f"    Timeout — server didn't respond to combined packet")
            
            # Fallback: try separate packets
            print(f"    Trying separate: CR first, then Login...")
            cr_body = struct.pack("<f", solve_duration) + pack_str(key_prefix) + b''.join(struct.pack("<I", n) for n in solution)
            cr_elem = build_message_v16(0x03, cr_body)
            pkt2 = _pkt(cr_elem, first_req=0)
            sock.sendto(pkt2, (server, port))
            time.sleep(1)
            
            login_body2, _ = build_login_body(PROTOCOL)
            login_elem = build_request_v16(0x00, rid, login_body2)
            pkt3 = _pkt(login_elem, first_req=0)
            sock.sendto(pkt3, (server, port))
            rid += 1
            
            try:
                data, _ = sock.recvfrom(4096)
                result = parse_reply_full(data)
                if result:
                    status, _, extra = result
                    print(f"    Separate response: 0x{status:02X}")
                    if extra: print(f"    Extra: {extra[:80].hex()}")
                else:
                    print(f"    No reply")
            except socket.timeout:
                print(f"    Separate also timed out")
            break
    
    sock.close()
    print(f"\nDone.")

if __name__ == "__main__":
    run()

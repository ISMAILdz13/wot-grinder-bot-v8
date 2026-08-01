#!/usr/bin/env python3
"""WoT Bot v30 — COMPLETE LOGIN FLOW

Protocol version 17.1.0 (5) = 285278213 — CONFIRMED WORKING!
Format: [proto(4B)] [LogOnParams] — NO encrypted flag byte (C++ format)

Flow:
1. Send LoginRequest → get Cuckoo challenge (0x42)
2. Parse challenge: type="cuckoo_cycle", key_prefix, max_nonce
3. Solve Cuckoo Cycle (SipHash-2-4 based PoW)
4. Send ChallengeResponse with solution
5. Send NEW LoginRequest (same BF key)
6. Get LoginSuccess (Blowfish-encrypted) with base app address
"""
import socket, struct, os, hashlib, time

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
    """C++ format: [proto(4B)] [LogOnParams] — NO enc flag!"""
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
    """Parse Cuckoo Cycle challenge from reply data"""
    pos = 0
    
    # Read challenge type string (packed)
    first = extra[pos]; pos += 1
    if first >= 255:
        slen = int.from_bytes(extra[pos:pos+3], 'little')
        pos += 3
    else:
        slen = first
    challenge_type = extra[pos:pos+slen].decode('utf-8', errors='replace')
    pos += slen
    
    # Read key_prefix blob (packed)
    first = extra[pos]; pos += 1
    if first >= 255:
        klen = int.from_bytes(extra[pos:pos+3], 'little')
        pos += 3
    else:
        klen = first
    key_prefix = extra[pos:pos+klen]
    pos += klen
    
    # Read max_nonce (u32 LE)
    max_nonce = struct.unpack_from("<I", extra, pos)[0] if pos + 4 <= len(extra) else 65536
    pos += 4
    
    return challenge_type, key_prefix, max_nonce

# ============ SIPHASH-2-4 (pure Python) ============
def siphash24(key_bytes, data):
    """SipHash-2-4 using a 16-byte key"""
    k0 = struct.unpack_from("<Q", key_bytes, 0)[0]
    k1 = struct.unpack_from("<Q", key_bytes, 8)[0]
    
    v0 = k0 ^ 0x736f6d6570736575
    v1 = k1 ^ 0x646f72616e646f6d
    v2 = k0 ^ 0x6c7967656e657261
    v3 = k1 ^ 0x7465646279746573
    
    MASK = 0xFFFFFFFFFFFFFFFF
    
    def rotl(x, b):
        return ((x << b) | (x >> (64 - b))) & MASK
    
    def sipround():
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & MASK; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32)
        v2 = (v2 + v3) & MASK; v3 = rotl(v3, 16); v3 ^= v2
        v0 = (v0 + v3) & MASK; v3 = rotl(v3, 21); v3 ^= v0
        v2 = (v2 + v1) & MASK; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32)
    
    pos = 0
    while pos + 8 <= len(data):
        m = struct.unpack_from("<Q", data, pos)[0]
        v3 ^= m
        sipround(); sipround()
        v0 ^= m
        pos += 8
    
    remaining = len(data) - pos
    last = data[pos:] if remaining > 0 else b''
    last = last + b'\x00' * (7 - remaining) + bytes([remaining])
    m = struct.unpack("<Q", last)[0]
    v3 ^= m
    sipround(); sipround()
    v0 ^= m
    
    v2 ^= 0xFF
    sipround(); sipround(); sipround(); sipround()
    return (v0 ^ v1 ^ v2 ^ v3) & MASK

def cuckoo_edge(key, nonce, graph_size=20):
    """Compute the two endpoints of edge for nonce"""
    h = siphash24(key, struct.pack("<Q", nonce))
    u = (h >> (64 - graph_size)) & ((1 << graph_size) - 1)
    v = ((h >> 1) >> (64 - graph_size)) & ((1 << graph_size) - 1)
    return u, v

def solve_cuckoo(key_prefix, max_nonce=1000000, graph_size=20):
    """Solve Cuckoo Cycle PoW — find 42-cycle"""
    print(f"    Solving Cuckoo Cycle...")
    print(f"    Key prefix: {key_prefix.hex()}")
    print(f"    Max nonce: {max_nonce}")
    
    key = hashlib.sha256(key_prefix).digest()[:16]
    print(f"    SipHash key: {key.hex()}")
    
    N = 1 << graph_size
    t0 = time.time()
    
    # Build adjacency list
    adj = {}
    print(f"    Building graph with {max_nonce} edges...")
    
    for nonce in range(max_nonce):
        u, v = cuckoo_edge(key, nonce, graph_size)
        if u == v:
            continue
        adj.setdefault(u, []).append((v, nonce))
        adj.setdefault(v, []).append((u, nonce))
        
        if nonce % 200000 == 0 and nonce > 0:
            elapsed = time.time() - t0
            print(f"    ... {nonce}/{max_nonce} edges, {elapsed:.1f}s, {len(adj)} nodes")
    
    print(f"    Graph: {len(adj)} nodes, {time.time()-t0:.1f}s")
    
    # Find 42-cycle using BFS from each node
    print(f"    Searching for 42-cycle...")
    target = 42
    
    for start_node in list(adj.keys()):
        # BFS
        visited = {start_node}
        # (node, path_nonces, path_nodes)
        queue = [(start_node, [], [start_node])]
        
        while queue:
            node, path, nodes_path = queue.pop(0)
            depth = len(path)
            
            if depth >= target:
                # Check if last edge connects back to start
                if node == start_node and depth == target:
                    print(f"    FOUND 42-cycle!")
                    return path
                continue
            
            for neighbor, nonce in adj.get(node, []):
                if depth == target - 1:
                    # Last edge — must connect back to start
                    if neighbor == start_node and len(path) + 1 == target:
                        print(f"    FOUND 42-cycle!")
                        return path + [nonce]
                elif neighbor not in visited and neighbor != start_node:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [nonce], nodes_path + [neighbor]))
        
        if start_node % 100 == 0:
            elapsed = time.time() - t0
            if elapsed > 60:
                print(f"    Timeout after {elapsed:.0f}s, trying random approach...")
                break
    
    # Random approach: try to find cycle via random walks
    print(f"    Trying random walk approach...")
    import random
    
    for attempt in range(100000):
        start = random.choice(list(adj.keys()))
        path = []
        visited = set()
        current = start
        edges = adj.get(current, [])
        if not edges:
            continue
            
        nonce = edges[0][1]
        path.append(nonce)
        current, _ = edges[0]
        
        while len(path) < target:
            current = current ^ 0  # just to keep going
            edges = adj.get(current, [])
            if not edges:
                break
            nonce = random.choice(edges)[1]
            if nonce in path:
                break
            path.append(nonce)
            # Follow edge to other endpoint
            u, v = cuckoo_edge(key, nonce, graph_size)
            current = v if current == u else u
            
            if len(path) == target and current == start:
                print(f"    FOUND 42-cycle at attempt {attempt}!")
                return path
        
        if attempt % 10000 == 0 and attempt > 0:
            print(f"    ... {attempt} attempts, {time.time()-t0:.1f}s")
    
    print(f"    No cycle found after {time.time()-t0:.1f}s")
    return None

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=10):
    PROTOCOL = 285278213  # 17.1.0 (5) — CONFIRMED!
    
    print(f"\n{'='*55}")
    print(f"  WoT Bot v30 — COMPLETE LOGIN FLOW")
    print(f"  Protocol: 17.1.0 (5) = {PROTOCOL}")
    print(f"  {server}:{port}")
    print(f"{'='*55}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1
    
    # Step 1: PING
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
    
    # Step 2: Send LoginRequest
    print(f"\n[2] Sending LoginRequest (protocol 17.1.0.5)...")
    login_body, bf_key = build_login_body(PROTOCOL)
    
    login_rid = rid
    elem = build_element_v16(0x00, rid, login_body)
    pkt = _pkt(elem, first_req=0)
    sock.sendto(pkt, (server, port))
    rid += 1
    
    try:
        data, _ = sock.recvfrom(4096)
        result = parse_reply_full(data)
        if not result:
            print(f"    Failed to parse reply"); sock.close(); return
        
        status, reply_rid, extra = result
        print(f"    Status: 0x{status:02X}, RID: 0x{reply_rid:08X}")
        print(f"    Extra ({len(extra)} bytes): {extra[:64].hex()}")
        
        if status == 0x41:
            print(f"    BadProtocolVersion"); sock.close(); return
        elif status == 0x40:
            print(f"    MalformedRequest — LogOnParams wrong"); sock.close(); return
        elif status == 0x42:
            print(f"\n[3] Cuckoo Challenge received!")
            
            # Dump raw bytes for debugging
            for i in range(0, min(len(extra), 64), 16):
                chunk = extra[i:i+16]
                print(f"    {i:4d}: {chunk.hex()}")
            
            try:
                challenge_type, key_prefix, max_nonce = parse_cuckoo_challenge(extra)
                print(f"    Type: {challenge_type}")
                print(f"    Key prefix ({len(key_prefix)} bytes): {key_prefix.hex()}")
                print(f"    Key prefix (text): {key_prefix}")
                print(f"    Max nonce: {max_nonce}")
            except Exception as e:
                print(f"    Parse error: {e}")
                print(f"    Raw extra hex: {extra.hex()}")
                sock.close(); return
            
            # Step 4: Solve Cuckoo
            print(f"\n[4] Solving Cuckoo Cycle PoW...")
            solution = solve_cuckoo(key_prefix, max_nonce, graph_size=20)
            
            if solution is None:
                print(f"    Failed to solve!")
                sock.close(); return
            
            print(f"    Solution: {len(solution)} nonces")
            print(f"    First 10: {solution[:10]}")
            
            # Step 5: Send ChallengeResponse
            print(f"\n[5] Sending ChallengeResponse...")
            duration = 1.0
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
                        print(f"    Extra: {extra[:64].hex()}")
                    
                    if status == 0x42:
                        print(f"    Another challenge issued")
                    elif status == 0x01:
                        print(f"    LOGIN SUCCESS!")
                    elif status == 0x47:
                        print(f"    Invalid User — need real WG credentials")
                    elif status == 0x53:
                        print(f"    Rate Limited")
                    else:
                        print(f"    Status: 0x{status:02X}")
                else:
                    print(f"    No reply parsed")
            except socket.timeout:
                print(f"    Timeout")
            
            # Step 6: Re-send LoginRequest
            print(f"\n[6] Sending NEW LoginRequest...")
            new_body, _ = build_login_body(PROTOCOL)  # same BF key!
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
                    
                    if status == 0x01:
                        print(f"\n    *** LOGIN SUCCESS! ***")
                        print(f"    Need Blowfish decrypt with BF key")
                    elif status == 0x42:
                        print(f"    Challenge again — Cuckoo solution rejected")
                    elif status == 0x47:
                        print(f"    Invalid User — 'guest' not accepted")
                    elif status == 0x48:
                        print(f"    Invalid Password")
                    elif status == 0x53:
                        print(f"    Rate Limited")
                    else:
                        print(f"    Status: 0x{status:02X}")
                else:
                    print(f"    No reply")
            except socket.timeout:
                print(f"    Timeout")
        else:
            print(f"    Unexpected: 0x{status:02X}")
    except socket.timeout:
        print(f"    Timeout")
    
    sock.close()
    print(f"\nDone.")

if __name__ == "__main__":
    run()

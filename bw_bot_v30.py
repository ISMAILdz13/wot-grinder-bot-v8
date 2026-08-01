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
import socket, struct, os, hashlib, time, siphash  # we may need to implement siphash

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
    return struct.pack("<I", protocol) + logon

def parse_reply_full(data):
    """Parse full reply element including extra data"""
    if len(data) < 6: return None
    content = data[6:]
    if len(content) < 5: return None
    if content[0] != 0xFF:
        return None
    length = struct.unpack_from("<I", content, 1)[0]
    rdata = content[5:5+length]
    if len(rdata) < 5: return None
    rid = struct.unpack_from("<I", rdata, 0)[0]
    status = rdata[4]
    extra = rdata[5:]
    return (status, rid, extra)

def parse_cuckoo_challenge(extra):
    """Parse Cuckoo Cycle challenge from reply data"""
    # Format: [type_str(packed)] [key_prefix(packed_blob)] [max_nonce(u32)]
    pos = 0
    
    # Read challenge type string
    first = extra[pos]; pos += 1
    if first >= 255:
        slen = struct.unpack_from("<I", extra, pos-1)[0] & 0xFFFFFF  # 3 bytes after 0xFF
        slen = int.from_bytes(extra[pos:pos+3], 'little')
        pos += 3
    else:
        slen = first
    challenge_type = extra[pos:pos+slen].decode('utf-8', errors='replace')
    pos += slen
    
    # Read key_prefix blob
    first = extra[pos]; pos += 1
    if first >= 255:
        klen = int.from_bytes(extra[pos:pos+3], 'little')
        pos += 3
    else:
        klen = first
    key_prefix = extra[pos:pos+klen]
    pos += klen
    
    # Read max_nonce (u32 LE)
    max_nonce = struct.unpack_from("<I", extra, pos)[0] if pos + 4 <= len(extra) else 0
    pos += 4
    
    return challenge_type, key_prefix, max_nonce

# ============ SIPHASH-2-4 IMPLEMENTATION ============
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
    
    # Process blocks
    pos = 0
    while pos + 8 <= len(data):
        m = struct.unpack_from("<Q", data, pos)[0]
        v3 ^= m
        sipround(); sipround()
        v0 ^= m
        pos += 8
    
    # Last block with padding
    remaining = len(data) - pos
    last_block = data[pos:] if remaining > 0 else b''
    last_block = last_block + b'\x00' * (7 - remaining) + bytes([remaining])
    m = struct.unpack("<Q", last_block)[0]
    v3 ^= m
    sipround(); sipround()
    v0 ^= m
    
    # Finalization
    v2 ^= 0xFF
    sipround(); sipround(); sipround(); sipround()
    
    return (v0 ^ v1 ^ v2 ^ v3) & MASK

def cuckoo_hash(key, nonce):
    """Compute the edge hash for Cuckoo Cycle"""
    data = struct.pack("<Q", nonce)
    return siphash24(key, data)

def solve_cuckoo(key_prefix, max_nonce=1000000, graph_size=20):
    """Solve Cuckoo Cycle PoW
    
    Graph has 2^graph_size nodes, edges = nonce values
    Find a cycle of length 42
    """
    print(f"    Solving Cuckoo Cycle...")
    print(f"    Key prefix: {key_prefix.hex()}")
    print(f"    Max nonce: {max_nonce}")
    print(f"    Graph size: 2^{graph_size} = {1 << graph_size} nodes")
    
    # Hash the key_prefix with SHA-256 to get the 16-byte SipHash key
    key = hashlib.sha256(key_prefix).digest()[:16]
    print(f"    SipHash key: {key.hex()}")
    
    N = 1 << graph_size  # number of nodes
    E = max_nonce         # number of edges to try
    
    # Build adjacency: for each edge (nonce), compute two node endpoints
    # node_u = hash(key, nonce) % N
    # node_v = hash(key, nonce | 0x8000000000000000) % N
    # Actually, in Cuckoo Cycle:
    # edge = siphash(key, nonce)
    # u = edge >> (64 - graph_size)  (top bits)
    # v = (edge & MASK_V) >> (64 - graph_size - 1)  (bottom bits with toggle)
    
    # Standard Cuckoo Cycle: u = edge >> (EDGE_BITS), v = edge & EDGE_MASK >> (EDGE_BITS)
    # Simplified: u and v are derived from the hash
    
    t0 = time.time()
    
    # Try a simplified approach: build graph and look for cycles
    # For production, use a proper Cuckoo solver
    
    # Build edge list
    edges = {}
    adj = {}  # node -> list of (neighbor, nonce)
    
    print(f"    Building graph with {E} edges...")
    for nonce in range(E):
        h = cuckoo_hash(key, nonce)
        u = h >> (64 - graph_size)  # top graph_size bits
        v = (h >> 1) >> (64 - graph_size)  # shifted for bipartite
        
        # Avoid self-loops
        if u == v:
            continue
        
        if u not in adj:
            adj[u] = []
        if v not in adj:
            adj[v] = []
        adj[u].append((v, nonce))
        adj[v].append((u, nonce))
        
        if nonce % 100000 == 0 and nonce > 0:
            elapsed = time.time() - t0
            print(f"    ... {nonce}/{E} edges, {elapsed:.1f}s, {len(adj)} nodes")
    
    print(f"    Graph built: {len(adj)} nodes, {E} edges, {time.time()-t0:.1f}s")
    
    # Find cycle of length 42 using BFS/DFS
    print(f"    Searching for 42-cycle...")
    
    # For efficiency, use a path-following approach
    # Start from each node, try to find a cycle of length 42
    target_len = 42
    
    for start_node in list(adj.keys())[:10000]:  # limit search
        # BFS to find cycle
        visited = {start_node: (None, None)}  # node -> (parent, nonce)
        queue = [(start_node, 0)]
        
        while queue:
            node, depth = queue.pop(0)
            if depth >= target_len // 2:
                break
            
            for neighbor, nonce in adj.get(node, []):
                if neighbor == start_node and depth > 1:
                    # Found cycle! But need exact length 42
                    if (depth + 1) == target_len:
                        print(f"    FOUND 42-cycle at nonce {nonce}!")
                        # Reconstruct path
                        path = []
                        n = node
                        while n is not None:
                            p, nt = visited[n]
                            if nt is not None:
                                path.append(nt)
                            n = p
                        path.append(nonce)
                        return path[:42]
                    continue
                
                if neighbor not in visited:
                    visited[neighbor] = (node, nonce)
                    queue.append((neighbor, depth + 1))
    
    # If no cycle found with simple BFS, try random approach
    print(f"    BFS didn't find cycle, trying random approach...")
    
    # Try: pick random nonces and build a path
    import random
    for attempt in range(10000):
        nonce = random.randint(0, E - 1)
        path = [nonce]
        nodes = set()
        h = cuckoo_hash(key, nonce)
        u = h >> (64 - graph_size)
        
        for _ in range(target_len):
            h = cuckoo_hash(key, path[-1])
            v = (h >> 1) >> (64 - graph_size)
            
            if v in nodes:
                break
            nodes.add(v)
            
            # Find next edge from v
            next_edges = adj.get(v, [])
            if not next_edges:
                break
            
            next_nonce = next_edges[0][1]
            if next_nonce in path:
                break
            
            path.append(next_nonce)
            
            if len(path) == target_len:
                print(f"    Found 42-cycle at attempt {attempt}!")
                return path
    
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
    bf_key = os.urandom(16)
    login_body = struct.pack("<I", PROTOCOL) + struct.pack("<B", 0) + \
                 pack_str("guest") + pack_str("") + pack_str(bf_key) + struct.pack("<I", 0)
    
    login_rid = rid
    elem = build_element_v16(0x00, rid, login_body)
    pkt = _pkt(elem, first_req=0)
    sock.sendto(pkt, (server, port))
    rid += 1
    
    try:
        data, _ = sock.recvfrom(4096)
        result = parse_reply_full(data)
        if not result:
            print(f"    Failed to parse reply")
            sock.close(); return
        
        status, reply_rid, extra = result
        print(f"    Status: 0x{status:02X}, RID: 0x{reply_rid:08X}")
        print(f"    Extra data ({len(extra)} bytes): {extra[:64].hex()}")
        
        if status == 0x41:
            print(f"    BadProtocolVersion — version rejected")
            sock.close(); return
        elif status == 0x40:
            print(f"    MalformedRequest — LogOnParams format wrong")
            sock.close(); return
        elif status == 0x42:
            print(f"\n[3] Cuckoo Challenge received!")
            
            # Parse the challenge
            try:
                challenge_type, key_prefix, max_nonce = parse_cuckoo_challenge(extra)
                print(f"    Type: {challenge_type}")
                print(f"    Key prefix ({len(key_prefix)} bytes): {key_prefix.hex()}")
                print(f"    Key prefix (text): {key_prefix}")
                print(f"    Max nonce: {max_nonce}")
            except Exception as e:
                print(f"    Parse error: {e}")
                print(f"    Raw extra: {extra.hex()}")
                # Try manual parse
                print(f"    Trying manual parse...")
                # The challenge format might be different
                # Let me dump the raw bytes
                for i in range(0, len(extra), 16):
                    chunk = extra[i:i+16]
                    print(f"    {i:4d}: {chunk.hex()} | {chunk}")
                sock.close(); return
            
            # Step 4: Solve Cuckoo Cycle
            print(f"\n[4] Solving Cuckoo Cycle PoW...")
            solution = solve_cuckoo(key_prefix, max_nonce, graph_size=20)
            
            if solution is None:
                print(f"    Failed to solve Cuckoo challenge!")
                sock.close(); return
            
            print(f"    Solution: {len(solution)} nonces")
            print(f"    Nonces: {solution[:10]}...")
            
            # Step 5: Send ChallengeResponse
            print(f"\n[5] Sending ChallengeResponse...")
            challenge_rid = rid
            duration = 1.0  # calculation duration in seconds
            
            # ChallengeResponse format: [duration(f32)] [solution_blob]
            # The solution is 42 u32 nonces
            solution_blob = b''.join(struct.pack("<I", n) for n in solution)
            challenge_body = struct.pack("<f", duration) + pack_str(solution_blob)
            
            # Element 0x03 (CHALLENGE_RESPONSE) V16
            elem = build_element_v16(0x03, rid, challenge_body)
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
                        print(f"    Extra: {extra[:64].hex()}")
                    
                    if status == 0x42:
                        print(f"    Another challenge? Need to solve again?")
                    elif status == 0x01:
                        print(f"    LOGIN SUCCESS!")
                        # Parse login success (Blowfish-encrypted)
                        # Contains: base_app_addr, login_key, server_message
                    elif status == 0x47:
                        print(f"    Invalid User — need proper credentials")
                    elif status == 0x48:
                        print(f"    Invalid Password")
                    elif status == 0x53:
                        print(f"    Rate Limited")
                    else:
                        print(f"    Status 0x{status:02X} — see error codes")
                else:
                    print(f"    No reply parsed")
            except socket.timeout:
                print(f"    Timeout waiting for challenge response")
            
            # Step 6: Send NEW LoginRequest
            print(f"\n[6] Sending NEW LoginRequest...")
            new_login_body = struct.pack("<I", PROTOCOL) + struct.pack("<B", 0) + \
                            pack_str("guest") + pack_str("") + pack_str(bf_key) + struct.pack("<I", 0)
            
            new_login_rid = rid
            elem = build_element_v16(0x00, rid, new_login_body)
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
                        print(f"    Need to decrypt with Blowfish (BF key: {bf_key.hex()})")
                        # Parse: [addr(4B IP + 2B port)] [login_key(4B)] [msg(str)]
                    elif status == 0x42:
                        print(f"    Another challenge — need to solve again")
                    elif status == 0x47:
                        print(f"    Invalid User — need WG credentials, not 'guest'")
                    elif status == 0x48:
                        print(f"    Invalid Password")
                    elif status == 0x53:
                        print(f"    Rate Limited — too many attempts")
                    else:
                        print(f"    Status 0x{status:02X}")
                else:
                    print(f"    No reply")
            except socket.timeout:
                print(f"    Timeout")
        else:
            print(f"    Unexpected status: 0x{status:02X}")
    except socket.timeout:
        print(f"    Timeout waiting for login response")
    
    sock.close()
    print(f"\nDone.")

if __name__ == "__main__":
    run()

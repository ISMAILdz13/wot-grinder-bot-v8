#!/usr/bin/env python3
"""WoT Bot v26 — Brute force protocol version on Element 0x00 V16

v25 confirmed: Element 0x00 V16 with fixed length WORKS (server reads rid correctly).
ALL tested versions (50,51,52,55,324) give 0x41 (BadProtocolVersion).
Need to find the correct version — scanning 0-200 + struct versions.

When we get 0x40 (MalformedRequest) instead of 0x41, we found the version!
Then v27 will fix the LogOnParams to get CHALLENGE (0x42).
"""
import socket, struct, os, sys, time

exec(open('/root/wot-grinder-bot-v8/bw_bot_v3.py' if os.path.exists('/root/wot-grinder-bot-v8/bw_bot_v3.py') else '/tmp/bw_bot_v3.py').read().split('def run(')[0])

def pack_u24(n):
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[:3]
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_u24(len(b)) + b

def build_element_v16(elem_id, rid, body):
    """FIXED: length = body ONLY."""
    return struct.pack("<BH", elem_id, len(body)) + struct.pack("<IH", rid, 0) + body

def build_login_body(protocol, encrypted=False):
    """Minimal login body: [protocol(4B)] + [encrypted_flag(1B=0)] + [LogOnParams]"""
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + pack_str("guest") + struct.pack("<I", 0)
    return struct.pack("<I", protocol) + struct.pack("<B", 0) + logon

def parse_reply(data):
    if len(data) < 11: return None
    content = data[6:]
    if len(content) >= 5 and content[0] == 0xFF:
        length = struct.unpack_from("<I", content, 1)[0]
        rdata = content[5:5+length]
        if len(rdata) >= 5:
            status = rdata[4]
            rid = struct.unpack_from("<I", rdata, 0)[0]
            return (status, rid)
    return None

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=2):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v26 — Brute Force Protocol Version")
    print(f"  {server}:{port}")
    print(f"{'='*55}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1
    
    # PING
    print(f"\n[1] PING...")
    sock.sendto(ping_packet(rid=rid), (server, port))
    try:
        data, _ = sock.recvfrom(4096)
        print(f"    PING OK"); rid += 1
    except socket.timeout:
        print(f"    PING timeout — trying p2...")
        sock.close(); sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        server, port = "login.p2.worldoftanks.eu", 20018
        sock.sendto(ping_packet(rid=rid), (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            print(f"    p2 PING OK"); rid += 1
        except socket.timeout:
            print(f"    All PING failed"); sock.close(); return
    
    # Build version list to test
    versions = []
    
    # Simple u32: 0-100
    for v in range(0, 101):
        versions.append((v, f"u32={v}"))
    
    # Higher values: 100-500 in steps of 5
    for v in range(105, 501, 5):
        versions.append((v, f"u32={v}"))
    
    # Struct versions (subpatch, patch, minor, major) as u32 LE
    # Format: bytes [sp, pa, mi, ma] → u32 LE
    for sp in range(0, 5):
        for pa in range(0, 20):
            for mi in [0, 1, 2, 3]:
                for ma in [0, 1, 2, 3]:
                    val = sp + pa*256 + mi*65536 + ma*16777216
                    if val not in [v for v, _ in versions]:
                        versions.append((val, f"struct({sp},{pa},{mi},{ma})={val}"))
    
    # Game version as integer
    for v in [20, 21, 22, 23, 230, 231, 232, 233, 200, 201, 202, 203,
             2000, 2001, 2002, 2003, 2010, 2020, 2030, 2031,
             65536, 65537, 131072, 131073, 196608, 196609,
             262144, 327680, 393216, 458752, 524288]:
        if v not in [v2 for v2, _ in versions]:
            versions.append((v, f"game_ver={v}"))
    
    # Remove duplicates and sort
    seen = set()
    unique_versions = []
    for v, desc in versions:
        if v not in seen:
            seen.add(v)
            unique_versions.append((v, desc))
    unique_versions.sort(key=lambda x: x[0])
    
    print(f"\n[2] Testing {len(unique_versions)} protocol versions...")
    print(f"    Looking for 0x40 (MalformedRequest) = version accepted!")
    print(f"    (0x41 = BadProtocolVersion = wrong version)")
    
    found = False
    count = 0
    for version, desc in unique_versions:
        body = build_login_body(version)
        elem = build_element_v16(0x00, rid, body)
        pkt = _pkt(elem, first_req=0)
        
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            result = parse_reply(data)
            if result:
                status, reply_rid = result
                if status == 0x40:
                    print(f"\n  *** FOUND! version={version} ({desc}) → 0x40 (MalformedRequest) ***")
                    print(f"      Server ACCEPTED version, body needs fixing!")
                    found = True
                    break
                elif status == 0x42:
                    print(f"\n  *** CHALLENGE! version={version} ({desc}) → 0x42 ***")
                    found = True
                    break
                elif status == 1:
                    print(f"\n  *** SUCCESS! version={version} ({desc}) → 0x01 ***")
                    found = True
                    break
                # 0x41 = BadProtocolVersion, skip silently
            rid += 1
        except socket.timeout:
            # Timeout might mean we hit the right version but server is waiting for more
            # Or it might mean rate limiting. Only report if it's unusual.
            rid += 1
        
        count += 1
        if count % 50 == 0:
            print(f"    ... tested {count}/{len(unique_versions)} versions so far (last: {desc})")
    
    sock.close()
    
    if not found:
        print(f"\n  Tested {count} versions, all returned 0x41 (BadProtocolVersion) or timeout")
        print(f"  The correct version might be > 500 or in a different format")
    else:
        print(f"\n  Found correct version after {count} tests!")
        print(f"  Next step: fix LogOnParams to get CHALLENGE (0x42)")

if __name__ == "__main__":
    run()

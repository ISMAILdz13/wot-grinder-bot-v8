#!/usr/bin/env python3
"""WoT Bot v27 — Focused protocol version scan

v26 missed struct versions with minor > 3 (BigWorld 2.9.0.0 has minor=9!).
Also trying BigWorld 14.4.1 engine version, higher u32 values, and build numbers.

From wg-toolkit-rs server.rs: GAME_VERSION = "eu_1.19.1_4"
This means the game version is 1.19.1, and the protocol might use:
  struct(0, 1, 19, 1) = 1 + 1*256 + 19*65536 + 1*16777216 = 16908545
  OR the BigWorld engine version (2.9.0.0 = struct(0,0,9,2) = 34144256)
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
    return struct.pack("<BH", elem_id, len(body)) + struct.pack("<IH", rid, 0) + body

def build_login_body(protocol):
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
            return (rdata[4], struct.unpack_from("<I", rdata, 0)[0])
    return None

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=2):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v27 — Focused Version Scan")
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
    
    versions = []
    
    # Struct versions with minor 4-25, major 0-5 (THE RANGE WE MISSED!)
    for ma in range(0, 6):
        for mi in range(4, 26):
            for pa in [0, 1]:
                for sp in [0]:
                    val = sp + pa*256 + mi*65536 + ma*16777216
                    versions.append((val, f"struct({sp},{pa},{mi},{ma})"))
    
    # BigWorld engine 14.x
    for sp in [0, 1]:
        for pa in [0, 1, 4]:
            for mi in [0, 1, 4]:
                for ma in [14, 15]:
                    val = sp + pa*256 + mi*65536 + ma*16777216
                    if val not in [v for v, _ in versions]:
                        versions.append((val, f"BW({sp},{pa},{mi},{ma})"))
    
    # WoT 1.19.x versions (from wg-toolkit-rs default)
    for pa in range(0, 5):
        for sp in range(0, 5):
            val = sp + pa*256 + 19*65536 + 1*16777216
            if val not in [v for v, _ in versions]:
                versions.append((val, f"wot1.19.{sp}.{pa}"))
    
    # WoT 2.x with minor > 3
    for mi in range(4, 26):
        for pa in range(0, 5):
            val = 0 + pa*256 + mi*65536 + 2*16777216
            if val not in [v for v, _ in versions]:
                versions.append((val, f"wot2.{mi}.{pa}"))
    
    # Higher simple u32 values
    for v in range(100, 501):
        if v not in [v2 for v2, _ in versions]:
            versions.append((v, f"u32={v}"))
    
    # Powers of 2 and common values
    for v in [196, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
             131072, 262144, 524288, 1048576, 2097152, 4194304,
             853, 956054, 956000, 956100,  # build numbers from version.xml
             1191, 11914, 11910,  # game version as int
             231, 2310, 230, 2300,  # WoT 2.3.1 as int
             200, 2000, 20000, 200000,  # WoT 2.0
             100000, 200000, 300000, 400000, 500000, 600000, 700000, 800000, 900000,
             1000000, 2000000, 3000000, 5000000, 10000000,
             ]:
        if v not in [v2 for v2, _ in versions]:
            versions.append((v, f"special={v}"))
    
    # Sort and deduplicate
    seen = set()
    unique = []
    for v, d in versions:
        if v not in seen:
            seen.add(v)
            unique.append((v, d))
    unique.sort(key=lambda x: x[0])
    
    print(f"\n[2] Testing {len(unique)} versions (focused on struct minor 4-25, BW 14.x)...")
    
    found = False
    count = 0
    for version, desc in unique:
        body = build_login_body(version)
        elem = build_element_v16(0x00, rid, body)
        pkt = _pkt(elem, first_req=0)
        
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            result = parse_reply(data)
            if result:
                status, reply_rid = result
                if status != 0x41:  # Not BadProtocolVersion = interesting!
                    print(f"\n  [{rid}] *** {desc}={version} → status=0x{status:02X} rid=0x{reply_rid:08X} ***")
                    if status == 0x40:
                        print(f"      MALFORMED REQUEST — version accepted!")
                        found = True
                        break
                    elif status == 0x42:
                        print(f"      CHALLENGE!")
                        found = True
                        break
                    elif status == 1:
                        print(f"      SUCCESS!")
                        found = True
                        break
            rid += 1
        except socket.timeout:
            # Timeout could mean rate limit or unusual
            rid += 1
        
        count += 1
        if count % 100 == 0:
            print(f"    ... {count}/{len(unique)} ({desc}={version})")
    
    sock.close()
    if not found:
        print(f"\n  Tested {count} versions, all 0x41 or timeout")
        print(f"  Protocol version is outside our search range")
        print(f"  May need to capture real WoT client traffic")
    else:
        print(f"\n  FOUND after {count} tests!")

if __name__ == "__main__":
    run()

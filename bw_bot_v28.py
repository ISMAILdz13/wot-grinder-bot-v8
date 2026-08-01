#!/usr/bin/env python3
"""WoT Bot v28 — Test patch=255 versions (THE BIG MISS!)

BigWorld source shows patch=255 was used for intermediate versions:
  Version 2.2.255 (0-5): Server-controlled entities
  Version 2.6.255 (0-6): WritePackedInt, login challenges, replay
  
We NEVER tested patch=255 in v26/v27! Only tested patch 0-19.

Specifically targeting 2.6.255.5 = where login challenges were added.
struct(subpatch, patch, minor, major) = (5, 255, 6, 2) = 34012933

Also: the supports() function checks EXACT match, so we need the EXACT version.
"""
import socket, struct, os

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
    print(f"  WoT Bot v28 — patch=255 versions + subpatches")
    print(f"  {server}:{port}")
    print(f"{'='*55}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1
    
    print(f"\n[1] PING...")
    sock.sendto(ping_packet(rid=rid), (server, port))
    try: sock.recvfrom(4096); print(f"    PING OK"); rid += 1
    except socket.timeout:
        sock.close(); sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        server, port = "login.p2.worldoftanks.eu", 20018
        sock.sendto(ping_packet(rid=rid), (server, port))
        try: sock.recvfrom(4096); print(f"    p2 PING OK"); rid += 1
        except: print(f"    PING failed"); sock.close(); return
    
    versions = []
    
    # CRITICAL: patch=255 versions from BigWorld source
    # Version 2.2.255 (0-5) — subpatch 0-5
    for sp in range(0, 6):
        val = sp + 255*256 + 2*65536 + 2*16777216
        versions.append((val, f"v2.2.255.{sp}"))
    
    # Version 2.6.255 (0-6) — subpatch 0-6 (login challenges added in .5!)
    for sp in range(0, 7):
        val = sp + 255*256 + 6*65536 + 2*16777216
        versions.append((val, f"v2.6.255.{sp}"))
    
    # Version 2.9.0 (0-5) — subpatch 0-5
    for sp in range(0, 6):
        val = sp + 0*256 + 9*65536 + 2*16777216
        versions.append((val, f"v2.9.0.{sp}"))
    
    # Higher minor with patch=255
    for mi in range(7, 30):
        val = 0 + 255*256 + mi*65536 + 2*16777216
        versions.append((val, f"v2.{mi}.255.0"))
    
    # Higher minor without patch=255 (we tested 4-25, now try 26-100)
    for mi in range(26, 101):
        val = 0 + 0 + mi*65536 + 2*16777216
        versions.append((val, f"v2.{mi}.0.0"))
    
    # Major 3-10 with minor 0-30 and patch 0
    for ma in range(3, 11):
        for mi in [0, 1, 2, 3, 5, 9, 10, 20, 30]:
            val = 0 + 0 + mi*65536 + ma*16777216
            versions.append((val, f"v{ma}.{mi}.0.0"))
    
    # Major 3-10 with patch=255
    for ma in range(3, 11):
        for mi in [0, 2, 6, 9]:
            val = 0 + 255*256 + mi*65536 + ma*16777216
            versions.append((val, f"v{ma}.{mi}.255.0"))
    
    # Very high minor values (100-255) with major 2
    for mi in [100, 150, 200, 255]:
        val = 0 + 0 + mi*65536 + 2*16777216
        versions.append((val, f"v2.{mi}.0.0"))
    
    # Subpatch variations for 2.9.0 (maybe WoT uses subpatch=1 or higher)
    for sp in range(1, 255):
        val = sp + 0 + 9*65536 + 2*16777216
        versions.append((val, f"v2.9.0.{sp}"))
    
    # Sort and deduplicate
    seen = set()
    unique = []
    for v, d in versions:
        if v not in seen:
            seen.add(v)
            unique.append((v, d))
    unique.sort(key=lambda x: x[0])
    
    print(f"\n[2] Testing {len(unique)} versions (patch=255 focus!)...")
    print(f"    Key target: v2.6.255.5 = {5 + 255*256 + 6*65536 + 2*16777216}")
    
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
                if status != 0x41:
                    print(f"\n  [{rid}] *** {desc}={version} → 0x{status:02X} rid=0x{reply_rid:08X} ***")
                    if status == 0x40:
                        print(f"      MALFORMED REQUEST — version accepted! Fix LogOnParams next!")
                        found = True; break
                    elif status == 0x42:
                        print(f"      CHALLENGE! Need to solve Cuckoo PoW!")
                        found = True; break
                    elif status == 1:
                        print(f"      SUCCESS!")
                        found = True; break
            rid += 1
        except socket.timeout:
            rid += 1
        
        count += 1
        if count % 100 == 0:
            print(f"    ... {count}/{len(unique)} ({desc}={version})")
    
    sock.close()
    if not found:
        print(f"\n  Tested {count} versions, all 0x41 or timeout")
    else:
        print(f"\n  FOUND after {count} tests!")

if __name__ == "__main__":
    run()

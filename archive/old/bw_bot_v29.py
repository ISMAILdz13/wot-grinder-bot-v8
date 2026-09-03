#!/usr/bin/env python3
"""WoT Bot v29 — Protocol version 17.1.0 (5) from Kurzdor/wot.bigworld-placeholder

Found BigWorld.protocolVersion = "17.1.0 (5)" in a WoT mod placeholder.
This means major=17, minor=1, patch=0, subpatch=5.
struct(5, 0, 1, 17) = 5 + 0*256 + 1*65536 + 17*16777216 = 285278213

We NEVER tested major > 10 in any previous version!
Also: NO encrypted flag byte — BigWorld C++ code writes protocol version
directly followed by LogOnParams (no bool between them).
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

def build_login_body_no_enc_flag(protocol):
    """BigWorld C++ format: [protocol(4B)] [LogOnParams] — NO encrypted flag!"""
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
    return struct.pack("<I", protocol) + logon  # NO encrypted flag byte!

def build_login_body_with_enc_flag(protocol):
    """wg-toolkit-rs format: [protocol(4B)] [encrypted_flag(1B)] [LogOnParams]"""
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
    return struct.pack("<I", protocol) + struct.pack("<B", 0) + logon

def build_login_body_no_context(protocol):
    """BigWorld C++ LogOnParams: [flags][user][pwd][bf_key][nonce] — NO context!"""
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
    return struct.pack("<I", protocol) + logon

def parse_reply(data):
    if len(data) < 11: return None
    content = data[6:]
    if len(content) >= 5 and content[0] == 0xFF:
        length = struct.unpack_from("<I", content, 1)[0]
        rdata = content[5:5+length]
        if len(rdata) >= 5:
            status = rdata[4]
            rid = struct.unpack_from("<I", rdata, 0)[0]
            extra = rdata[5:] if len(rdata) > 5 else b""
            return (status, rid, extra)
    return None

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=3):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v29 — Protocol 17.1.0 (5) + no enc flag")
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
    
    # Key protocol version: 17.1.0 (5) = 285278213
    target = 285278213
    
    # Build a list of versions to test
    versions = []
    
    # The TARGET version and subpatch variations
    for sp in range(0, 10):
        val = sp + 0*256 + 1*65536 + 17*16777216
        versions.append((val, f"v17.1.0.{sp}"))
    
    # Nearby major versions
    for ma in range(15, 22):
        for mi in range(0, 5):
            for pa in range(0, 3):
                for sp in [0, 1, 5]:
                    val = sp + pa*256 + mi*65536 + ma*16777216
                    versions.append((val, f"v{ma}.{mi}.{pa}.{sp}"))
    
    # Also test with 2.x engine version but different approach
    for mi in [9, 10, 11, 12, 15, 20, 25, 30, 50, 100]:
        val = 0 + 0 + mi*65536 + 2*16777216
        versions.append((val, f"v2.{mi}.0.0"))
    
    # Sort and deduplicate
    seen = set()
    unique = []
    for v, d in versions:
        if v not in seen:
            seen.add(v)
            unique.append((v, d))
    unique.sort(key=lambda x: x[0])
    
    print(f"\n[2] Testing {len(unique)} versions with BOTH formats:")
    print(f"    Format A: [proto(4B)] [LogOnParams] (BigWorld C++ — no enc flag)")
    print(f"    Format B: [proto(4B)] [enc_flag(1B)] [LogOnParams] (wg-toolkit-rs)")
    print(f"    Key target: v17.1.0.5 = {target}")
    
    found = False
    count = 0
    for version, desc in unique:
        # Test BOTH formats: without enc flag (C++ format) and with enc flag (Rust format)
        for fmt_name, body_func in [("no-enc", build_login_body_no_enc_flag), 
                                     ("enc", build_login_body_with_enc_flag)]:
            body = body_func(version)
            elem = build_element_v16(0x00, rid, body)
            pkt = _pkt(elem, first_req=0)
            
            sock.sendto(pkt, (server, port))
            try:
                data, _ = sock.recvfrom(4096)
                result = parse_reply(data)
                if result:
                    status, reply_rid, extra = result
                    if status != 0x41:  # Not BadProtocolVersion = interesting!
                        msg = extra.decode('utf-8', errors='replace')[:100] if extra else ""
                        print(f"\n  [{rid}] *** {desc}={version} [{fmt_name}] → 0x{status:02X} rid=0x{reply_rid:08X} msg='{msg}' ***")
                        if status == 0x40:
                            print(f"      MALFORMED REQUEST — version accepted! Fix LogOnParams!")
                            found = True
                        elif status == 0x42:
                            print(f"      CHALLENGE! Need Cuckoo PoW!")
                            found = True
                        elif status == 1:
                            print(f"      SUCCESS!")
                            found = True
                        elif status == 0x43:
                            print(f"      BAD DIGEST!")
                        elif status == 0x47:
                            print(f"      INVALID USER!")
                        if found:
                            break
                rid += 1
            except socket.timeout:
                rid += 1
        
        count += 1
        if count % 50 == 0:
            print(f"    ... {count}/{len(unique)} ({desc}={version})")
        
        if found:
            break
    
    sock.close()
    if not found:
        print(f"\n  Tested {count} versions x 2 formats, all 0x41 or timeout")
    else:
        print(f"\n  FOUND after {count} tests!")

if __name__ == "__main__":
    run()

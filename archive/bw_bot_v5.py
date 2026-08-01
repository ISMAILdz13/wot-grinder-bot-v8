#!/usr/bin/env python3
"""WoT Bot v5 — Fixed C++ protocol format

Key fixes:
1. No `encrypted` flag (C++ protocol doesn't have it)
2. Packed int string lengths (1 byte for <255, 0xFF+3B for >=255)  
3. No `context` field (C++ LogOnParams: flags+username+password+encKey+nonce)
4. Try both C++ and Rust formats
5. Try with IS_RELIABLE flag
"""
import socket, struct, hashlib, os, time, sys

# Import core from v3 (everything before run function)
exec(open('/root/wot-grinder-bot-v8/bw_bot_v3.py' if os.path.exists('/root/wot-grinder-bot-v8/bw_bot_v3.py') else '/tmp/bw_bot_v3.py').read().split('def run(')[0])

def pack_int(n):
    """BigWorld packed int: 1 byte if <255, 0xFF + 3 bytes LE if >=255"""
    if n >= 255:
        return struct.pack("<B", 0xFF) + struct.pack("<I", n)[1:]  # 0xFF + 3 bytes LE
    return struct.pack("<B", n)

def pack_str(s):
    """Pack a string with packed_int length prefix"""
    b = s.encode() if isinstance(s, str) else s
    return pack_int(len(b)) + b

def login_packet_v5(rid, protocol=51, user="guest", pwd="", bf_key=None, nonce=0, fmt="cpp"):
    """Build login request element.
    
    fmt="cpp":  protocol(4B) + flags(1B) + username + password + encKey + nonce(4B)
    fmt="rust": protocol(4B) + encrypted(1B) + flags(1B) + username + password + bf_key + context + nonce(4B)  
    """
    if bf_key is None: bf_key = os.urandom(16)
    
    if fmt == "cpp":
        # C++ LogOnParams format (no encrypted flag, no context, packed_int strings)
        body = struct.pack("<I", protocol)  # LOGIN_VERSION
        body += struct.pack("<B", 0)  # flags (no digest)
        body += pack_str(user)  # username
        body += pack_str(pwd)  # password
        body += pack_str(bf_key)  # encryptionKey (Blowfish key as blob)
        body += struct.pack("<I", nonce)  # nonce
    else:
        # Rust format (with encrypted flag and context, but using packed_int strings)
        body = struct.pack("<I", protocol)
        body += struct.pack("<B", 0)  # encrypted = false
        body += struct.pack("<B", 0)  # flags (no digest)
        body += pack_str(user)
        body += pack_str(pwd)
        body += pack_str(bf_key)
        body += pack_str("guest")  # context
        body += struct.pack("<I", nonce)
    
    # Build request element: [element_id] [length(2B)] [request_id(4B)] [next(2B)] [body]
    rh = struct.pack("<IH", rid, 0)
    inner = rh + body
    content = struct.pack("<BH", 0x00, len(inner)) + inner
    
    # Build packet (off-channel, unreliable, has_requests)
    raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:], bf_key

def login_packet_reliable(rid, protocol=51, user="guest", pwd="", bf_key=None, nonce=0, seq=1, fmt="cpp"):
    """Build login request with IS_RELIABLE flag (like C++ RetryingRequest)"""
    if bf_key is None: bf_key = os.urandom(16)
    
    if fmt == "cpp":
        body = struct.pack("<I", protocol)
        body += struct.pack("<B", 0)
        body += pack_str(user)
        body += pack_str(pwd)
        body += pack_str(bf_key)
        body += struct.pack("<I", nonce)
    else:
        body = struct.pack("<I", protocol)
        body += struct.pack("<B", 0)  # encrypted
        body += struct.pack("<B", 0)  # flags
        body += pack_str(user)
        body += pack_str(pwd)
        body += pack_str(bf_key)
        body += pack_str("guest")  # context
        body += struct.pack("<I", nonce)
    
    rh = struct.pack("<IH", rid, 0)
    inner = rh + body
    content = struct.pack("<BH", 0x00, len(inner)) + inner
    
    # With IS_RELIABLE + HAS_SEQ_NUM
    flags = FLAGS['HAS_REQUESTS'] | FLAGS['IS_RELIABLE'] | FLAGS['HAS_SEQ_NUM']
    footer = struct.pack("<H", 2) + struct.pack("<I", seq)
    raw = struct.pack("<IH", 0, flags) + content + footer
    return struct.pack("<I", _prefix(raw)) + raw[4:], bf_key

def run_v5(server="login.p1.worldoftanks.eu", port=20016, timeout=8):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v5 — {server}:{port}")
    print(f"{'='*55}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1

    # [1] PING
    print(f"\n[1] PING (rid={rid})...")
    pkt = ping_packet(rid=rid, num=0)
    sock.sendto(pkt, (server, port))
    try:
        data, addr = sock.recvfrom(4096)
        print(f"    ✅ PING reply: {data.hex()} from {addr}")
        rid += 1
    except socket.timeout:
        print(f"    ❌ PING timeout")
        sock.close(); return

    # [2] Try different formats and protocol versions
    tests = [
        # (description, protocol, fmt, reliable)
        ("C++ fmt, proto=51, unreliable", 51, "cpp", False),
        ("C++ fmt, proto=51, reliable", 51, "cpp", True),
        ("C++ fmt, proto=52, unreliable", 52, "cpp", False),
        ("C++ fmt, proto=52, reliable", 52, "cpp", True),
        ("Rust fmt, proto=51, unreliable", 51, "rust", False),
        ("Rust fmt, proto=51, reliable", 51, "rust", True),
        ("C++ fmt, proto=60, reliable", 60, "cpp", True),
        ("C++ fmt, proto=100, reliable", 100, "cpp", True),
    ]
    
    for desc, proto, fmt, reliable in tests:
        print(f"\n[2] {desc} (rid={rid})...")
        if reliable:
            pkt, bf_key = login_packet_reliable(rid=rid, protocol=proto, fmt=fmt, seq=1)
        else:
            pkt, bf_key = login_packet_v5(rid=rid, protocol=proto, fmt=fmt)
        print(f"    → {pkt[:50].hex()}... ({len(pkt)}B)")
        sock.sendto(pkt, (server, port))
        try:
            data, addr = sock.recvfrom(4096)
            print(f"    ← RAW: {data.hex()} ({len(data)}B) from {addr}")
            r = parse_response(data)
            print(f"    Parsed: {r}")
            rid += 1
            if r.get("type") in ("CHALLENGE", "SUCCESS"):
                print(f"    🎯 Got {r['type']}!")
                break
        except socket.timeout:
            print(f"    ❌ Timeout")
            rid += 1

    sock.close()

if __name__ == "__main__":
    run_v5()

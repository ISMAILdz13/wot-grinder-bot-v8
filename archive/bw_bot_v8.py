#!/usr/bin/env python3
"""WoT Bot v8 — Probe ALL element IDs to find which ones the server responds to.

PING works at 0x02. Login might be at a different ID in WoT's modified interface.
Try element IDs 0x00-0x0F with a minimal Variable16 login payload.
Also try Fixed(0) probe-style messages for each ID.
"""
import socket, struct, os, sys, time

exec(open('/root/wot-grinder-bot-v8/bw_bot_v3.py' if os.path.exists('/root/wot-grinder-bot-v8/bw_bot_v3.py') else '/tmp/bw_bot_v3.py').read().split('def run(')[0])

def pack_int(n):
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[1:]
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_int(len(b)) + b

def probe_element(elem_id, rid, body_data, length_type="v16"):
    """Send a packet with a single element of given ID and body."""
    rh = struct.pack("<IH", rid, 0)
    inner = rh + body_data
    if length_type == "v16":
        content = struct.pack("<BH", elem_id, len(inner)) + inner
    elif length_type == "v32":
        content = struct.pack("<BI", elem_id, len(inner)) + inner
    elif length_type == "fixed":
        content = struct.pack("<B", elem_id) + body_data
    
    raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def run_v8(server="login.p1.worldoftanks.eu", port=20016, timeout=3):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v8 — Element ID Probe — {server}:{port}")
    print(f"{'='*55}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1

    # PING first
    print(f"\n[1] PING (rid={rid})...")
    sock.sendto(ping_packet(rid=rid, num=0), (server, port))
    try:
        data, addr = sock.recvfrom(4096)
        print(f"    ✅ PING OK")
        rid += 1
    except socket.timeout:
        print(f"    ❌ PING timeout — server unreachable")
        sock.close(); return

    # Minimal login body (C++ format, plain, no RSA)
    login_body = struct.pack("<I", 51)  # protocol
    login_body += struct.pack("<B", 0)  # flags
    login_body += pack_str("guest")    # username
    login_body += pack_str("")         # password
    login_body += pack_str(os.urandom(16))  # bf_key
    login_body += struct.pack("<I", 0) # nonce

    # Probe element IDs 0x00 through 0x0F
    print(f"\n[2] Probing element IDs 0x00-0x0F with Variable16 login payload...")
    for eid in range(0x10):
        if eid == 0x02:  # Skip PING (already works)
            continue
        pkt = probe_element(eid, rid, login_body, "v16")
        sock.sendto(pkt, (server, port))
        try:
            data, addr = sock.recvfrom(4096)
            print(f"    ID=0x{eid:02X} → ✅ RESPONSE! {data[:20].hex()}... ({len(data)}B)")
            print(f"      Full: {data.hex()}")
            rid += 1
        except socket.timeout:
            print(f"    ID=0x{eid:02X} → timeout")
            rid += 1

    # Also try Fixed format (like PING) for each ID
    print(f"\n[3] Probing element IDs with Fixed(1) format (like PING)...")
    for eid in range(0x10):
        if eid == 0x02:
            continue
        pkt = probe_element(eid, rid, struct.pack("<B", 0), "fixed")
        sock.sendto(pkt, (server, port))
        try:
            data, addr = sock.recvfrom(4096)
            print(f"    ID=0x{eid:02X} Fixed → ✅ RESPONSE! {data[:20].hex()}... ({len(data)}B)")
            rid += 1
        except socket.timeout:
            print(f"    ID=0x{eid:02X} Fixed → timeout")
            rid += 1

    # Try Variable32 too
    print(f"\n[4] Probing element IDs 0x00-0x05 with Variable32 login payload...")
    for eid in range(6):
        if eid == 0x02:
            continue
        pkt = probe_element(eid, rid, login_body, "v32")
        sock.sendto(pkt, (server, port))
        try:
            data, addr = sock.recvfrom(4096)
            print(f"    ID=0x{eid:02X} V32 → ✅ RESPONSE! {data[:20].hex()}... ({len(data)}B)")
            print(f"      Full: {data.hex()}")
            rid += 1
        except socket.timeout:
            print(f"    ID=0x{eid:02X} V32 → timeout")
            rid += 1

    sock.close()

if __name__ == "__main__":
    run_v8()

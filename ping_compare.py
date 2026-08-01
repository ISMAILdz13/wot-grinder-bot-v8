#!/usr/bin/env python3
"""Compare v3 and v40 PING packets byte-by-byte"""
import socket, struct, os, sys, time

# Import v3 functions
exec(open(os.path.expanduser("~/wot-grinder-bot-v8/bw_bot_v3.py")).read().split("def run(")[0])

# v3 PING
v3_pkt = ping_packet(rid=1)
print(f"v3 PING ({len(v3_pkt)}B): {v3_pkt.hex()}")

# v40 PING (rebuild from scratch)
FLAG_HAS_REQUESTS = 0x0001

def v40_prefix(raw):
    p0 = struct.unpack_from("<I", raw, 4)[0] if len(raw) >= 8 else 0
    p1 = struct.unpack_from("<I", raw, 8)[0] if len(raw) >= 12 else 0
    a = (p0 + p1) & 0xFFFFFFFF
    b = (a << 13) & 0xFFFFFFFF
    c = ((b ^ a) >> 17) & 0xFFFFFFFF
    return (c ^ b ^ a ^ ((c ^ b ^ a) << 5)) & 0xFFFFFFFF

def v40_build_request_fixed(elem_id, rid, body):
    return struct.pack("<B", elem_id) + struct.pack("<IH", rid, 0) + body

def v40_build_packet(content, first_req=None):
    flags = 0
    footer = b""
    if first_req is not None:
        flags |= FLAG_HAS_REQUESTS
        footer = struct.pack("<H", first_req + 2)
    raw = struct.pack("<IH", 0, flags) + content + footer
    return struct.pack("<I", v40_prefix(raw)) + raw[4:]

v40_elem = v40_build_request_fixed(0x02, 1, struct.pack("<B", 0))
v40_pkt = v40_build_packet(v40_elem, first_req=0)
print(f"v40 PING ({len(v40_pkt)}B): {v40_pkt.hex()}")

# Compare
if v3_pkt == v40_pkt:
    print("\n*** PACKETS IDENTICAL! ***")
else:
    print("\n*** PACKETS DIFFER! ***")
    for i, (a, b) in enumerate(zip(v3_pkt, v40_pkt)):
        if a != b:
            print(f"  Byte {i}: v3=0x{a:02x} v40=0x{b:02x}")

# Also test v3 _prefix vs v40_prefix with same input
raw = struct.pack("<IH", 0, 0x0001) + v40_elem + struct.pack("<H", 2)
v3_pre = _prefix(raw)
v40_pre = v40_prefix(raw)
print(f"\nv3 prefix:  0x{v3_pre:08x}")
print(f"v40 prefix: 0x{v40_pre:08x}")
if v3_pre == v40_pre:
    print("Prefixes MATCH!")
else:
    print("Prefixes DIFFER!")

# Send both to server
print("\n--- Sending to server ---")
for name, pkt in [("v3", v3_pkt), ("v40", v40_pkt)]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(pkt, ("login.p1.worldoftanks.eu", 20016))
        data, _ = sock.recvfrom(4096)
        print(f"{name} PING: OK ({len(data)}B) reply={data.hex()}")
    except socket.timeout:
        print(f"{name} PING: TIMEOUT")
    except Exception as e:
        print(f"{name} PING: {e}")
    sock.close()

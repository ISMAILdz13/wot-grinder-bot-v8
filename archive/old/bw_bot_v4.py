#!/usr/bin/env python3
"""WoT Bot v4 — Fixed protocol version + raw dump mode"""
import socket, struct, hashlib, os, time, sys

# Import everything from v3
exec(open('/tmp/bw_bot_v3.py'.replace('/tmp/bw_bot_v3.py', '/root/wot-grinder-bot-v8/bw_bot_v3.py') if os.path.exists('/root/wot-grinder-bot-v8/bw_bot_v3.py') else '/tmp/bw_bot_v3.py').read().split('def run(')[0])

def run_v4(server="login.p1.worldoftanks.eu", port=20016, timeout=10):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v4 — {server}:{port}")
    print(f"{'='*55}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1

    # [1] PING
    print(f"\n[1] PING (rid={rid})...")
    pkt = ping_packet(rid=rid, num=0)
    print(f"    → {pkt.hex()} ({len(pkt)}B)")
    sock.sendto(pkt, (server, port))
    try:
        data, addr = sock.recvfrom(4096)
        print(f"    ← RAW: {data.hex()} ({len(data)}B) from {addr}")
        r = parse_response(data)
        print(f"    Parsed: {r}")
        rid += 1
    except socket.timeout:
        print(f"    ❌ Timeout")
        sock.close(); return

    # [2] Try multiple protocol versions
    for proto_ver in [51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 324]:
        print(f"\n[2] LoginRequest (rid={rid}, protocol={proto_ver})...")
        pkt, bf_key = login_packet(rid=rid, protocol=proto_ver, user="guest", ctx="guest")
        print(f"    → {pkt[:40].hex()}... ({len(pkt)}B)")
        sock.sendto(pkt, (server, port))
        try:
            data, addr = sock.recvfrom(4096)
            print(f"    ← RAW: {data.hex()} ({len(data)}B) from {addr}")
            r = parse_response(data)
            print(f"    Parsed: {r}")
            if r.get("type") == "CHALLENGE":
                print(f"    🎯 Got challenge with protocol={proto_ver}!")
                rid += 1
                break
            elif r.get("type") == "ERROR":
                print(f"    Error: {r.get('error','?')}: {r.get('error_msg','?')}")
                rid += 1
                if "protocol" in r.get('error_msg','').lower():
                    print(f"    → Server told us the version range! Keep this info.")
                continue
            elif r.get("type") == "SUCCESS":
                print(f"    🎉 SUCCESS with protocol={proto_ver}!")
                rid += 1
                break
            else:
                print(f"    ? Unknown response type")
                rid += 1
                break
        except socket.timeout:
            print(f"    ❌ Timeout (protocol={proto_ver})")
            rid += 1
            continue

    sock.close()

if __name__ == "__main__":
    for s, p in [("login.p1.worldoftanks.eu",20016),("login.p2.worldoftanks.eu",20016),("login.p3.worldoftanks.eu",20016)]:
        run_v4(s, p)
        print()

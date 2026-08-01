#!/usr/bin/env python3
"""Quick network diagnostic — can we reach WoT servers at all?"""
import socket, struct, time

# Test 1: DNS resolution
for host in ["login.p1.worldoftanks.eu", "login.p2.worldoftanks.eu", "login.p3.worldoftanks.eu"]:
    try:
        ip = socket.gethostbyname(host)
        print(f"DNS: {host} -> {ip}")
    except:
        print(f"DNS: {host} -> FAILED")

# Test 2: TCP connect
for host, port in [("login.p1.worldoftanks.eu", 20016), ("login.p2.worldoftanks.eu", 20018), ("api.worldoftanks.eu", 443)]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        print(f"TCP: {host}:{port} -> CONNECTED")
        s.close()
    except socket.timeout:
        print(f"TCP: {host}:{port} -> TIMEOUT")
    except Exception as e:
        print(f"TCP: {host}:{port} -> ERROR: {e}")

# Test 3: UDP PING using v3 code
import os, sys
sys.path.insert(0, os.path.expanduser("~/wot-grinder-bot-v8"))
exec(open(os.path.expanduser("~/wot-grinder-bot-v8/bw_bot_v3.py")).read().split("def run(")[0])

for host, port in [("login.p1.worldoftanks.eu", 20016), ("login.p2.worldoftanks.eu", 20018)]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        pkt = ping_packet(rid=1)
        sock.sendto(pkt, (host, port))
        t0 = time.time()
        data, _ = sock.recvfrom(4096)
        elapsed = time.time() - t0
        print(f"UDP PING: {host}:{port} -> OK ({len(data)}B in {elapsed:.2f}s)")
        sock.close()
    except socket.timeout:
        print(f"UDP PING: {host}:{port} -> TIMEOUT (5s)")
    except Exception as e:
        print(f"UDP PING: {host}:{port} -> ERROR: {e}")
    finally:
        try: sock.close()
        except: pass

# Test 4: Check if v35 still works (uses exec from v3)
print("\nTesting v35 PING...")
try:
    exec(open(os.path.expanduser("~/wot-grinder-bot-v8/bw_bot_v35.py")).read().split("def run(")[0])
    # v35 uses imported ping_packet from v3
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(ping_packet(rid=1), ("login.p1.worldoftanks.eu", 20016))
    data, _ = sock.recvfrom(4096)
    print(f"v35 PING: OK ({len(data)}B)")
    sock.close()
except socket.timeout:
    print(f"v35 PING: TIMEOUT")
except Exception as e:
    print(f"v35 PING: {e}")

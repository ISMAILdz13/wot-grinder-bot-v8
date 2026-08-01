#!/usr/bin/env python3
"""Fast TCP-only test for WoT game servers. No UDP waste."""
import socket, struct, sys

servers = [
    "login.p1.worldoftanks.eu",
    "login.p2.worldoftanks.eu",
    "login.p3.worldoftanks.eu",
    "login.p5.worldoftanks.eu",
]
ports = [5222, 5223, 443, 20016, 20018]

# Correct BigWorld PING: prefix(4B) + flags(2B=0) + element 0x02 + num 0x00
def build_ping():
    buf = bytearray(14)
    buf[4:6] = struct.pack("<H", 0)  # flags=0
    buf[6] = 0x02  # PING element
    buf[7] = 0x00  # num=0
    p0 = struct.unpack_from("<I", buf, 4)[0]
    p1 = struct.unpack_from("<I", buf, 8)[0]
    a = (p0 + p1) & 0xFFFFFFFF
    b = (a << 13) & 0xFFFFFFFF
    c = ((b ^ a) >> 17) & 0xFFFFFFFF
    d = (c ^ b ^ a ^ ((c ^ b ^ a) << 5)) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 0, d)
    return bytes(buf[:8])

ping = build_ping()
print(f"=== TCP-ONLY WoT Server Test (VPN active) ===")
print(f"PING packet: {ping.hex()}\n")

found = False
for server in servers:
    for port in ports:
        try:
            print(f"  TCP {server}:{port}...", end=" ", flush=True)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server, port))
            print(f"CONNECTED!", end=" ")
            # Send BigWorld PING
            sock.sendall(ping)
            sock.settimeout(5)
            try:
                data = sock.recv(4096)
                if data:
                    print(f"✓ RESPONSE {len(data)} bytes: {data[:20].hex()}")
                    found = True
                else:
                    print("✗ no data (closed)")
            except socket.timeout:
                print("✗ timeout on recv")
            except Exception as e:
                print(f"✗ recv: {str(e)[:30]}")
            sock.close()
        except socket.timeout:
            print("✗ timeout")
        except ConnectionRefusedError:
            print("✗ refused")
        except Exception as e:
            print(f"✗ {str(e)[:40]}")

# Also test: can we reach wargaming.net now (was blocked without VPN)?
print("\n=== VPN Verification ===")
for host in ["wargaming.net", "login.p1.worldoftanks.eu"]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, 443))
        print(f"  {host}:443 -> CONNECTED ✓")
        sock.close()
    except:
        print(f"  {host}:443 -> BLOCKED ✗")

print(f"\n{'✅ Found working connection!' if found else '❌ No game server responded on TCP'}")

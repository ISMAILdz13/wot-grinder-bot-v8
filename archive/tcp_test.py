#!/usr/bin/env python3
"""Quick TCP connectivity test for WoT game servers."""
import socket, ssl, struct, sys

servers = [
    "login.p1.worldoftanks.eu",
    "login.p2.worldoftanks.eu", 
    "login.p3.worldoftanks.eu",
    "login.p5.worldoftanks.eu",
]
ports = [5222, 5223, 443, 20016, 20018, 80]

# BigWorld PING packet (correct format)
def build_ping():
    body = bytes([0x02, 0x00])  # PING element ID=0x02, num=0
    buf = bytearray(14)
    struct.pack_into("<H", buf, 4, 0)  # flags=0
    buf[6:8] = body
    # Compute prefix
    p0 = struct.unpack_from("<I", buf, 4)[0]
    p1 = struct.unpack_from("<I", buf, 8)[0]
    a = (p0 + p1) & 0xFFFFFFFF
    b = (a << 13) & 0xFFFFFFFF
    c = ((b ^ a) >> 17) & 0xFFFFFFFF
    d = (c ^ b ^ a ^ ((c ^ b ^ a) << 5)) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 0, d)
    return bytes(buf[:8])

ping = build_ping()
print(f"BigWorld PING: {ping.hex()} ({len(ping)} bytes)\n")

for server in servers:
    for port in ports:
        try:
            print(f"  TCP {server}:{port}...", end=" ", flush=True)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server, port))
            
            use_tls = (port == 443)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=server)
            
            # Send PING
            sock.sendall(ping)
            
            # Try to read response
            sock.settimeout(5)
            try:
                data = sock.recv(4096)
                if data:
                    print(f"✓ RESPONSE! {len(data)} bytes: {data[:20].hex()}")
                else:
                    print("✗ connected, no response (closed)")
            except socket.timeout:
                print("✗ connected, timeout on recv")
            except Exception as e:
                print(f"✗ connected, recv error: {str(e)[:40]}")
        except socket.timeout:
            print("✗ timeout")
        except ConnectionRefusedError:
            print("✗ refused")
        except Exception as e:
            print(f"✗ {str(e)[:50]}")
        finally:
            try: sock.close()
            except: pass

print("\nDone. If any port shows ✓ RESPONSE, that's our connection path.")

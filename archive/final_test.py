#!/usr/bin/env python3
"""
Final connectivity test — tries every combination:
1. TCP with TLS + correct PING (prefix=1)
2. TCP raw + correct PING (prefix=1) 
3. TCP with TLS + LoginRequest
4. TCP raw + LoginRequest with length prefix
5. UDP with correct PING (prefix=1)
"""
import socket, ssl, struct, time

SERVER = "login.p1.worldoftanks.eu"
PORTS = [20016, 20018, 443, 5222]

# Correct PING with prefix=1 (NOT xorshift)
def build_ping_v2():
    return bytes([0x01, 0x00, 0x00, 0x00,  # prefix = 1
                  0x00, 0x00,                # flags = 0
                  0x02, 0x00])               # element=PING, num=0

# LoginRequest with prefix=1
def build_login_v2():
    body = bytearray()
    body += bytes([0x00])  # element ID = LoginRequest
    body += struct.pack("<I", 0x0144)  # protocol version
    body += bytes([0x00, 0x00])  # not encrypted, flags
    uname = b"guest"
    body += struct.pack("<H", len(uname)) + uname
    body += struct.pack("<H", 0)  # empty password
    body += struct.pack("<H", 0)  # empty blowfish key
    ctx = b"guest"
    body += struct.pack("<H", len(ctx)) + ctx
    body += struct.pack("<I", 0)  # nonce
    
    pkt = bytearray(6 + len(body))
    pkt[0:4] = struct.pack("<I", 1)  # prefix=1
    pkt[4:6] = struct.pack("<H", 0)  # flags=0
    pkt[6:6+len(body)] = body
    return bytes(pkt)

# LoginRequest with 4-byte length prefix (for TCP streaming)
def build_login_with_length():
    login = build_login_v2()
    length = struct.pack(">I", len(login))  # big-endian length
    return length + login

ping = build_ping_v2()
login = build_login_v2()
login_len = build_login_with_length()

print(f"=== Final WoT Connectivity Test ===")
print(f"  PING (prefix=1): {ping.hex()}")
print(f"  LOGIN (prefix=1): {login[:20].hex()}...")
print(f"  LOGIN+LEN: {login_len[:24].hex()}...\n")

def try_tcp(host, port, use_tls, data, label):
    try:
        print(f"  {label}...", end=" ", flush=True)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        
        sock.sendall(data)
        time.sleep(0.5)
        resp = sock.recv(4096)
        if resp:
            print(f"✓ RESPONSE {len(resp)} bytes: {resp[:30].hex()}")
            return True
        else:
            print("✗ closed")
        sock.close()
    except socket.timeout:
        print("✗ timeout")
    except ssl.SSLError as e:
        print(f"✗ TLS: {str(e)[:30]}")
    except ConnectionRefusedError:
        print("✗ refused")
    except Exception as e:
        print(f"✗ {str(e)[:40]}")
    return False

def try_udp(host, port, data, label):
    try:
        print(f"  {label}...", end=" ", flush=True)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(data, (host, port))
        resp, addr = sock.recvfrom(4096)
        print(f"✓ RESPONSE {len(resp)} bytes: {resp[:30].hex()}")
        sock.close()
        return True
    except socket.timeout:
        print("✗ timeout")
    except Exception as e:
        print(f"✗ {str(e)[:40]}")
    return False

found = False

# Test 1: UDP with correct PING (prefix=1)
print("--- UDP with correct PING (prefix=1) ---")
for port in [20016, 20018]:
    if try_udp(SERVER, port, ping, f"UDP {SERVER}:{port} PING"):
        found = True

# Test 2: UDP with LoginRequest (prefix=1)
print("\n--- UDP with LoginRequest (prefix=1) ---")
for port in [20016, 20018]:
    if try_udp(SERVER, port, login, f"UDP {SERVER}:{port} LOGIN"):
        found = True

# Test 3: TCP with TLS + PING
print("\n--- TCP with TLS + PING (prefix=1) ---")
for port in [20016, 443]:
    if try_tcp(SERVER, port, True, ping, f"TCP+TLS {SERVER}:{port} PING"):
        found = True

# Test 4: TCP raw + PING (prefix=1)
print("\n--- TCP raw + PING (prefix=1) ---")
for port in [20016, 20018, 5222]:
    if try_tcp(SERVER, port, False, ping, f"TCP {SERVER}:{port} PING"):
        found = True

# Test 5: TCP raw + LoginRequest with length prefix
print("\n--- TCP raw + LoginRequest + length prefix ---")
for port in [20016, 20018]:
    if try_tcp(SERVER, port, False, login_len, f"TCP {SERVER}:{port} LOGIN+LEN"):
        found = True

# Test 6: TCP with TLS + LoginRequest
print("\n--- TCP with TLS + LoginRequest ---")
for port in [20016, 443]:
    if try_tcp(SERVER, port, True, login, f"TCP+TLS {SERVER}:{port} LOGIN"):
        found = True

# Test 7: TCP 5222 with TLS + PING
print("\n--- TCP 5222 with TLS + PING ---")
if try_tcp(SERVER, 5222, True, ping, f"TCP+TLS {SERVER}:5222 PING"):
    found = True

print(f"\n{'='*50}")
print(f"{'✅ FOUND WORKING CONNECTION!' if found else '❌ No response from any combination'}")
print(f"{'='*50}")

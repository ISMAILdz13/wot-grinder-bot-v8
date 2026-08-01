#!/usr/bin/env python3
"""
Smart WoT connectivity test — tries the RIGHT protocol for each port.
- UDP: BigWorld LoginRequest (correct first packet, not PING)
- UDP: BigWorld PING (simple probe)
- TCP 5222: XMPP stream handshake (XML)
- TCP 443: HTTP GET (web probe)
"""
import socket, struct, sys, time

SERVERS = ["login.p1.worldoftanks.eu", "login.p2.worldoftanks.eu"]

# ── BigWorld PING packet ──
def build_ping():
    buf = bytearray(14)
    buf[4:6] = struct.pack("<H", 0)
    buf[6] = 0x02  # PING element
    buf[7] = 0x00
    p0 = struct.unpack_from("<I", buf, 4)[0]
    p1 = struct.unpack_from("<I", buf, 8)[0]
    a = (p0 + p1) & 0xFFFFFFFF
    b = (a << 13) & 0xFFFFFFFF
    c = ((b ^ a) >> 17) & 0xFFFFFFFF
    d = (c ^ b ^ a ^ ((c ^ b ^ a) << 5)) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 0, d)
    return bytes(buf[:8])

# ── BigWorld LoginRequest packet ──
def build_login_request():
    """Build a BigWorld LoginRequest (element ID=0x00)."""
    body = bytearray()
    body += struct.pack("<I", 0x0144)   # protocol version
    body += bytes([0x00])               # not encrypted
    body += bytes([0x00])               # flags
    uname = b"guest"
    body += struct.pack("<H", len(uname)) + uname
    pword = b""
    body += struct.pack("<H", len(pword)) + pword
    bf_key = bytes(56)  # empty blowfish key
    body += struct.pack("<H", len(bf_key)) + bf_key
    ctx = b"guest"
    body += struct.pack("<H", len(ctx)) + ctx
    body += struct.pack("<I", 0)  # nonce
    
    full_body = bytes([0x00]) + bytes(body)  # element ID = 0x00 (LoginRequest)
    
    # Build packet with prefix
    buf = bytearray(6 + len(full_body) + 8)
    struct.pack_into("<H", buf, 4, 0)  # flags
    buf[6:6+len(full_body)] = full_body
    p0 = struct.unpack_from("<I", buf, 4)[0]
    p1 = struct.unpack_from("<I", buf, 8)[0]
    a = (p0 + p1) & 0xFFFFFFFF
    b = (a << 13) & 0xFFFFFFFF
    c = ((b ^ a) >> 17) & 0xFFFFFFFF
    d = (c ^ b ^ a ^ ((c ^ b ^ a) << 5)) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 0, d)
    return bytes(buf[:6+len(full_body)])

# ── XMPP stream header ──
XMPP_HEADER = (
    b'<?xml version="1.0"?>'
    b'<stream:stream xmlns:stream="http://etherx.jabber.org/streams" '
    b'xmlns="jabber:client" to="wot" version="1.0">'
)

ping = build_ping()
login = build_login_request()

print("=== Smart WoT Connectivity Test (VPN active) ===\n")

# ── Test 1: UDP with PING ──
print("--- UDP with PING ---")
for server in SERVERS[:1]:  # just p1 to save time
    for port in [20016, 20018]:
        try:
            print(f"  UDP {server}:{port} PING...", end=" ", flush=True)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(ping, (server, port))
            data, addr = sock.recvfrom(4096)
            print(f"✓ RESPONSE {len(data)} bytes: {data[:20].hex()}")
            sock.close()
        except socket.timeout:
            print("✗ timeout")
            sock.close()
        except Exception as e:
            print(f"✗ {str(e)[:40]}")

# ── Test 2: UDP with LoginRequest ──
print("\n--- UDP with LoginRequest ---")
for server in SERVERS[:1]:
    for port in [20016, 20018]:
        try:
            print(f"  UDP {server}:{port} LOGIN...", end=" ", flush=True)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(login, (server, port))
            data, addr = sock.recvfrom(4096)
            print(f"✓ RESPONSE {len(data)} bytes: {data[:30].hex()}")
            sock.close()
        except socket.timeout:
            print("✗ timeout")
            sock.close()
        except Exception as e:
            print(f"✗ {str(e)[:40]}")

# ── Test 3: TCP 5222 with XMPP ──
print("\n--- TCP 5222 with XMPP handshake ---")
for server in SERVERS[:1]:
    try:
        print(f"  TCP {server}:5222 XMPP...", end=" ", flush=True)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((server, 5222))
        sock.sendall(XMPP_HEADER)
        time.sleep(1)
        data = sock.recv(4096)
        if data:
            txt = data.decode('utf-8', errors='replace')[:200]
            print(f"✓ RESPONSE {len(data)} bytes:")
            print(f"    {txt}")
        else:
            print("✗ no data")
        sock.close()
    except socket.timeout:
        print("✗ timeout")
    except Exception as e:
        print(f"✗ {str(e)[:40]}")

# ── Test 4: TCP 443 with HTTP ──
print("\n--- TCP 443 with HTTP ---")
for server in SERVERS[:1]:
    try:
        print(f"  TCP {server}:443 HTTP...", end=" ", flush=True)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((server, 443))
        sock.sendall(b"GET / HTTP/1.1\r\nHost: " + server.encode() + b"\r\n\r\n")
        time.sleep(1)
        data = sock.recv(4096)
        if data:
            txt = data.decode('utf-8', errors='replace')[:200]
            print(f"✓ RESPONSE {len(data)} bytes:")
            print(f"    {txt}")
        else:
            print("✗ no data")
        sock.close()
    except socket.timeout:
        print("✗ timeout")
    except Exception as e:
        print(f"✗ {str(e)[:40]}")

# ── Test 5: TCP 20016 with LoginRequest ──
print("\n--- TCP 20016 with BigWorld LoginRequest ---")
for server in SERVERS[:1]:
    try:
        print(f"  TCP {server}:20016 LOGIN...", end=" ", flush=True)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((server, 20016))
        sock.sendall(login)
        time.sleep(1)
        data = sock.recv(4096)
        if data:
            print(f"✓ RESPONSE {len(data)} bytes: {data[:30].hex()}")
        else:
            print("✗ no data")
        sock.close()
    except socket.timeout:
        print("✗ timeout")
    except Exception as e:
        print(f"✗ {str(e)[:40]}")

print("\n=== Done ===")

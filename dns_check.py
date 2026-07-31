#!/usr/bin/env python3
"""Check DNS resolution and basic connectivity for WoT servers."""
import socket, struct

servers = [
    "login.p1.worldoftanks.eu",
    "login.p2.worldoftanks.eu",
    "login.p3.worldoftanks.eu",
    "login.p5.worldoftanks.eu",
    "api.worldoftanks.eu",
    "eu.wargaming.net",
    "wargaming.net",
]

print("=== DNS Resolution ===\n")
for host in servers:
    try:
        ips = socket.getaddrinfo(host, 443, socket.AF_INET)
        ip = ips[0][4][0]
        print(f"  {host} -> {ip}")
    except Exception as e:
        print(f"  {host} -> FAILED: {e}")

print("\n=== Quick TCP 443 test (5s timeout) ===\n")
for host in ["api.worldoftanks.eu", "wargaming.net", "login.p1.worldoftanks.eu"]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, 443))
        print(f"  {host}:443 -> CONNECTED ✓")
        sock.close()
    except socket.timeout:
        print(f"  {host}:443 -> TIMEOUT ✗")
    except Exception as e:
        print(f"  {host}:443 -> {str(e)[:40]}")

print("\n=== Try connecting directly to resolved IP ===\n")
# If login.p1 resolves, try connecting to its IP directly
for host in ["login.p1.worldoftanks.eu"]:
    try:
        ips = socket.getaddrinfo(host, None, socket.AF_INET)
        ip = ips[0][4][0]
        print(f"  {host} resolved to {ip}")
        for port in [443, 80, 20016]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, port))
                print(f"    {ip}:{port} -> CONNECTED ✓")
                sock.close()
            except socket.timeout:
                print(f"    {ip}:{port} -> TIMEOUT ✗")
            except Exception as e:
                print(f"    {ip}:{port} -> {str(e)[:30]}")
    except:
        print(f"  {host} -> DNS FAILED")

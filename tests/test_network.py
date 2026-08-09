#!/usr/bin/env python3
"""Comprehensive UDP test for WoT — checks if UDP works at all, then tries WoT."""
import socket, struct, os, time

def test_udp_dns():
    """Test if outbound UDP works at all (DNS query to 8.8.8.8)."""
    print("[0] Testing UDP connectivity (DNS to 8.8.8.8:53)...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        # Simple DNS query for google.com
        query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        query += b'\x06google\x03com\x00\x00\x01\x00\x01'
        sock.sendto(query, ("8.8.8.8", 53))
        data, addr = sock.recvfrom(4096)
        print(f"  ✅ UDP works! DNS reply: {len(data)}B from {addr}")
        sock.close()
        return True
    except Exception as e:
        print(f"  ❌ UDP test failed: {e}")
        print("  → This environment blocks outbound UDP. Need a VPS or VPN with UDP.")
        return False

def test_wot_servers():
    """Test multiple WoT login servers and ports."""
    servers = [
        ("login.p1.worldoftanks.eu", 20016),
        ("login.p2.worldoftanks.eu", 20016),
        ("login.p3.worldoftanks.eu", 20016),
        ("login.p1.worldoftanks.eu", 20014),
        ("login.p2.worldoftanks.eu", 20014),
    ]
    
    for host, port in servers:
        try:
            addr = socket.gethostbyname(host)
        except:
            print(f"  ❌ {host} — DNS failed")
            continue
        
        print(f"  Testing {host} ({addr}):{port}...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # Send a simple packet (just 4 bytes of zeros)
            sock.sendto(b'\x00' * 10, (host, port))
            try:
                data, addr = sock.recvfrom(4096)
                print(f"    ✅ Got reply: {len(data)}B from {addr}")
                print(f"    Hex: {data[:20].hex()}")
                return host, port
            except socket.timeout:
                print(f"    ❌ No reply (timeout)")
        except Exception as e:
            print(f"    ❌ Error: {e}")
        finally:
            sock.close()
    return None

def test_tcp_servers():
    """Test TCP connectivity to WoT servers."""
    print("\n[2b] Testing TCP connectivity...")
    for host, port in [("login.p1.worldoftanks.eu", 443), ("login.p1.worldoftanks.eu", 5222)]:
        try:
            addr = socket.gethostbyname(host)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            print(f"  ✅ TCP {host}:{port} connected!")
            sock.close()
        except Exception as e:
            print(f"  ❌ TCP {host}:{port}: {e}")

if __name__ == "__main__":
    print("=== WoT Network Test ===\n")
    
    udp_works = test_udp_dns()
    
    print(f"\n[1] Testing WoT servers (UDP {'available' if udp_works else 'blocked'})...")
    result = test_wot_servers() if udp_works else None
    
    if not result:
        test_tcp_servers()
        
        print("\n=== Summary ===")
        if not udp_works:
            print("❌ UDP is blocked on this network/environment.")
            print("   Options:")
            print("   1. GitHub Codespaces (may have different network rules)")
            print("   2. Oracle Cloud free tier (full VPS, UDP allowed)")
            print("   3. A small VPS provider (VPSServer, Contabo, etc.)")
            print("   4. A VPN that supports UDP forwarding (not Stealth/TCP mode)")
        elif not result:
            print("❌ UDP works but WoT servers not responding.")
            print("   WoT may be blocking this IP range (cloud provider).")
            print("   Try: GitHub Codespaces or a residential VPN.")
        else:
            print(f"✅ Found working server: {result[0]}:{result[1]}")
            print("   Now run: python3 test_wot_login.py")

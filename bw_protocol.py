#!/usr/bin/env python3
"""
BigWorld Protocol — Correct PING packet implementation
Based on wg-toolkit-rs source code analysis.

Packet format:
  [4B prefix (xorshift, LE)] [2B flags (LE)] [content...] [footer...]

Flags (u16 LE):
  0x0001 = HAS_REQUESTS    0x0002 = HAS_PIGGYBACKS  0x0004 = HAS_ACKS
  0x0008 = ON_CHANNEL      0x0010 = IS_RELIABLE      0x0020 = IS_FRAGMENT
  0x0040 = HAS_SEQUENCE_NUM 0x0080 = INDEXED_CHANNEL 0x0100 = HAS_CHECKSUM
  0x0200 = CREATE_CHANNEL   0x0400 = HAS_CUMULATIVE_ACK 0x1000 = UNK_1000

Footer fields (written after content, in this order):
  1. sequence_range (8B) — if IS_FRAGMENT
  2. first_request_offset (2B LE) — if HAS_REQUESTS (value = actual_offset + 2)
  3. last_reliable_seq (4B LE) — if UNK_1000
  4. sequence_number (4B LE) — if IS_RELIABLE or IS_FRAGMENT
  5. single_acks (4B each, reversed) + count (1B) — if HAS_ACKS
  6. cumulative_ack (4B LE) — if HAS_CUMULATIVE_ACK
  7. indexed_channel (8B: version+index) — if INDEXED_CHANNEL
  8. piggyback packets — if HAS_PIGGYBACKS
  9. checksum (4B LE) — if HAS_CHECKSUM

For off-channel PING:
  - Flags = 0x0001 (HAS_REQUESTS only)
  - No sequence number (not reliable, not fragment)
  - No acks, no channel, no checksum
  - Footer = just first_request_offset (2B LE)
"""

import socket
import struct
import sys
import time

def compute_prefix(packet: bytes, offset: int = 0) -> int:
    """Compute BigWorld packet prefix (xorshift checksum)."""
    # p0 = u32 LE at offset 4 (flags + first 2 bytes of content)
    # p1 = u32 LE at offset 8 (next 4 bytes of content)
    if len(packet) >= 12:
        p0 = struct.unpack_from("<I", packet, 4)[0]
        p1 = struct.unpack_from("<I", packet, 8)[0]
    elif len(packet) >= 8:
        p0 = struct.unpack_from("<I", packet, 4)[0]
        p1 = 0
    else:
        p0 = 0
        p1 = 0
    
    a = (offset + p0 + p1) & 0xFFFFFFFF
    b = (a << 13) & 0xFFFFFFFF
    c = ((b ^ a) >> 17) & 0xFFFFFFFF
    d = (c ^ b ^ a ^ ((c ^ b ^ a) << 5)) & 0xFFFFFFFF
    return d

def build_ping_packet(request_id: int = 1, ping_num: int = 0) -> bytes:
    """
    Build a proper BigWorld PING request packet.
    
    Content layout:
      [element_id=0x02 (1B)] [request_id (4B LE)] [next_request_offset (2B LE=0)] [num (1B)]
    
    Footer layout:
      [first_request_offset (2B LE)] = (0 + 2) = 2  (request starts at content offset 0)
    
    Flags: 0x0001 (HAS_REQUESTS)
    """
    # Build content
    element_id = 0x02  # PING
    content = struct.pack("<B", element_id)          # 1B: element ID
    content += struct.pack("<I", request_id)          # 4B: request ID (LE)
    content += struct.pack("<H", 0)                   # 2B: next_request_offset = 0 (no next)
    content += struct.pack("<B", ping_num)            # 1B: ping num
    
    # Build footer
    first_request_offset = 0  # request starts at content offset 0
    footer = struct.pack("<H", first_request_offset + 2)  # stored = actual + 2
    
    # Build flags
    flags = 0x0001  # HAS_REQUESTS only
    
    # Assemble packet (prefix placeholder + flags + content + footer)
    prefix_placeholder = struct.pack("<I", 0)  # will be computed
    packet = prefix_placeholder + struct.pack("<H", flags) + content + footer
    
    # Compute prefix
    prefix = compute_prefix(packet, offset=0)
    packet = struct.pack("<I", prefix) + packet[4:]
    
    return packet

def build_login_request_packet(request_id: int = 2, protocol: int = 0x0144,
                                username: str = "guest", password: str = "",
                                blowfish_key: bytes = None, context: str = "guest",
                                nonce: int = 0) -> bytes:
    """
    Build a BigWorld LoginRequest packet.
    
    LoginRequest element:
      ID = 0x00, Length = Variable16 (2B length)
      Data: protocol(4B) + encrypted(bool 1B=false) + flags(1B) + 
            username(string_var) + password(string_var) + 
            blowfish_key(blob_var) + context(string_var) + nonce(4B)
    """
    if blowfish_key is None:
        blowfish_key = bytes(56)  # 56 zero bytes
    
    # Build login request body (after element ID and length)
    body = struct.pack("<I", protocol)       # 4B: protocol version
    body += struct.pack("<B", 0)              # 1B: not encrypted (false)
    body += struct.pack("<B", 0)              # 1B: flags (no digest)
    
    # string_variable: u16 LE length + data
    uname = username.encode()
    body += struct.pack("<H", len(uname)) + uname
    pword = password.encode()
    body += struct.pack("<H", len(pword)) + pword
    
    # blob_variable: u16 LE length + data
    body += struct.pack("<H", len(blowfish_key)) + blowfish_key
    
    ctx = context.encode()
    body += struct.pack("<H", len(ctx)) + ctx
    
    body += struct.pack("<I", nonce)          # 4B: nonce
    
    # Build content: element_id + length(u16 LE) + request_header + body
    element_id = 0x00  # LOGIN_REQUEST
    content = struct.pack("<B", element_id)
    # Variable16 length: 2 bytes for the length of (request_header + body)
    request_header = struct.pack("<I", request_id) + struct.pack("<H", 0)  # request_id + next=0
    inner_data = request_header + body
    content += struct.pack("<H", len(inner_data))  # Variable16 length
    content += inner_data
    
    # Build footer
    first_request_offset = 0
    footer = struct.pack("<H", first_request_offset + 2)
    
    flags = 0x0001  # HAS_REQUESTS
    
    prefix_placeholder = struct.pack("<I", 0)
    packet = prefix_placeholder + struct.pack("<H", flags) + content + footer
    
    prefix = compute_prefix(packet, offset=0)
    packet = struct.pack("<I", prefix) + packet[4:]
    
    return packet

def test_ping(server: str, port: int, timeout: float = 5.0):
    """Send a PING to a WoT server and wait for response."""
    print(f"\n{'='*60}")
    print(f"  PING test: {server}:{port}")
    print(f"{'='*60}")
    
    packet = build_ping_packet(request_id=1, ping_num=0)
    print(f"  Packet: {packet.hex()} ({len(packet)} bytes)")
    print(f"  Prefix:  {struct.unpack_from('<I', packet, 0)[0]:08x}")
    print(f"  Flags:   {struct.unpack_from('<H', packet, 4)[0]:04x}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        print(f"  Sent {len(packet)} bytes")
        
        data, addr = sock.recvfrom(4096)
        print(f"  ✅ RESPONSE from {addr}: {len(data)} bytes")
        print(f"  Data: {data[:32].hex()}")
        
        # Try to decode the response
        if len(data) >= 6:
            resp_prefix = struct.unpack_from("<I", data, 0)[0]
            resp_flags = struct.unpack_from("<H", data, 4)[0]
            print(f"  Response prefix: {resp_prefix:08x}")
            print(f"  Response flags:  {resp_flags:04x}")
        
        sock.close()
        return True
    except socket.timeout:
        print(f"  ❌ Timeout ({timeout}s)")
        sock.close()
        return False
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def test_login_request(server: str, port: int, timeout: float = 5.0):
    """Send a LoginRequest to a WoT server and wait for response."""
    print(f"\n{'='*60}")
    print(f"  LOGIN test: {server}:{port}")
    print(f"{'='*60}")
    
    packet = build_login_request_packet(
        request_id=2,
        protocol=0x0144,
        username="guest",
        password="",
        blowfish_key=bytes(56),
        context="guest",
        nonce=0
    )
    print(f"  Packet: {packet[:32].hex()}... ({len(packet)} bytes)")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        print(f"  Sent {len(packet)} bytes")
        
        data, addr = sock.recvfrom(4096)
        print(f"  ✅ RESPONSE from {addr}: {len(data)} bytes")
        print(f"  Data: {data[:48].hex()}")
        sock.close()
        return True
    except socket.timeout:
        print(f"  ❌ Timeout ({timeout}s)")
        sock.close()
        return False
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

if __name__ == "__main__":
    servers = [
        ("login.p1.worldoftanks.eu", 20016),
        ("login.p1.worldoftanks.eu", 20018),
        ("login.p2.worldoftanks.eu", 20016),
        ("login.p3.worldoftanks.eu", 20016),
        ("login.p5.worldoftanks.eu", 20016),
    ]
    
    print("BigWorld Protocol — Correct PING Implementation")
    print("Based on wg-toolkit-rs source code analysis")
    print(f"Time: {time.strftime('%H:%M:%S')}")
    
    # Verify packet format
    pkt = build_ping_packet()
    print(f"\nSample PING packet: {pkt.hex()} ({len(pkt)} bytes)")
    
    any_success = False
    for server, port in servers:
        if test_ping(server, port, timeout=3):
            any_success = True
            test_login_request(server, port, timeout=5)
            break
    
    if not any_success:
        print(f"\n{'='*60}")
        print("  No responses from any server.")
        print("  This means UDP is blocked on this network.")
        print("  Try on a VPS with full UDP access.")
        print(f"{'='*60}")

#!/usr/bin/env python3
"""WoT Bot v15 — Correct version format (4-byte struct) + encrypted flag

BigWorld 14.4.1 findings:
- Version is ClientServerProtocolVersion: subpatch(1B) + patch(1B) + minor(1B) + major(1B)
- Current version: (major=2, minor=9, patch=0, subpatch=0) = bytes \x00\x00\x09\x02
- Body format: version(4B) + encrypted(bool 1B) + LogOnParams
- BW default key confirmed correct (hardcoded in source)
- Element 0x01 V32 BE confirmed
"""
import socket, struct, os, sys, time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1

exec(open('/root/wot-grinder-bot-v8/bw_bot_v3.py' if os.path.exists('/root/wot-grinder-bot-v8/bw_bot_v3.py') else '/tmp/bw_bot_v3.py').read().split('def run(')[0])

KEY_BW = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7/MNyWDdFpXhpFTO9LHz
CUQPYv2YP5rqJjUoxAFa3uKiPKbRvVFjUQ9lGHyjCmtixBbBqCTvDWu6Zh9Imu3x
KgCJh6NPSkddH3l+C+51FNtu3dGntbSLWuwi6Au1ErNpySpdx+Le7YEcFviY/ClZ
ayvVdA0tcb5NVJ4Axu13NvsuOUMqHxzCZRXCe6nyp6phFP2dQQZj8QZp0VsMFvhh
MsZ4srdFLG0sd8qliYzSqIyEQkwO8TQleHzfYYZ90wPTCOvMnMe5+zCH0iPJMisP
YB60u6lK9cvDEeuhPH95TPpzLNUFgmQIu9FU8PkcKA53bj0LWZR7v86Oco6vFg6V
sQIDAQAB
-----END PUBLIC KEY-----"""

def pack_int(n):
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[1:]
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_int(len(b)) + b

def rsa_encrypt(plaintext, pem_key=KEY_BW):
    key = RSA.importKey(pem_key)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    return cipher.encrypt(plaintext)

def build_v32_be(elem_id, rid, body):
    rh = struct.pack(">I", rid) + struct.pack(">H", 0)
    inner = rh + body
    content = bytes([elem_id]) + struct.pack(">I", len(inner)) + inner
    raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def parse_reply(data):
    if len(data) < 11: return {"raw": data.hex(), "error": "short"}
    if data[6] != 0xFF: return {"raw": data.hex(), "error": "not reply"}
    length = struct.unpack("<I", data[7:11])[0]
    rd = data[11:11+length]
    r = {"len": length, "raw": rd.hex()}
    if length >= 5:
        status = rd[4]
        codes = {1:"SUCCESS", 0x42:"CHALLENGE", 64:"Malformed", 65:"BadVersion",
                 67:"InvalidUser", 68:"InvalidPwd", 83:"RateLimited", 85:"ChallengeErr"}
        r["type"] = codes.get(status, f"0x{status:02X}")
        if length > 5:
            try: r["msg"] = rd[5:].decode('utf-8', errors='replace')[:200]
            except: r["msg"] = rd[5:].hex()[:50]
    return r

def make_logon(user="guest", pwd="", bf_key=None, nonce=0):
    if bf_key is None: bf_key = os.urandom(16)
    return struct.pack("<B", 0) + pack_str(user) + pack_str(pwd) + pack_str(bf_key) + struct.pack("<I", nonce)

def send_one(server, port, body, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(ping_packet(rid=1, num=0), (server, port))
    try: sock.recvfrom(4096)
    except: sock.close(); return {"error": "PING timeout"}
    pkt = build_v32_be(0x01, 2, body)
    sock.sendto(pkt, (server, port))
    try:
        data, _ = sock.recvfrom(4096)
        r = parse_reply(data)
        sock.close()
        return r
    except: sock.close(); return {"error": "timeout"}

def run_v15(server="login.p1.worldoftanks.eu", port=20016):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v15 — Struct Version + Encrypted Flag — {server}:{port}")
    print(f"{'='*55}")

    # Version as 4-byte struct: subpatch(0) + patch(0) + minor(9) + major(2)
    # Written as: \x00 \x00 \x09 \x02
    version_struct = bytes([0, 0, 9, 2])  # subpatch, patch, minor, major
    
    # Also try as u32 LE (same bytes)
    version_u32 = struct.pack("<I", 0x02090000)  # same as struct bytes
    
    tests = []
    
    # Test 1: Version struct (0,0,9,2) + encrypted=true + RSA BW key
    bf = os.urandom(16)
    logon = make_logon(bf_key=bf)
    rsa_data = rsa_encrypt(logon)
    body = version_struct + struct.pack("<B", 1) + rsa_data  # encrypted=true
    tests.append(("Struct v2.9.0.0 + enc=true + RSA BW", body))
    
    # Test 2: Same but as u32 (should be same bytes)
    body = version_u32 + struct.pack("<B", 1) + rsa_data
    tests.append(("u32 0x02090000 + enc=true + RSA BW", body))
    
    # Test 3: Version struct + encrypted=false + plain LogOnParams
    bf = os.urandom(16)
    logon = make_logon(bf_key=bf)
    body = version_struct + struct.pack("<B", 0) + logon  # encrypted=false
    tests.append(("Struct v2.9.0.0 + enc=false + plain", body))
    
    # Test 4: Various version structs
    for major, minor, patch, subpatch in [(2,9,0,0), (2,6,255,5), (2,6,0,0), (2,3,0,0), (2,2,255,5), (2,5,0,0)]:
        v = bytes([subpatch, patch, minor, major])
        bf = os.urandom(16)
        logon = make_logon(bf_key=bf)
        rsa_data = rsa_encrypt(logon)
        body = v + struct.pack("<B", 1) + rsa_data
        tests.append((f"Struct v{major}.{minor}.{patch}.{subpatch} + enc=true + RSA", body))
    
    # Test 5: Old format (u32=50) + encrypted=true + RSA BW (control)
    bf = os.urandom(16)
    logon = make_logon(bf_key=bf)
    rsa_data = rsa_encrypt(logon)
    body = struct.pack("<I", 50) + struct.pack("<B", 1) + rsa_data
    tests.append(("u32=50 + enc=true + RSA BW (control)", body))
    
    # Test 6: Old format (u32=50) + NO encrypted flag + RSA (C++ format)
    body = struct.pack("<I", 50) + rsa_data
    tests.append(("u32=50 + NO enc flag + RSA (C++ control)", body))
    
    # Test 7: Version struct + encrypted=true + RSA with context field
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + pack_str("guest") + struct.pack("<I", 0)
    rsa_data = rsa_encrypt(logon)
    body = version_struct + struct.pack("<B", 1) + rsa_data
    tests.append(("Struct v2.9.0.0 + enc=true + RSA with context", body))

    for desc, body in tests:
        print(f"\n  {desc}...")
        r = send_one(server, port, body)
        marker = "🎯" if r.get("type") not in ("Malformed", "BadVersion", "error") else "  "
        print(f"  {marker} → {r}")
        if r.get("type") in ("SUCCESS", "CHALLENGE", "InvalidUser", "InvalidPwd"):
            print(f"  🔥 BREAKTHROUGH: {r['type']}!")
            break

if __name__ == "__main__":
    run_v15()

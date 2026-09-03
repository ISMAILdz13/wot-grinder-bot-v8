#!/usr/bin/env python3
"""WoT Bot v18 — V16 BE with correct struct version

BREAKTHROUGH: We were sending Variable32 (4B length) but the server
expects Variable16 (2B length)! When V32 BE is misread as V16, the
first 2 bytes (\x00\x00) give length=0 → empty body → MalformedRequest.

Also: version is a 4-byte struct (subpatch, patch, minor, major),
NOT u32. Server version is 2.9.0.0 = bytes \x00\x00\x09\x02.

Also: NO encrypted flag — server reads version then LogOnParams directly.
The interface comment "bool encrypted" is just documentation, not actual code.
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

def make_logon(user="guest", pwd="", bf_key=None, nonce=0):
    if bf_key is None: bf_key = os.urandom(16)
    return struct.pack("<B", 0) + pack_str(user) + pack_str(pwd) + pack_str(bf_key) + struct.pack("<I", nonce)

def build_element(elem_id, rid, body, v32=False, be=True):
    """Build element with V16 (default) or V32, BE (default) or LE fields."""
    if be:
        rh = struct.pack(">I", rid) + struct.pack(">H", 0)
    else:
        rh = struct.pack("<I", rid) + struct.pack("<H", 0)
    inner = rh + body
    if v32:
        length_bytes = struct.pack(">I" if be else "<I", len(inner))
    else:
        length_bytes = struct.pack(">H" if be else "<H", len(inner))
    content = bytes([elem_id]) + length_bytes + inner
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
                 67:"InvalidUser", 68:"InvalidPwd", 69:"AlreadyLoggedIn",
                 82:"LoginNotAllowed", 83:"RateLimited", 85:"ChallengeErr"}
        r["type"] = codes.get(status, f"0x{status:02X}")
        if length > 5:
            try: r["msg"] = rd[5:].decode('utf-8', errors='replace')[:200]
            except: r["msg"] = rd[5:].hex()[:50]
    return r

def send_one(server, port, pkt, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(ping_packet(rid=1, num=0), (server, port))
    try: sock.recvfrom(4096)
    except: sock.close(); return {"error": "PING timeout"}
    sock.sendto(pkt, (server, port))
    try:
        data, _ = sock.recvfrom(4096)
        r = parse_reply(data)
        sock.close()
        return r
    except: sock.close(); return {"error": "timeout"}

def run_v18(server="login.p1.worldoftanks.eu", port=20016):
    print(f"\n{'='*60}")
    print(f"  WoT Bot v18 — V16 BE + Struct Version — {server}:{port}")
    print(f"{'='*60}")

    # Version as 4-byte struct: subpatch(0) + patch(0) + minor(9) + major(2)
    version_struct = bytes([0, 0, 9, 2])
    
    # Also try u32=50 for comparison
    version_u32 = struct.pack("<I", 50)
    
    # LogOnParams (plain, no RSA)
    logon = make_logon()
    
    # RSA-encrypted LogOnParams
    try:
        rsa_data = rsa_encrypt(logon)
        rsa_ok = True
    except Exception as e:
        print(f"  ⚠️ RSA key error: {e}")
        rsa_data = b""
        rsa_ok = False

    tests = []
    
    # THE KEY TESTS: V16 BE, elem 0x00, struct version, no encrypted flag
    # Body = version_struct + RSA_data (no encrypted flag, C++ format)
    if rsa_ok:
        body = version_struct + rsa_data
        pkt = build_element(0x00, 2, body)  # V16 BE default
        tests.append(("V16BE elem=0x00 struct_v + RSA (no enc flag)", pkt))
    
    # Same with plain LogOnParams (no RSA)
    body = version_struct + logon
    pkt = build_element(0x00, 2, body)
    tests.append(("V16BE elem=0x00 struct_v + plain (no enc flag)", pkt))
    
    # Try with encrypted=false flag (in case server reads it)
    body = version_struct + struct.pack("<B", 0) + logon
    pkt = build_element(0x00, 2, body)
    tests.append(("V16BE elem=0x00 struct_v + enc=false + plain", pkt))
    
    # Try with encrypted=true flag
    if rsa_ok:
        body = version_struct + struct.pack("<B", 1) + rsa_data
        pkt = build_element(0x00, 2, body)
        tests.append(("V16BE elem=0x00 struct_v + enc=true + RSA", pkt))
    
    # Also test elem 0x01 V16 BE (in case ID is different)
    if rsa_ok:
        body = version_struct + rsa_data
        pkt = build_element(0x01, 2, body)
        tests.append(("V16BE elem=0x01 struct_v + RSA", pkt))
    
    body = version_struct + logon
    pkt = build_element(0x01, 2, body)
    tests.append(("V16BE elem=0x01 struct_v + plain", pkt))
    
    # u32=50 with V16 BE (for comparison with old format)
    if rsa_ok:
        body = version_u32 + rsa_data
        pkt = build_element(0x00, 2, body)
        tests.append(("V16BE elem=0x00 u32=50 + RSA", pkt))
    
    body = version_u32 + logon
    pkt = build_element(0x00, 2, body)
    tests.append(("V16BE elem=0x00 u32=50 + plain", pkt))
    
    # V16 LE for comparison (in case BE is wrong)
    if rsa_ok:
        body = version_struct + rsa_data
        pkt = build_element(0x00, 2, body, be=False)
        tests.append(("V16LE elem=0x00 struct_v + RSA", pkt))
    
    # V32 BE elem=0x00 (control — should also work now)
    if rsa_ok:
        body = version_struct + rsa_data
        pkt = build_element(0x00, 2, body, v32=True)
        tests.append(("V32BE elem=0x00 struct_v + RSA (control)", pkt))
    
    # V32 BE elem=0x01 (our old format — control)
    if rsa_ok:
        body = version_struct + rsa_data
        pkt = build_element(0x01, 2, body, v32=True)
        tests.append(("V32BE elem=0x01 struct_v + RSA (old control)", pkt))

    for desc, pkt in tests:
        print(f"\n  {desc}...")
        r = send_one(server, port, pkt)
        if r.get("error"):
            print(f"  ❌ {r}")
        else:
            marker = "🎯" if r.get("type") not in ("Malformed", "BadVersion") else "  "
            print(f"  {marker} → {r}")
            if r.get("type") in ("SUCCESS", "CHALLENGE", "InvalidUser", "InvalidPwd"):
                print(f"  🔥🔥🔥 BREAKTHROUGH: {r['type']}!")
                # Don't break — show all results

if __name__ == "__main__":
    run_v18()

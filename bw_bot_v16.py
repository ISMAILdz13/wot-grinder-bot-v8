#!/usr/bin/env python3
"""WoT Bot v16 — Bypass RSA with encrypted=false

Key insight: The server reads version + encrypted(bool) + LogOnParams.
If encrypted=false, server reads PLAIN LogOnParams — no RSA needed!
This bypasses the RSA key issue entirely.
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
        rid_be = struct.unpack(">I", rd[:4])[0]
        status = rd[4]
        codes = {1:"SUCCESS", 0x42:"CHALLENGE", 64:"Malformed", 65:"BadVersion",
                 67:"InvalidUser", 68:"InvalidPwd", 69:"AlreadyLoggedIn",
                 83:"RateLimited", 85:"ChallengeErr", 82:"LoginNotAllowed"}
        r["type"] = codes.get(status, f"0x{status:02X}")
        r["rid"] = f"0x{rid_be:08X}" if rid_be != 0xFFFFFFFF else "0xFFFFFFFF"
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

def run_v16(server="login.p1.worldoftanks.eu", port=20016):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v16 — encrypted=false (No RSA) — {server}:{port}")
    print(f"{'='*55}")

    tests = []
    
    # THE KEY TEST: u32=50 + encrypted=false + plain LogOnParams
    bf = os.urandom(16)
    logon = make_logon(bf_key=bf)
    body = struct.pack("<I", 50) + struct.pack("<B", 0) + logon  # encrypted=false
    tests.append(("u32=50 + enc=false + plain LogOnParams", body))
    
    # Same with struct version
    bf = os.urandom(16)
    logon = make_logon(bf_key=bf)
    body = bytes([0,0,9,2]) + struct.pack("<B", 0) + logon
    tests.append(("struct v2.9.0.0 + enc=false + plain", body))
    
    # encrypted=true with BW key (control)
    bf = os.urandom(16)
    logon = make_logon(bf_key=bf)
    rsa_data = rsa_encrypt(logon)
    body = struct.pack("<I", 50) + struct.pack("<B", 1) + rsa_data
    tests.append(("u32=50 + enc=true + RSA BW (control)", body))
    
    # Try different usernames with encrypted=false
    for user in ["guest", "test", "", "player", "anonymous"]:
        bf = os.urandom(16)
        logon = make_logon(user=user, bf_key=bf)
        body = struct.pack("<I", 50) + struct.pack("<B", 0) + logon
        tests.append((f"u32=50 + enc=false + user='{user}'", body))
    
    # Try with HAS_DIGEST flag (flags=1) + encrypted=false
    bf = os.urandom(16)
    digest = os.urandom(16)
    logon = struct.pack("<B", 1) + pack_str("guest") + pack_str("") + pack_str(bf) + digest + struct.pack("<I", 0)
    body = struct.pack("<I", 50) + struct.pack("<B", 0) + logon
    tests.append(("u32=50 + enc=false + flags=HAS_DIGEST", body))
    
    # Try with nonce != 0
    bf = os.urandom(16)
    logon = make_logon(bf_key=bf, nonce=12345)
    body = struct.pack("<I", 50) + struct.pack("<B", 0) + logon
    tests.append(("u32=50 + enc=false + nonce=12345", body))
    
    # Try proto=51 + encrypted=false
    bf = os.urandom(16)
    logon = make_logon(bf_key=bf)
    body = struct.pack("<I", 51) + struct.pack("<B", 0) + logon
    tests.append(("u32=51 + enc=false + plain", body))
    
    # Try with NO encrypted flag at all (raw C++ format, old BigWorld 2.0.1)
    bf = os.urandom(16)
    logon = make_logon(bf_key=bf)
    body = struct.pack("<I", 50) + logon  # NO encrypted flag
    tests.append(("u32=50 + NO enc flag + plain (C++ old)", body))

    for desc, body in tests:
        print(f"\n  {desc}...")
        r = send_one(server, port, body)
        marker = "🎯" if r.get("type") not in ("Malformed", "BadVersion", "error") else "  "
        print(f"  {marker} → {r}")
        if r.get("type") in ("SUCCESS", "CHALLENGE", "InvalidUser", "InvalidPwd", "AlreadyLoggedIn"):
            print(f"  🔥🔥🔥 BREAKTHROUGH: {r['type']}!")
            break

if __name__ == "__main__":
    run_v16()

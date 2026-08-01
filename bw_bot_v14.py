#!/usr/bin/env python3
"""WoT Bot v14 — Isolate rate limiting vs format issue.

Tests 2-3 gave 0x40 but tests 8-16 gave 0x41 with SAME format/proto.
Hypothesis: server changes state after bad requests (rate limiting).
Test: send ONE request at a time, fresh socket each time.
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
            try: r["msg"] = rd[5:].decode('utf-8', errors='replace')[:100]
            except: pass
    return r

def send_one(server, port, rid, body, timeout=5):
    """Send a single request with a fresh socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    # PING first
    sock.sendto(ping_packet(rid=rid, num=0), (server, port))
    try:
        sock.recvfrom(4096)
    except:
        sock.close()
        return {"error": "PING timeout"}
    rid += 1
    # Login request
    pkt = build_v32_be(0x01, rid, body)
    sock.sendto(pkt, (server, port))
    try:
        data, _ = sock.recvfrom(4096)
        r = parse_reply(data)
        sock.close()
        return r
    except:
        sock.close()
        return {"error": "login timeout"}

def run_v14(server="login.p1.worldoftanks.eu", port=20016):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v14 — Isolate Rate Limiting — {server}:{port}")
    print(f"{'='*55}")

    # Test 1: BW key, proto=50, user="guest" — FRESH socket, first request
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
    body = struct.pack("<I", 50) + rsa_encrypt(logon, KEY_BW)
    print(f"\n[1] BW key, proto=50, user=guest (fresh socket)...")
    r = send_one(server, port, 1, body)
    print(f"   → {r}")

    # Test 2: BW key, proto=50, user="test" — FRESH socket, first request
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("test") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
    body = struct.pack("<I", 50) + rsa_encrypt(logon, KEY_BW)
    print(f"\n[2] BW key, proto=50, user=test (fresh socket)...")
    r = send_one(server, port, 1, body)
    print(f"   → {r}")

    # Test 3: Same as test 1 but with different random BF key
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
    body = struct.pack("<I", 50) + rsa_encrypt(logon, KEY_BW)
    print(f"\n[3] BW key, proto=50, user=guest, diff BF (fresh socket)...")
    r = send_one(server, port, 1, body)
    print(f"   → {r}")

    # Test 4: BW key, proto=50, user="player"
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("player") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
    body = struct.pack("<I", 50) + rsa_encrypt(logon, KEY_BW)
    print(f"\n[4] BW key, proto=50, user=player (fresh socket)...")
    r = send_one(server, port, 1, body)
    print(f"   → {r}")

    # Test 5: BW key, proto=50, user="" (empty)
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
    body = struct.pack("<I", 50) + rsa_encrypt(logon, KEY_BW)
    print(f"\n[5] BW key, proto=50, user='' (fresh socket)...")
    r = send_one(server, port, 1, body)
    print(f"   → {r}")

    # Test 6: Try with context field (Rust format without encrypted flag)
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + pack_str("guest") + struct.pack("<I", 0)
    body = struct.pack("<I", 50) + rsa_encrypt(logon, KEY_BW)
    print(f"\n[6] BW key, proto=50, with context (fresh socket)...")
    r = send_one(server, port, 1, body)
    print(f"   → {r}")

    # Test 7: No RSA, just plaintext LogOnParams
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
    body = struct.pack("<I", 50) + logon
    print(f"\n[7] No RSA, proto=50, plain LogOnParams (fresh socket)...")
    r = send_one(server, port, 1, body)
    print(f"   → {r}")

if __name__ == "__main__":
    run_v14()

#!/usr/bin/env python3
"""WoT Bot v17 — Test Variable16 BE (from BigWorld source) vs Variable32 BE

BigWorld 14.4.1 source says: MERCURY_VARIABLE_MESSAGE(login, 2, ...)
- "2" means Variable16 (2B length)
- Element ID 0x00 (login is first in interface)

But our v8 test of 0x00 V16 timed out. Maybe V16 was LE, not BE.
Now we know BE is correct — let's test V16 BE properly.
"""
import socket, struct, os, sys, time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1

exec(open('/root/wot-grinder-bot-v8/bw_bot_v3.py' if os.path.exists('/root/wot-grinder-bot-v8/bw_bot_v3.py') else '/tmp/bw_bot_v3.py').read().split('def run(')[0])

KEY_BW = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7/MNyWDdFpXhpFTO9LHz
CUQPYv2YP5rqJjUoxAFrqJjUoxAFa3uKiPKbRvVFjUQ9lGHyjCmtixBbBqCTvDWu6
Zh9Imu3xKgCJh6NPSkddH3l+C+51FNtu3dGntbSLWuwi6Au1ErNpySpdx+Le7YEc
FviY/ClZayvVdA0tcb5NVJ4Axu13NvsuOUMqHxzCZRXCe6nyp6phFP2dQQZj8QZp
0VsMFvhhMsZ4srdFLG0sd8qliYzSqIyEQkwO8TQleHzfYYZ90wPTCOvMnMe5+zCH
0iPJMisPYB60u6lK9cvDEeuhPH95TPpzLNUFgmQIu9FU8PkcKA53bj0LWZR7v86O
co6vFg6VsQIDAQAB
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

def build_element(elem_id, rid, body, v32=True, be=True):
    """Build element with V16 or V32, BE or LE fields."""
    if be:
        rh = struct.pack(">I", rid) + struct.pack(">H", 0)
    else:
        rh = struct.pack("<I", rid) + struct.pack("<H", 0)
    inner = rh + body
    if v32:
        if be:
            content = bytes([elem_id]) + struct.pack(">I", len(inner)) + inner
        else:
            content = bytes([elem_id]) + struct.pack("<I", len(inner)) + inner
    else:
        if be:
            content = bytes([elem_id]) + struct.pack(">H", len(inner)) + inner
        else:
            content = bytes([elem_id]) + struct.pack("<H", len(inner)) + inner
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
                 67:"InvalidUser", 68:"InvalidPwd", 83:"RateLimited"}
        r["type"] = codes.get(status, f"0x{status:02X}")
        if length > 5:
            try: r["msg"] = rd[5:].decode('utf-8', errors='replace')[:200]
            except: pass
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

def run_v17(server="login.p1.worldoftanks.eu", port=20016):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v17 — V16 BE vs V32 BE — {server}:{port}")
    print(f"{'='*55}")

    # Build login body: version(50) + encrypted(false) + plain LogOnParams
    logon = make_logon()
    body_enc_false = struct.pack("<I", 50) + struct.pack("<B", 0) + logon
    
    # Also try without encrypted flag (C++ old format)
    body_no_enc = struct.pack("<I", 50) + logon
    
    # RSA body (no enc flag, C++ format)
    rsa_data = rsa_encrypt(logon)
    body_rsa = struct.pack("<I", 50) + rsa_data
    
    # RSA body with enc=true flag
    body_rsa_enc = struct.pack("<I", 50) + struct.pack("<B", 1) + rsa_data

    tests = []
    
    # Test all combinations: elem_id × V16/V32 × BE/LE × body formats
    for elem_id in [0x00, 0x01]:
        for v32 in [False, True]:
            for be in [True, False]:
                fmt = f"{'V32' if v32 else 'V16'}{'BE' if be else 'LE'}"
                # enc=false body
                pkt = build_element(elem_id, 2, body_enc_false, v32=v32, be=be)
                tests.append((f"elem=0x{elem_id:02X} {fmt} enc=false", pkt))
                # no enc flag body
                pkt = build_element(elem_id, 2, body_no_enc, v32=v32, be=be)
                tests.append((f"elem=0x{elem_id:02X} {fmt} no-enc plain", pkt))
                # RSA no enc flag
                pkt = build_element(elem_id, 2, body_rsa, v32=v32, be=be)
                tests.append((f"elem=0x{elem_id:02X} {fmt} RSA no-enc", pkt))

    for desc, pkt in tests:
        print(f"\n  {desc}...")
        r = send_one(server, port, pkt)
        if r.get("error"):
            print(f"  ❌ {r}")
        else:
            marker = "🎯" if r.get("type") not in ("Malformed", "BadVersion") else "  "
            print(f"  {marker} → {r}")
            if r.get("type") in ("SUCCESS", "CHALLENGE", "InvalidUser"):
                print(f"  🔥🔥🔥 BREAKTHROUGH!")
                break

if __name__ == "__main__":
    run_v17()

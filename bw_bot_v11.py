#!/usr/bin/env python3
"""WoT Bot v11 — Find the correct protocol version.

BE Mercury fields confirmed working. Error changes with version:
  51-52 → 0x40 (too old)
  55-60 → 0x41 (too new)
Try 53, 54 and wider range to find the sweet spot.
Also try RSA with different keys for the correct version.
"""
import socket, struct, os, sys, time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1

exec(open('/root/wot-grinder-bot-v8/bw_bot_v3.py' if os.path.exists('/root/wot-grinder-bot-v8/bw_bot_v3.py') else '/tmp/bw_bot_v3.py').read().split('def run(')[0])

KEY_WOT = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyjeVAXWfhj02sEGd8BnK
Z2y8Twnwefea2R3QulJurdD0lmFPyczP2Z54Lju7TAMYtJ4o02MTkm2BKtmd7WOt
yFxyVEDdRH65D2PK2bEzptve6JoBQD9uZQZn3Vi4MmMzrlWkkF9NkJ84A45ZxocN
M8oLTjfhdkLvDMvvG1h8oc4KAD9uGv3FRgQSkIZtD5ro+stOvQiiDj4OQd5o9+M0
JS36ks1C69vjMsOWC+gFH/rdDEEoFOwGIM6Q8iTYb2rjHeyAP2fNPGf+X7l73+yV
s7lm2Bh2WezlZSDikycb1r3FvB4wUhohahwfuORGdMtxidzIQzNdcFo0Gg+dg7wc
hwIDAQAB
-----END PUBLIC KEY-----"""

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

def rsa_encrypt(plaintext, pem_key):
    key = RSA.importKey(pem_key)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    return cipher.encrypt(plaintext)

def build_v32_be(elem_id, rid, body):
    """V32 with BE Mercury fields, LE body."""
    rh = struct.pack(">I", rid) + struct.pack(">H", 0)  # BE request_id + BE next
    inner = rh + body
    content = bytes([elem_id]) + struct.pack(">I", len(inner)) + inner  # BE length
    raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def parse_reply(data):
    if len(data) < 11: return {"raw": data.hex(), "error": "short"}
    flags = struct.unpack("<H", data[4:6])[0]
    if data[6] != 0xFF: return {"raw": data.hex(), "error": f"not reply"}
    length = struct.unpack("<I", data[7:11])[0]
    rd = data[11:11+length]
    r = {"len": length, "raw": rd.hex()}
    if length >= 5:
        rid_be = struct.unpack(">I", rd[:4])[0]  # Try BE for reply_id too
        rid_le = struct.unpack("<I", rd[:4])[0]
        status = rd[4]
        if status == 1: r["type"] = "SUCCESS"
        elif status == 0x42: r["type"] = "CHALLENGE"
        elif status >= 64: r["type"] = f"ERR(0x{status:02X})"
        else: r["type"] = f"OK(0x{status:02X})"
        r["rid_BE"] = f"0x{rid_be:08X}" if rid_be != 0xFFFFFFFF else "0xFFFFFFFF"
        if length > 5:
            try: r["msg"] = rd[5:].decode('utf-8', errors='replace')[:100]
            except: r["msg"] = rd[5:].hex()[:50]
    return r

def make_logon(user="guest", pwd="", bf_key=None, nonce=0):
    if bf_key is None: bf_key = os.urandom(16)
    return struct.pack("<B", 0) + pack_str(user) + pack_str(pwd) + pack_str(bf_key) + struct.pack("<I", nonce)

def run_v11(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v11 — Find Protocol Version — {server}:{port}")
    print(f"{'='*55}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1

    # PING
    print(f"\n[1] PING...")
    sock.sendto(ping_packet(rid=rid, num=0), (server, port))
    try:
        data, _ = sock.recvfrom(4096)
        print(f"    ✅ PING OK")
        rid += 1
    except socket.timeout:
        print(f"    ❌ PING timeout")
        sock.close(); return

    # Phase 1: Scan protocol versions 50-60 (plain body)
    print(f"\n[2] Scanning protocol versions 50-60 (plain)...")
    for proto in range(50, 61):
        bf = os.urandom(16)
        body = struct.pack("<I", proto) + make_logon(bf_key=bf)
        pkt = build_v32_be(0x01, rid, body)
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            marker = "🎯" if r.get("type") not in ("ERR(0x40)", "ERR(0x41)") else "  "
            print(f"    {marker} proto={proto}: {r}")
            rid += 1
            if r.get("type") in ("SUCCESS", "CHALLENGE"):
                break
        except socket.timeout:
            print(f"    ❌ proto={proto}: timeout")
            rid += 1

    # Phase 2: Try wider range if needed
    print(f"\n[3] Scanning wider range 40-70...")
    for proto in list(range(40, 50)) + list(range(61, 71)):
        bf = os.urandom(16)
        body = struct.pack("<I", proto) + make_logon(bf_key=bf)
        pkt = build_v32_be(0x01, rid, body)
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            marker = "🎯" if r.get("type") not in ("ERR(0x40)", "ERR(0x41)") else "  "
            print(f"    {marker} proto={proto}: {r}")
            rid += 1
            if r.get("type") in ("SUCCESS", "CHALLENGE"):
                break
        except socket.timeout:
            print(f"    ❌ proto={proto}: timeout")
            rid += 1

    # Phase 3: RSA with the version that gave different error
    print(f"\n[4] RSA with both keys for proto=53,54...")
    for proto in [53, 54]:
        for key_name, key in [("WoT", KEY_WOT), ("BW", KEY_BW)]:
            bf = os.urandom(16)
            rsa_data = rsa_encrypt(make_logon(bf_key=bf), key)
            body = struct.pack("<I", proto) + rsa_data
            pkt = build_v32_be(0x01, rid, body)
            sock.sendto(pkt, (server, port))
            try:
                data, _ = sock.recvfrom(4096)
                r = parse_reply(data)
                print(f"    RSA {key_name} proto={proto}: {r}")
                rid += 1
                if r.get("type") in ("SUCCESS", "CHALLENGE"):
                    print(f"    🎯 BREAKTHROUGH!")
                    break
            except socket.timeout:
                print(f"    ❌ RSA {key_name} proto={proto}: timeout")
                rid += 1

    sock.close()

if __name__ == "__main__":
    run_v11()

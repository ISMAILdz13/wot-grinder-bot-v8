#!/usr/bin/env python3
"""WoT Bot v7 — Try Variable32 (4B length) for login instead of Variable16 (2B)

The PING reply uses Variable32 (4B length). Maybe ALL elements use Variable32.
Our login was using Variable16 (2B length) which shifts the data.
"""
import socket, struct, hashlib, os, time, sys
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

def pack_int(n):
    if n >= 255:
        return struct.pack("<B", 0xFF) + struct.pack("<I", n)[1:]
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_int(len(b)) + b

def rsa_encrypt(plaintext, pem_key):
    key = RSA.importKey(pem_key)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    return cipher.encrypt(plaintext)

def login_v32_rsa(rid, protocol=51, user="guest", pwd="", bf_key=None, nonce=0, pem_key=KEY_WOT):
    """Login with Variable32 (4B length) element format + RSA encryption"""
    if bf_key is None: bf_key = os.urandom(16)
    
    # LogOnParams plaintext
    logon = struct.pack("<B", 0)  # flags
    logon += pack_str(user)
    logon += pack_str(pwd)
    logon += pack_str(bf_key)
    logon += struct.pack("<I", nonce)
    
    rsa_data = rsa_encrypt(logon, pem_key)
    body = struct.pack("<I", protocol) + rsa_data
    
    # Variable32 element: [0x00] [length(4B)] [request_id(4B)] [next(2B)] [body]
    rh = struct.pack("<IH", rid, 0)
    inner = rh + body
    content = struct.pack("<BI", 0x00, len(inner)) + inner  # 4B length!
    
    raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:], bf_key

def login_v32_plain(rid, protocol=51, user="guest", pwd="", bf_key=None, nonce=0):
    """Login with Variable32 (4B length) element format, plaintext"""
    if bf_key is None: bf_key = os.urandom(16)
    
    body = struct.pack("<I", protocol)
    body += struct.pack("<B", 0)
    body += pack_str(user)
    body += pack_str(pwd)
    body += pack_str(bf_key)
    body += struct.pack("<I", nonce)
    
    rh = struct.pack("<IH", rid, 0)
    inner = rh + body
    content = struct.pack("<BI", 0x00, len(inner)) + inner  # 4B length!
    
    raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:], bf_key

def login_v16_rsa(rid, protocol=51, user="guest", pwd="", bf_key=None, nonce=0, pem_key=KEY_WOT):
    """Login with Variable16 (2B length) + RSA (same as v6)"""
    if bf_key is None: bf_key = os.urandom(16)
    
    logon = struct.pack("<B", 0)
    logon += pack_str(user)
    logon += pack_str(pwd)
    logon += pack_str(bf_key)
    logon += struct.pack("<I", nonce)
    
    rsa_data = rsa_encrypt(logon, pem_key)
    body = struct.pack("<I", protocol) + rsa_data
    
    rh = struct.pack("<IH", rid, 0)
    inner = rh + body
    content = struct.pack("<BH", 0x00, len(inner)) + inner  # 2B length
    
    raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:], bf_key

def run_v7(server="login.p1.worldoftanks.eu", port=20016, timeout=8):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v7 — Variable32 Login Test — {server}:{port}")
    print(f"{'='*55}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1

    # PING
    print(f"\n[1] PING (rid={rid})...")
    pkt = ping_packet(rid=rid, num=0)
    sock.sendto(pkt, (server, port))
    try:
        data, addr = sock.recvfrom(4096)
        print(f"    ✅ PING OK from {addr}")
        rid += 1
    except socket.timeout:
        print(f"    ❌ PING timeout")
        sock.close(); return

    tests = [
        ("V32+RSA WoT key, proto=51", lambda r: login_v32_rsa(r, 51)),
        ("V32+plain, proto=51", lambda r: login_v32_plain(r, 51)),
        ("V32+RSA WoT key, proto=52", lambda r: login_v32_rsa(r, 52)),
        ("V32+plain, proto=52", lambda r: login_v32_plain(r, 52)),
        ("V16+RSA WoT key, proto=51 (control)", lambda r: login_v16_rsa(r, 51)),
        ("V32+RSA WoT key, proto=60", lambda r: login_v32_rsa(r, 60)),
    ]
    
    for desc, fn in tests:
        print(f"\n[2] {desc} (rid={rid})...")
        pkt, bf = fn(rid)
        print(f"    → {pkt[:60].hex()}... ({len(pkt)}B)")
        sock.sendto(pkt, (server, port))
        try:
            data, addr = sock.recvfrom(4096)
            print(f"    ← RAW: {data.hex()} ({len(data)}B) from {addr}")
            r = parse_response(data)
            print(f"    Parsed: {r}")
            rid += 1
            if r.get("type") in ("CHALLENGE", "SUCCESS"):
                print(f"    🎯 {r['type']}!")
                break
        except socket.timeout:
            print(f"    ❌ Timeout")
            rid += 1

    sock.close()

if __name__ == "__main__":
    run_v7()

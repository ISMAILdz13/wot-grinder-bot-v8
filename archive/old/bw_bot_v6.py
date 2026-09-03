#!/usr/bin/env python3
"""WoT Bot v6 — RSA-encrypted login with real WoT public keys

The server requires RSA-encrypted LogOnParams (BigWorld version 45+).
Format: LOGIN_VERSION(4B) + RSA-OAEP-SHA1(LogOnParams)
LogOnParams: flags(1B) + username(packed_str) + password(packed_str) + encKey(packed_blob) + nonce(4B)
"""
import socket, struct, hashlib, os, time, sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1

# Import core from v3
exec(open('/root/wot-grinder-bot-v8/bw_bot_v3.py' if os.path.exists('/root/wot-grinder-bot-v8/bw_bot_v3.py') else '/tmp/bw_bot_v3.py').read().split('def run(')[0])

# RSA public keys found on GitHub
KEY_WOT = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyjeVAXWfhj02sEGd8BnK
Z2y8Twnwefea2R3QulJurdD0lmFPyczP2Z54Lju7TAMYtJ4o02MTkm2BKtmd7WOt
yFxyVEDdRH65D2PK2bEzptve6JoBQD9uZQZn3Vi4MmMzrlWkkF9NkJ84A45ZxocN
M8oLTjfhdkLvDMvvG1h8oc4KAD9uGv3FRgQSkIZtD5ro+stOvQiiDj4OQd5o9+M0
JS36ks1C69vjMsOWC+gFH/rdDEEoFOwGIM6Q8iTYb2rjHeyAP2fNPGf+X7l73+yV
s7lm2Bh2WezlZSDikycb1r3FvB4wUhohahwfuORGdMtxidzIQzNdcFo0Gg+dg7wc
hwIDAQAB
-----END PUBLIC KEY-----"""

KEY_BW_DEFAULT = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7/MNyWDdFpXhpFTO9LHz
CUQPYv2YP5rqJjUoxAFa3uKiPKbRvVFjUQ9lGHyjCmtixBbBqCTvDWu6Zh9Imu3x
KgCJh6NPSkddH3l+C+51FNtu3dGntbSLWuwi6Au1ErNpySpdx+Le7YEcFviY/ClZ
ayvVdA0tcb5NVJ4Axu13NvsuOUMqHxzCZRXCe6nyp6phFP2dQQZj8QZp0VsMFvhh
MsZ4srdFLG0sd8qliYzSqIyEQkwO8TQleHzfYYZ90wPTCOvMnMe5+zCH0iPJMisP
YB60u6lK9cvDEeuhPH95TPpzLNUFgmQIu9FU8PkcKA53bj0LWZR7v86Oco6vFg6V
sQIDAQAB
-----END PUBLIC KEY-----"""

def pack_int(n):
    """BigWorld packed int: 1 byte if <255, 0xFF + 3 bytes LE if >=255"""
    if n >= 255:
        return struct.pack("<B", 0xFF) + struct.pack("<I", n)[1:]
    return struct.pack("<B", n)

def pack_str(s):
    """Pack a string with packed_int length prefix"""
    b = s.encode() if isinstance(s, str) else s
    return pack_int(len(b)) + b

def rsa_encrypt(plaintext, pem_key):
    """RSA-OAEP-SHA1 encrypt (matching BigWorld's RSAStreamEncoder)"""
    key = RSA.importKey(pem_key)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    # For 2048-bit key: max plaintext = 256 - 2*20 - 2 = 214 bytes
    # Our LogOnParams is ~33 bytes, fits in one block
    encrypted = cipher.encrypt(plaintext)
    return encrypted

def login_packet_rsa(rid, protocol=51, user="guest", pwd="", bf_key=None, nonce=0, pem_key=KEY_WOT):
    """Build RSA-encrypted login request (C++ BigWorld format)"""
    if bf_key is None: bf_key = os.urandom(16)
    
    # Build LogOnParams plaintext (what gets RSA-encrypted)
    logon_params = struct.pack("<B", 0)  # flags (no digest)
    logon_params += pack_str(user)  # username
    logon_params += pack_str(pwd)  # password  
    logon_params += pack_str(bf_key)  # encryptionKey (Blowfish key)
    logon_params += struct.pack("<I", nonce)  # nonce
    
    # RSA encrypt the LogOnParams
    rsa_data = rsa_encrypt(logon_params, pem_key)
    
    # Build login body: LOGIN_VERSION(4B) + RSA_encrypted_data
    body = struct.pack("<I", protocol) + rsa_data
    
    # Build request element: [0x00] [length(2B)] [request_id(4B)] [next(2B)] [body]
    rh = struct.pack("<IH", rid, 0)
    inner = rh + body
    content = struct.pack("<BH", 0x00, len(inner)) + inner
    
    # Build packet (off-channel, unreliable, has_requests)
    raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:], bf_key

def login_packet_plain(rid, protocol=51, user="guest", pwd="", bf_key=None, nonce=0):
    """Build plaintext login request (C++ format, no RSA)"""
    if bf_key is None: bf_key = os.urandom(16)
    
    # LogOnParams in plaintext
    body = struct.pack("<I", protocol)  # LOGIN_VERSION
    body += struct.pack("<B", 0)  # flags (no digest)
    body += pack_str(user)  # username
    body += pack_str(pwd)  # password
    body += pack_str(bf_key)  # encryptionKey
    body += struct.pack("<I", nonce)  # nonce
    
    rh = struct.pack("<IH", rid, 0)
    inner = rh + body
    content = struct.pack("<BH", 0x00, len(inner)) + inner
    
    raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:], bf_key

def run_v6(server="login.p1.worldoftanks.eu", port=20016, timeout=8):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v6 — RSA Encrypted Login — {server}:{port}")
    print(f"{'='*55}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1

    # [1] PING
    print(f"\n[1] PING (rid={rid})...")
    pkt = ping_packet(rid=rid, num=0)
    sock.sendto(pkt, (server, port))
    try:
        data, addr = sock.recvfrom(4096)
        print(f"    ✅ PING reply from {addr}")
        rid += 1
    except socket.timeout:
        print(f"    ❌ PING timeout")
        sock.close(); return

    # [2] RSA-encrypted login with WoT key
    tests = [
        ("RSA WoT key, proto=51", 51, KEY_WOT, "WoT"),
        ("RSA BW default key, proto=51", 51, KEY_BW_DEFAULT, "BW"),
        ("RSA WoT key, proto=52", 52, KEY_WOT, "WoT"),
        ("RSA BW default key, proto=52", 52, KEY_BW_DEFAULT, "BW"),
        ("Plain C++ fmt, proto=51", 51, None, "plain"),
        ("RSA WoT key, proto=60", 60, KEY_WOT, "WoT"),
    ]
    
    for desc, proto, key, key_name in tests:
        print(f"\n[2] {desc} (rid={rid})...")
        if key:
            pkt, bf_key = login_packet_rsa(rid=rid, protocol=proto, pem_key=key)
            print(f"    RSA block: {len(pkt)}B total, key={key_name}")
        else:
            pkt, bf_key = login_packet_plain(rid=rid, protocol=proto)
            print(f"    Plain: {len(pkt)}B")
        print(f"    → {pkt[:60].hex()}...")
        sock.sendto(pkt, (server, port))
        try:
            data, addr = sock.recvfrom(4096)
            print(f"    ← RAW: {data.hex()} ({len(data)}B) from {addr}")
            r = parse_response(data)
            print(f"    Parsed: {r}")
            rid += 1
            if r.get("type") in ("CHALLENGE", "SUCCESS"):
                print(f"    🎯 Got {r['type']} with {desc}!")
                break
        except socket.timeout:
            print(f"    ❌ Timeout")
            rid += 1

    sock.close()

if __name__ == "__main__":
    for s in ["login.p1.worldoftanks.eu"]:
        run_v6(s, 20016)

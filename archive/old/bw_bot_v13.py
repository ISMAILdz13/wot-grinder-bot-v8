#!/usr/bin/env python3
"""WoT Bot v13 — Test BW default key with proto=50 (valid version)

The loginapp_wot.pubkey from WoT Blitz = BigWorld default key.
Maybe the PC WoT server uses the same key!
Test both keys with proto=50 (valid) to see which gives a different error.
Also: test with/without encrypted flag, with real WG username.
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
        # Error codes from wg-toolkit-rs
        codes = {1:"SUCCESS", 0x42:"CHALLENGE", 64:"MalformedRequest", 65:"BadProtocolVersion",
                 67:"InvalidUser", 68:"InvalidPassword", 69:"AlreadyLoggedIn", 70:"BadDigest",
                 71:"DBFailure", 72:"DBNotReady", 73:"IllegalChars", 74:"ServerNotReady",
                 76:"NoBaseApp", 77:"BaseAppOverload", 78:"CellAppOverload", 82:"LoginNotAllowed",
                 83:"RateLimited", 84:"Banned", 85:"ChallengeError"}
        r["type"] = codes.get(status, f"UNKNOWN(0x{status:02X})")
        r["rid"] = f"0x{rid_be:08X}" if rid_be != 0xFFFFFFFF else "0xFFFFFFFF"
        if length > 5:
            try: r["msg"] = rd[5:].decode('utf-8', errors='replace')[:200]
            except: r["msg"] = rd[5:].hex()[:50]
    return r

def make_logon(user="guest", pwd="", bf_key=None, nonce=0, context=None):
    if bf_key is None: bf_key = os.urandom(16)
    params = struct.pack("<B", 0) + pack_str(user) + pack_str(pwd) + pack_str(bf_key)
    if context is not None:
        params += pack_str(context)
    params += struct.pack("<I", nonce)
    return params

def run_v13(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v13 — BW Key vs WoT Key, proto=50 — {server}:{port}")
    print(f"{'='*55}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1

    # PING
    print(f"\n[1] PING...")
    sock.sendto(ping_packet(rid=rid, num=0), (server, port))
    try:
        sock.recvfrom(4096); print(f"    ✅ PING OK"); rid += 1
    except: print(f"    ❌ PING timeout"); sock.close(); return

    tests = []
    
    # Test BW key with proto=50 (valid version), C++ format (no encrypted flag)
    for proto in [50, 51]:
        for key_name, key in [("BW", KEY_BW), ("WoT", KEY_WOT)]:
            bf = os.urandom(16)
            logon = make_logon(bf_key=bf)  # C++ format (no context)
            rsa_data = rsa_encrypt(logon, key)
            body = struct.pack("<I", proto) + rsa_data  # No encrypted flag
            tests.append((f"C++ {key_name} key, proto={proto}, no enc flag", body))
    
    # Test BW key with Rust format (encrypted=true flag)
    for key_name, key in [("BW", KEY_BW), ("WoT", KEY_WOT)]:
        bf = os.urandom(16)
        logon = make_logon(bf_key=bf, context="guest")  # Rust format (with context)
        rsa_data = rsa_encrypt(logon, key)
        body = struct.pack("<I", 50) + struct.pack("<B", 1) + rsa_data  # encrypted=true
        tests.append((f"Rust {key_name} key, proto=50, enc=true", body))
    
    # Test BW key with a real-looking WG username
    for user in ["test", "player", ""]:
        bf = os.urandom(16)
        logon = make_logon(user=user, bf_key=bf)
        rsa_data = rsa_encrypt(logon, KEY_BW)
        body = struct.pack("<I", 50) + rsa_data
        tests.append((f"BW key, proto=50, user='{user}'", body))
    
    # Test BW key with different BF key sizes
    for bf_size in [4, 8, 16, 24, 32, 56]:
        bf = os.urandom(bf_size)
        logon = make_logon(bf_key=bf)
        rsa_data = rsa_encrypt(logon, KEY_BW)
        body = struct.pack("<I", 50) + rsa_data
        tests.append((f"BW key, proto=50, bf_size={bf_size}", body))

    for desc, body in tests:
        print(f"\n[{rid}] {desc}...")
        pkt = build_v32_be(0x01, rid, body)
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            marker = "🎯" if r.get("type") not in ("MalformedRequest", "BadProtocolVersion") else "  "
            print(f"   {marker} {r}")
            rid += 1
            if r.get("type") in ("SUCCESS", "CHALLENGE", "InvalidUser", "InvalidPassword"):
                print(f"   🔥 KEY FINDING: {r['type']}!")
                break
        except socket.timeout:
            print(f"   ❌ Timeout")
            rid += 1

    sock.close()

if __name__ == "__main__":
    run_v13()

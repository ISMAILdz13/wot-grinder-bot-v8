#!/usr/bin/env python3
"""WoT Bot v9 — CORRECT element ID (0x01) + Variable32 + RSA encryption

BREAKTHROUGH: Element 0x01 with V32 got error response (0x40).
WoT LoginInterface: 0x01=login(V32), 0x02=ping(Fixed)
Error 0x40 = likely "malformed" or "needs RSA encryption"
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

def build_v32_request(elem_id, rid, body):
    """Build a Variable32 request element."""
    rh = struct.pack("<IH", rid, 0)  # request_id(4B) + next(2B)
    inner = rh + body
    content = struct.pack("<BI", elem_id, len(inner)) + inner  # [id][len(4B)][inner]
    raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def parse_reply(data):
    """Parse a reply packet."""
    if len(data) < 11:
        return {"raw": data.hex(), "error": "too short"}
    prefix = data[:4]
    flags = struct.unpack("<H", data[4:6])[0]
    if data[6] != 0xFF:
        return {"raw": data.hex(), "error": f"not a reply (0x{data[6]:02X})"}
    length = struct.unpack("<I", data[7:11])[0]
    reply_data = data[11:11+length]
    
    result = {
        "flags": f"0x{flags:04X}",
        "length": length,
        "raw_data": reply_data.hex(),
    }
    
    if length >= 4:
        reply_id = struct.unpack("<I", reply_data[:4])[0]
        result["reply_id"] = f"0x{reply_id:08X}"
        
        if length >= 5:
            status = reply_data[4]
            if status == 1:
                result["type"] = "SUCCESS"
            elif status == 0x42:  # 'B'
                result["type"] = "CHALLENGE"
            elif status >= 64:
                result["type"] = f"ERROR(0x{status:02X})"
            else:
                result["type"] = f"STATUS(0x{status:02X})"
            
            if length > 5:
                msg = reply_data[5:]
                try:
                    result["message"] = msg.decode('utf-8', errors='replace')
                except:
                    result["message"] = msg.hex()
    
    return result

def run_v9(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v9 — Element 0x01 V32 — {server}:{port}")
    print(f"{'='*55}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1

    # PING
    print(f"\n[1] PING (rid={rid})...")
    sock.sendto(ping_packet(rid=rid, num=0), (server, port))
    try:
        data, addr = sock.recvfrom(4096)
        print(f"    ✅ PING OK")
        rid += 1
    except socket.timeout:
        print(f"    ❌ PING timeout")
        sock.close(); return

    # Build LogOnParams plaintext
    def make_logon(user="guest", pwd="", bf_key=None, nonce=0):
        if bf_key is None: bf_key = os.urandom(16)
        params = struct.pack("<B", 0)  # flags (no digest)
        params += pack_str(user)
        params += pack_str(pwd)
        params += pack_str(bf_key)
        params += struct.pack("<I", nonce)
        return params

    # Try many combinations
    tests = []
    
    # RSA with WoT key, various protocol versions
    for proto in [51, 52, 55, 60]:
        bf = os.urandom(16)
        logon = make_logon(bf_key=bf)
        rsa_data = rsa_encrypt(logon, KEY_WOT)
        body = struct.pack("<I", proto) + rsa_data
        tests.append((f"RSA WoT, proto={proto}", body))
    
    # RSA with BW default key
    for proto in [51, 52]:
        bf = os.urandom(16)
        logon = make_logon(bf_key=bf)
        rsa_data = rsa_encrypt(logon, KEY_BW)
        body = struct.pack("<I", proto) + rsa_data
        tests.append((f"RSA BW, proto={proto}", body))
    
    # Plain (no RSA), various protocols
    for proto in [51, 52, 55, 60]:
        bf = os.urandom(16)
        body = struct.pack("<I", proto)
        body += make_logon(bf_key=bf)
        tests.append((f"Plain, proto={proto}", body))
    
    # With nonce (non-zero)
    for proto in [51]:
        bf = os.urandom(16)
        logon = make_logon(bf_key=bf, nonce=12345)
        rsa_data = rsa_encrypt(logon, KEY_WOT)
        body = struct.pack("<I", proto) + rsa_data
        tests.append((f"RSA WoT, proto={proto}, nonce=12345", body))

    # With digest flag
    for proto in [51]:
        bf = os.urandom(16)
        digest = os.urandom(16)
        logon = struct.pack("<B", 1)  # flags = HAS_DIGEST
        logon += pack_str("guest")
        logon += pack_str("")
        logon += pack_str(bf)
        logon += digest
        logon += struct.pack("<I", 0)
        rsa_data = rsa_encrypt(logon, KEY_WOT)
        body = struct.pack("<I", proto) + rsa_data
        tests.append((f"RSA WoT+digest, proto={proto}", body))

    for desc, body in tests:
        print(f"\n[2] {desc} (rid={rid})...")
        pkt = build_v32_request(0x01, rid, body)
        print(f"    → {len(pkt)}B")
        sock.sendto(pkt, (server, port))
        try:
            data, addr = sock.recvfrom(4096)
            r = parse_reply(data)
            print(f"    ← {r}")
            rid += 1
            if r.get("type") == "CHALLENGE":
                print(f"    🎯 GOT CHALLENGE!")
                break
            elif r.get("type") == "SUCCESS":
                print(f"    🎉 GOT SUCCESS!")
                break
        except socket.timeout:
            print(f"    ❌ Timeout")
            rid += 1

    sock.close()

if __name__ == "__main__":
    run_v9()

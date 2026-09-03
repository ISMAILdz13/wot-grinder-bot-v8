#!/usr/bin/env python3
"""WoT Bot v20b — RSA padding variants + C++ style LogOnParams"""
import socket, struct, os, sys, time

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA1, SHA256

FLAG_HAS_REQUESTS = 0x0002

def xorshift32_transform(data):
    val = 0
    for b in data:
        val ^= b; val = (val * 0x100) & 0xFFFFFFFF; val = (val + b) & 0xFFFFFFFF
    return val

def _prefix(raw):
    return xorshift32_transform(raw[4:])

def pack_int(n):
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[1:]
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_int(len(b)) + b

def build_ping(rid):
    content = struct.pack("<B", 0x02) + struct.pack("<I", rid) + struct.pack("<H", 0) + b'\x00'
    raw = struct.pack("<IH", 0, FLAG_HAS_REQUESTS) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def build_v32_request(elem_id, rid, body):
    inner = struct.pack("<IH", rid, 0) + body
    content = struct.pack("<BI", elem_id, len(inner)) + inner
    raw = struct.pack("<IH", 0, FLAG_HAS_REQUESTS) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def build_v16_request(elem_id, rid, body):
    inner = struct.pack("<IH", rid, 0) + body
    content = struct.pack("<BH", elem_id, len(inner)) + inner
    raw = struct.pack("<IH", 0, FLAG_HAS_REQUESTS) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def build_fixed_request(elem_id, rid, body):
    inner = struct.pack("<IH", rid, 0) + body
    content = struct.pack("<B", elem_id) + inner
    raw = struct.pack("<IH", 0, FLAG_HAS_REQUESTS) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def parse_reply(data):
    if len(data) < 11: return {"raw": data.hex(), "error": "short"}
    flags = struct.unpack("<H", data[4:6])[0]
    if data[6] != 0xFF: return {"raw": data.hex(), "error": f"not reply"}
    length = struct.unpack("<I", data[7:11])[0]
    rdata = data[11:11+length]
    result = {"flags": f"0x{flags:04X}", "len": length, "raw": rdata.hex()}
    if length >= 4:
        rid = struct.unpack("<I", rdata[:4])[0]
        result["rid"] = f"0x{rid:08X}"
        if length >= 5:
            status = rdata[4]
            if status == 1: result["type"] = "SUCCESS"
            elif status == 0x42: result["type"] = "CHALLENGE"
            elif status >= 64: result["type"] = f"ERROR(0x{status:02X})"
            else: result["type"] = f"STATUS(0x{status:02X})"
            if length > 5:
                result["data"] = rdata[5:].hex()
                try: result["msg"] = rdata[5:].decode('utf-8', errors='replace')[:200]
                except: pass
    return result

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

def rsa_oaep(plaintext, pem, hash_algo=SHA1):
    key = RSA.importKey(pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=hash_algo)
    return cipher.encrypt(plaintext)

def rsa_pkcs1v15(plaintext, pem):
    key = RSA.importKey(pem)
    cipher = PKCS1_v1_5.new(key)
    return cipher.encrypt(plaintext)

def logon_v1(user="guest", pwd="", bf_key=None, nonce=0, flags=0):
    if bf_key is None: bf_key = os.urandom(16)
    p = struct.pack("<B", flags); p += pack_str(user); p += pack_str(pwd)
    p += pack_str(bf_key); p += struct.pack("<I", nonce); return p

def logon_v3(user="guest", pwd="", bf_key=None, nonce=0, flags=0):
    if bf_key is None: bf_key = os.urandom(16)
    p = struct.pack("<B", flags); p += user.encode() + b'\x00'; p += pwd.encode() + b'\x00'
    p += struct.pack("<B", len(bf_key)) + bf_key; p += struct.pack("<I", nonce); return p

def logon_minimal(bf_key=None):
    if bf_key is None: bf_key = os.urandom(16)
    return struct.pack("<B", 0) + pack_str(bf_key)

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v20b — RSA Padding + Format Variants")
    print(f"  {server}:{port}")
    print(f"{'='*55}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1
    print(f"\n[1] PING (rid={rid})...")
    sock.sendto(build_ping(rid), (server, port))
    try:
        data, _ = sock.recvfrom(4096)
        print(f"    PING OK")
        rid += 1
    except socket.timeout:
        print(f"    PING timeout")
        sock.close(); return

    tests = []
    # RSA-OAEP SHA1 with WoT key
    for proto in [51, 52, 55, 60, 72, 75]:
        for logon_fn, ldesc in [(logon_v1, "v1"), (logon_v3, "v3")]:
            bf = os.urandom(16)
            body = struct.pack("<I", proto) + rsa_oaep(logon_fn(bf_key=bf), KEY_WOT, SHA1)
            tests.append((f"OAEP-SHA1 WoT proto={proto} {ldesc}", body, 0x01, "v32"))
    # RSA-OAEP SHA256
    for proto in [51, 52, 55]:
        bf = os.urandom(16)
        body = struct.pack("<I", proto) + rsa_oaep(logon_v1(bf_key=bf), KEY_WOT, SHA256)
        tests.append((f"OAEP-SHA256 WoT proto={proto}", body, 0x01, "v32"))
    # RSA-PKCS1v15
    for proto in [51, 52, 55, 60, 72]:
        for logon_fn, ldesc in [(logon_v1, "v1"), (logon_v3, "v3")]:
            bf = os.urandom(16)
            body = struct.pack("<I", proto) + rsa_pkcs1v15(logon_fn(bf_key=bf), KEY_WOT)
            tests.append((f"PKCS1v15 WoT proto={proto} {ldesc}", body, 0x01, "v32"))
    # PKCS1v15 with BW key
    for proto in [51, 52, 55]:
        bf = os.urandom(16)
        body = struct.pack("<I", proto) + rsa_pkcs1v15(logon_v1(bf_key=bf), KEY_BW)
        tests.append((f"PKCS1v15 BW proto={proto}", body, 0x01, "v32"))
    # Plain (no RSA)
    for proto in [51, 52, 55, 72]:
        for logon_fn, ldesc in [(logon_v1, "v1"), (logon_v3, "v3")]:
            bf = os.urandom(16)
            body = struct.pack("<I", proto) + logon_fn(bf_key=bf)
            tests.append((f"Plain proto={proto} {ldesc}", body, 0x01, "v32"))
    # Proto-only
    for proto in [51, 52, 55, 72, 75]:
        tests.append((f"Proto-only proto={proto}", struct.pack("<I", proto), 0x01, "v32"))
    # Minimal
    for proto in [51, 52]:
        bf = os.urandom(16)
        body = struct.pack("<I", proto) + rsa_oaep(logon_minimal(bf), KEY_WOT)
        tests.append((f"OAEP minimal proto={proto}", body, 0x01, "v32"))
    # Element 0x00
    for proto in [51, 52]:
        bf = os.urandom(16)
        body = struct.pack("<I", proto) + rsa_oaep(logon_v1(bf_key=bf), KEY_WOT)
        tests.append((f"OAEP elem=0x00 proto={proto}", body, 0x00, "v32"))
    # V16 format
    for proto in [51, 52]:
        bf = os.urandom(16)
        body = struct.pack("<I", proto) + rsa_oaep(logon_v1(bf_key=bf), KEY_WOT)
        tests.append((f"OAEP v16 elem=0x01 proto={proto}", body, 0x01, "v16"))
    # Fixed format
    for proto in [51, 52]:
        bf = os.urandom(16)
        body = struct.pack("<I", proto) + rsa_oaep(logon_v1(bf_key=bf), KEY_WOT)
        tests.append((f"OAEP fixed elem=0x01 proto={proto}", body, 0x01, "fixed"))

    print(f"\n[2] Testing {len(tests)} combinations...")
    for desc, body, elem_id, fmt in tests:
        print(f"\n  [{rid}] {desc}...")
        if fmt == "v32": pkt = build_v32_request(elem_id, rid, body)
        elif fmt == "v16": pkt = build_v16_request(elem_id, rid, body)
        else: pkt = build_fixed_request(elem_id, rid, body)
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            print(f"      <- {r}")
            rid += 1
            if r.get("type") == "CHALLENGE":
                print(f"      CHALLENGE! data={r.get('data','')[:200]}")
                with open('/tmp/wot_challenge.bin', 'wb') as f: f.write(data[11:])
                break
            elif r.get("type") == "SUCCESS":
                print(f"      SUCCESS!")
                break
        except socket.timeout:
            print(f"      timeout")
            rid += 1
    sock.close()

if __name__ == "__main__":
    for server, port in [("login.p1.worldoftanks.eu", 20016), ("login.p2.worldoftanks.eu", 20018)]:
        run(server, port)
        time.sleep(1)

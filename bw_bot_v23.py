#!/usr/bin/env python3
"""WoT Bot v23 — CORRECT Element 0x00 V16 with exact wg-toolkit-rs body format

Root cause of 20h failure: we were sending to Element 0x01 V32 (wrong element!).
wg-toolkit-rs confirms: LOGIN_REQUEST = 0x00, format = Variable16.

Body format (from wg-toolkit-rs source):
  [protocol(4B LE)] + [encrypted_flag(1B bool)] + [LogOnParams]

LogOnParams (write_login_request):
  [flags(1B=0)] + [username(packed_str)] + [password(packed_str)] +
  [bf_key(packed_blob)] + [context(packed_str)] + [nonce(4B LE)]

packed_str = packed_u24 length + data (1 byte for <255)
"""
import socket, struct, os, sys, time

# Import v3's exact packet code (correct _prefix, FLAGS, _pkt)
exec(open('/root/wot-grinder-bot-v8/bw_bot_v3.py' if os.path.exists('/root/wot-grinder-bot-v8/bw_bot_v3.py') else '/tmp/bw_bot_v3.py').read().split('def run(')[0])

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1

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

def rsa_oaep(plaintext, pem):
    key = RSA.importKey(pem)
    return PKCS1_OAEP.new(key, hashAlgo=SHA1).encrypt(plaintext)

def pack_u24(n):
    """packed_u24: 1 byte for <255, 0xFF + 3 bytes for >=255."""
    if n >= 255:
        return struct.pack("<B", 0xFF) + struct.pack("<I", n)[:3]
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_u24(len(b)) + b

def build_logon_params(user="guest", pwd="", bf_key=None, ctx="guest", nonce=0, has_digest=False):
    """Build LogOnParams exactly as wg-toolkit-rs write_login_request."""
    if bf_key is None:
        bf_key = os.urandom(16)
    p = struct.pack("<B", 0x01 if has_digest else 0x00)  # flags
    p += pack_str(user)        # write_string_variable
    p += pack_str(pwd)         # write_string_variable
    p += pack_str(bf_key)     # write_blob_variable
    p += pack_str(ctx)        # write_string_variable
    if has_digest:
        p += os.urandom(16)   # 16-byte digest
    p += struct.pack("<I", nonce)  # write_u32 LE
    return p

def build_login_v16(rid, protocol, encrypted, logon_params, rsa_key_pem=None):
    """Build LoginRequest: Element 0x00, Variable16.
    
    Element: [0x00] [length(2B LE)] [rid(4B)] [next(2B)] [body]
    Body: [protocol(4B LE)] + [encrypted_flag(1B)] + [LogOnParams or RSA(LogOnParams)]
    """
    if encrypted and rsa_key_pem:
        payload = rsa_oaep(logon_params, rsa_key_pem)
    else:
        payload = logon_params
    
    body = struct.pack("<I", protocol)  # protocol (4B LE)
    body += struct.pack("<B", 1 if encrypted else 0)  # encrypted_flag (1B bool)
    body += payload
    
    # Element: [id] [len(2B)] [rid(4B)] [next(2B)] [body]
    inner = struct.pack("<IH", rid, 0) + body
    content = struct.pack("<BH", 0x00, len(inner)) + inner  # V16: 2-byte length
    
    return _pkt(content, first_req=0)

def parse_reply(data):
    if len(data) < 6:
        return {"error": "too short", "raw": data.hex()}
    prefix = struct.unpack_from("<I", data, 0)[0]
    flags = struct.unpack_from("<H", data, 4)[0]
    content = data[6:]
    r = {"prefix": f"{prefix:08x}", "flags": f"{flags:04x}"}
    
    if flags & FLAGS['HAS_CHECKSUM'] and len(content) >= 4: content = content[:-4]
    if flags & FLAGS['INDEXED_CHANNEL'] and len(content) >= 8: content = content[8:]
    if flags & FLAGS['HAS_CUMULATIVE_ACK'] and len(content) >= 2: content = content[2:]
    
    if len(content) >= 5 and content[0] == 0xFF:
        length = struct.unpack_from("<I", content, 1)[0]
        rdata = content[5:5+length]
        if len(rdata) >= 5:
            reply_rid = struct.unpack_from("<I", rdata, 0)[0]
            status = rdata[4]
            r["rid"] = f"0x{reply_rid:08X}"
            if status == 1: r["type"] = "SUCCESS"
            elif status == 0x42: r["type"] = "CHALLENGE"
            elif status >= 64: r["type"] = f"ERROR(0x{status:02X})"
            else: r["type"] = f"STATUS(0x{status:02X})"
            if len(rdata) > 5:
                r["data"] = rdata[5:].hex()[:200]
                try: r["msg"] = rdata[5:].decode('utf-8', errors='replace')[:100]
                except: pass
    else:
        r["content"] = content.hex()[:200]
    return r

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v23 — Element 0x00 V16 (CORRECT!)")
    print(f"  {server}:{port}")
    print(f"{'='*55}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1
    
    # PING
    print(f"\n[1] PING...")
    sock.sendto(ping_packet(rid=rid), (server, port))
    try:
        data, _ = sock.recvfrom(4096)
        print(f"    PING OK ({len(data)}B)")
        rid += 1
    except socket.timeout:
        print(f"    PING timeout — trying p2...")
        sock.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        server, port = "login.p2.worldoftanks.eu", 20018
        sock.sendto(ping_packet(rid=rid), (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            print(f"    p2 PING OK")
            rid += 1
        except socket.timeout:
            print(f"    All PING failed")
            sock.close(); return
    
    tests = []
    
    # ===== Element 0x00 V16 — PLAINTEXT (encrypted=false) =====
    for proto in [50, 51, 52, 55, 324]:
        bf = os.urandom(16)
        logon = build_logon_params(user="guest", pwd="", bf_key=bf, ctx="guest")
        pkt = build_login_v16(rid, proto, encrypted=False, logon_params=logon)
        tests.append((f"V16 plain proto={proto}", pkt))
    
    # ===== Element 0x00 V16 — RSA with WoT key =====
    for proto in [50, 51, 52, 55]:
        bf = os.urandom(16)
        logon = build_logon_params(user="guest", pwd="", bf_key=bf, ctx="guest")
        pkt = build_login_v16(rid, proto, encrypted=True, logon_params=logon, rsa_key_pem=KEY_WOT)
        tests.append((f"V16 RSA-WoT proto={proto}", pkt))
    
    # ===== Element 0x00 V16 — RSA with BW key =====
    for proto in [50, 51, 52]:
        bf = os.urandom(16)
        logon = build_logon_params(user="guest", pwd="", bf_key=bf, ctx="guest")
        pkt = build_login_v16(rid, proto, encrypted=True, logon_params=logon, rsa_key_pem=KEY_BW)
        tests.append((f"V16 RSA-BW proto={proto}", pkt))
    
    # ===== Element 0x00 V16 — no context =====
    for proto in [50, 51, 52]:
        bf = os.urandom(16)
        logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
        pkt = build_login_v16(rid, proto, encrypted=False, logon_params=logon)
        tests.append((f"V16 plain no-ctx proto={proto}", pkt))
    
    # ===== Element 0x00 V16 — with digest (flags=0x01) =====
    for proto in [50, 51, 52]:
        bf = os.urandom(16)
        logon = build_logon_params(user="guest", pwd="", bf_key=bf, ctx="guest", has_digest=True)
        pkt = build_login_v16(rid, proto, encrypted=False, logon_params=logon)
        tests.append((f"V16 plain digest proto={proto}", pkt))
    
    # ===== Element 0x00 V16 — RSA no context =====
    for proto in [50, 51, 52]:
        bf = os.urandom(16)
        logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
        pkt = build_login_v16(rid, proto, encrypted=True, logon_params=logon, rsa_key_pem=KEY_WOT)
        tests.append((f"V16 RSA-WoT no-ctx proto={proto}", pkt))
    
    print(f"\n[2] Testing {len(tests)} combinations on Element 0x00 V16...")
    for desc, pkt in tests:
        print(f"\n  [{rid}] {desc}...")
        print(f"      -> {len(pkt)}B: {pkt[:30].hex()}...")
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            print(f"      <- {r}")
            rid += 1
            if r.get("type") == "CHALLENGE":
                print(f"      *** CHALLENGE! data={r.get('data','')}")
                with open('/tmp/wot_challenge.bin', 'wb') as f: f.write(data)
                break
            elif r.get("type") == "SUCCESS":
                print(f"      *** SUCCESS!")
                break
        except socket.timeout:
            print(f"      timeout")
            rid += 1
    
    sock.close()

if __name__ == "__main__":
    run()

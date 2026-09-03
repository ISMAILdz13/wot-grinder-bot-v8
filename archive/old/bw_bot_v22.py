#!/usr/bin/env python3
"""WoT Bot v22 — Add encrypted_flag byte (the missing piece!)

v21 got 0x40 (MalformedRequest) because the body was missing the 
encrypted_flag byte between protocol_version and RSA data.

Correct body format (from wg-toolkit-rs):
  [protocol(4B LE)] + [encrypted_flag(1B)] + [RSA_encrypted(LogOnParams)(256B)]
  Total: 261 bytes

Also tests:
- encrypted_flag=0 + plaintext LogOnParams
- encrypted_flag=1 + RSA with different LogOnParams formats
- Different element IDs (0x00, 0x01) with V32-LE
"""
import socket, struct, os, sys, time

# Import v3's exact packet code (which has WORKING PING)
exec(open('/root/wot-grinder-bot-v8/bw_bot_v3.py' if os.path.exists('/root/wot-grinder-bot-v8/bw_bot_v3.py') else '/tmp/bw_bot_v3.py').read().split('def run(')[0])

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
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

def rsa_pkcs1(plaintext, pem):
    key = RSA.importKey(pem)
    return PKCS1_v1_5.new(key).encrypt(plaintext)

def pack_int(n):
    """BigWorld packed_int: 1 byte for <255, 0xFF + 3 bytes for larger."""
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[1:]
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_int(len(b)) + b

def build_v32_le(elem_id, rid, body):
    """V32 with LE fields — confirmed correct by v21 (gets 0x40 not 0x41)."""
    rh = struct.pack("<I", rid) + struct.pack("<H", 0)
    inner = rh + body
    content = bytes([elem_id]) + struct.pack("<I", len(inner)) + inner
    raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def parse_reply(data):
    if len(data) < 6: return {"error": "too short", "raw": data.hex()}
    prefix = struct.unpack_from("<I", data, 0)[0]
    flags = struct.unpack_from("<H", data, 4)[0]
    content = data[6:]
    r = {"prefix": f"{prefix:08x}", "flags": f"{flags:04x}"}
    
    if flags & FLAGS['HAS_CHECKSUM'] and len(content) >= 4: content = content[:-4]
    if flags & FLAGS['INDEXED_CHANNEL'] and len(content) >= 8: content = content[8:]
    if flags & FLAGS['HAS_CUMULATIVE_ACK'] and len(content) >= 2: content = content[2:]
    
    if not (flags & FLAGS['HAS_REQUESTS']):
        r["content"] = content.hex()[:200]
        # Parse reply element (0xFF)
        if len(content) >= 5 and content[0] == 0xFF:
            length = struct.unpack_from("<I", content, 1)[0]
            rdata = content[5:5+length]
            if len(rdata) >= 5:
                rid = struct.unpack_from("<I", rdata, 0)[0]
                status = rdata[4]
                r["rid"] = f"0x{rid:08X}"
                if status == 1: r["type"] = "SUCCESS"
                elif status == 0x42: r["type"] = "CHALLENGE"
                elif status >= 64: r["type"] = f"ERROR(0x{status:02X})"
                else: r["type"] = f"STATUS(0x{status:02X})"
                if len(rdata) > 5:
                    r["data"] = rdata[5:].hex()[:200]
                    try: r["msg"] = rdata[5:].decode('utf-8', errors='replace')[:100]
                    except: pass
        return r
    r["type"] = "request_reply"
    return r

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v22 — Encrypted Flag Fix — {server}:{port}")
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
        server = "login.p2.worldoftanks.eu"; port = 20018
        sock.sendto(ping_packet(rid=rid), (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            print(f"    p2 PING OK")
            rid += 1
        except socket.timeout:
            print(f"    All PING failed")
            sock.close(); return
    
    tests = []
    
    # LogOnParams formats
    def logon_packed(user="guest", pwd="", bf_key=None, ctx="guest", nonce=0, flags=0):
        """packed_int format (wg-toolkit-rs / BigWorld standard)."""
        if bf_key is None: bf_key = os.urandom(16)
        p = struct.pack("<B", flags)
        p += pack_str(user)
        p += pack_str(pwd)
        p += pack_str(bf_key)
        if ctx is not None: p += pack_str(ctx)
        p += struct.pack("<I", nonce)
        return p
    
    def logon_v3(user="guest", pwd="", bf_key=None, ctx="guest", nonce=0):
        """v3 format: 2-byte length prefixes."""
        if bf_key is None: bf_key = os.urandom(16)
        p = struct.pack("<IBB", 0, 0, 0)  # flags(1B) + 2 unknown bytes
        p += struct.pack("<H", len(user.encode())) + user.encode()
        p += struct.pack("<H", len(pwd.encode())) + pwd.encode()
        p += struct.pack("<H", len(bf_key)) + bf_key
        p += struct.pack("<H", len(ctx.encode())) + ctx.encode()
        p += struct.pack("<I", nonce)
        return p
    
    # ===== Tests with encrypted_flag=1 + RSA =====
    for proto in [51, 52, 55]:
        for logon_fn, ldesc in [(logon_packed, "packed"), (logon_v3, "v3fmt")]:
            for key_name, key, enc_fn in [
                ("WoT", KEY_WOT, rsa_oaep),
                ("BW", KEY_BW, rsa_oaep),
                ("WoT-P15", KEY_WOT, rsa_pkcs1),
            ]:
                bf = os.urandom(16)
                logon = logon_fn(bf_key=bf)
                rsa_data = enc_fn(logon, key)
                # WITH encrypted flag
                body = struct.pack("<I", proto) + struct.pack("<B", 1) + rsa_data
                tests.append((f"flag=1 {key_name} {ldesc} proto={proto}", body, 0x01))
    
    # ===== Tests with encrypted_flag=0 + plaintext =====
    for proto in [51, 52, 55]:
        for logon_fn, ldesc in [(logon_packed, "packed"), (logon_v3, "v3fmt")]:
            bf = os.urandom(16)
            logon = logon_fn(bf_key=bf)
            body = struct.pack("<I", proto) + struct.pack("<B", 0) + logon
            tests.append((f"flag=0 plain {ldesc} proto={proto}", body, 0x01))
    
    # ===== Test without encrypted flag (v21 baseline — should still get 0x40) =====
    for proto in [51, 52]:
        bf = os.urandom(16)
        logon = logon_packed(bf_key=bf)
        rsa_data = rsa_oaep(logon, KEY_WOT)
        body = struct.pack("<I", proto) + rsa_data
        tests.append((f"NO-FLAG {ldesc} proto={proto} (baseline)", body, 0x01))
    
    # ===== Try Element 0x00 with V32-LE + encrypted flag =====
    for proto in [51, 52]:
        bf = os.urandom(16)
        logon = logon_packed(bf_key=bf)
        rsa_data = rsa_oaep(logon, KEY_WOT)
        body = struct.pack("<I", proto) + struct.pack("<B", 1) + rsa_data
        tests.append((f"flag=1 elem=0x00 proto={proto}", body, 0x00))
    
    # ===== Try logon without ctx field =====
    for proto in [51, 52]:
        bf = os.urandom(16)
        logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
        rsa_data = rsa_oaep(logon, KEY_WOT)
        body = struct.pack("<I", proto) + struct.pack("<B", 1) + rsa_data
        tests.append((f"flag=1 no-ctx proto={proto}", body, 0x01))
    
    print(f"\n[2] Testing {len(tests)} combinations...")
    found = False
    for desc, body, elem_id in tests:
        print(f"\n  [{rid}] {desc}...")
        print(f"      body={len(body)}B")
        pkt = build_v32_le(elem_id, rid, body)
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            print(f"      <- {r}")
            rid += 1
            if r.get("type") == "CHALLENGE":
                print(f"      *** CHALLENGE! data={r.get('data','')}")
                with open('/tmp/wot_challenge.bin', 'wb') as f: f.write(data)
                found = True
                break
            elif r.get("type") == "SUCCESS":
                print(f"      *** SUCCESS!")
                found = True
                break
            elif r.get("type", "").startswith("ERROR"):
                # Track which ones get 0x40 vs 0x41
                pass
        except socket.timeout:
            print(f"      timeout")
            rid += 1
    
    sock.close()
    if not found:
        print("\nNo CHALLENGE or SUCCESS yet. Check error codes above:")
        print("  0x40 = MalformedRequest (version OK, payload wrong)")
        print("  0x41 = BadProtocolVersion (version field wrong)")
        print("  0x42 = CHALLENGE (success! need to solve Cuckoo)")
        print("  timeout = wrong element ID or format")

if __name__ == "__main__":
    run()

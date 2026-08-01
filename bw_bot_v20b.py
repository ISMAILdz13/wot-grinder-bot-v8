#!/usr/bin/env python3
"""WoT Bot v20b — RSA padding variants + C++ style LogOnParams

Error 0x40 from v8 means server PARSED the packet but rejected the payload.
Possible causes:
1. RSA-OAEP vs RSA-PKCS1v15 padding mismatch
2. LogOnParams serialization format (C++ packed_int vs our format)
3. Wrong protocol version
4. Server expects Cuckoo challenge BEFORE login

This script tries:
- RSA-OAEP (SHA1, SHA256) and RSA-PKCS1v15
- Multiple protocol versions
- Different LogOnParams formats
- Element IDs 0x00-0x03
- V16, V32, Fixed formats
"""
import socket, struct, os, sys, time

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA1, SHA256

# ============================================================
# BigWorld protocol (shared with v20)
# ============================================================
FLAG_HAS_REQUESTS = 0x0002

def xorshift32_transform(data):
    val = 0
    for b in data:
        val ^= b
        val = (val * 0x100) & 0xFFFFFFFF
        val = (val + b) & 0xFFFFFFFF
    return struct.pack("<I", val)

def _prefix(raw):
    return xorshift32_transform(raw[4:])

def pack_int(n):
    """BigWorld packed int: 1 byte for <255, 0xFF + 3 bytes for larger."""
    if n >= 255:
        return struct.pack("<B", 0xFF) + struct.pack("<I", n)[1:]
    return struct.pack("<B", n)

def pack_str(s):
    """Packed string: packed_int length + data."""
    b = s.encode() if isinstance(s, str) else s
    return pack_int(len(b)) + b

def pack_blob(b):
    """Blob_var: packed_int length + data (same as pack_str)."""
    return pack_str(b)

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
    """Variable16: [elem_id][len(2B)][rid(4B)][next(2B)][body]"""
    inner = struct.pack("<IH", rid, 0) + body
    content = struct.pack("<BH", elem_id, len(inner)) + inner
    raw = struct.pack("<IH", 0, FLAG_HAS_REQUESTS) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def build_fixed_request(elem_id, rid, body):
    """Fixed format: [elem_id][rid(4B)][next(2B)][body] (no length field)"""
    inner = struct.pack("<IH", rid, 0) + body
    content = struct.pack("<B", elem_id) + inner
    raw = struct.pack("<IH", 0, FLAG_HAS_REQUESTS) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def parse_reply(data):
    if len(data) < 11:
        return {"raw": data.hex(), "error": "short"}
    flags = struct.unpack("<H", data[4:6])[0]
    if data[6] != 0xFF:
        return {"raw": data.hex(), "error": f"not reply (0x{data[6]:02X})"}
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
                try:
                    result["msg"] = rdata[5:].decode('utf-8', errors='replace')[:200]
                except: pass
    return result

# ============================================================
# RSA keys
# ============================================================
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

# ============================================================
# LogOnParams formats
# ============================================================

def logon_v1(user="guest", pwd="", bf_key=None, nonce=0, flags=0):
    """Standard BigWorld LogOnParams (packed_int strings)."""
    if bf_key is None: bf_key = os.urandom(16)
    p = struct.pack("<B", flags)
    p += pack_str(user)
    p += pack_str(pwd)
    p += pack_str(bf_key)
    p += struct.pack("<I", nonce)
    return p

def logon_v2(user="guest", pwd="", bf_key=None, nonce=0, flags=0):
    """Alternative: blob_var for bf_key (packed_int length + data)."""
    if bf_key is None: bf_key = os.urandom(16)
    p = struct.pack("<B", flags)
    p += pack_str(user)
    p += pack_str(pwd)
    p += pack_blob(bf_key)  # Same as pack_str but explicit
    p += struct.pack("<I", nonce)
    return p

def logon_v3(user="guest", pwd="", bf_key=None, nonce=0, flags=0):
    """C++ style: null-terminated strings instead of packed_int."""
    if bf_key is None: bf_key = os.urandom(16)
    p = struct.pack("<B", flags)
    p += user.encode() + b'\x00'
    p += pwd.encode() + b'\x00'
    p += struct.pack("<B", len(bf_key)) + bf_key
    p += struct.pack("<I", nonce)
    return p

def logon_minimal(bf_key=None):
    """Minimal: just flags + bf_key (no user/pwd/nonce)."""
    if bf_key is None: bf_key = os.urandom(16)
    return struct.pack("<B", 0) + pack_str(bf_key)

# ============================================================
# Main test
# ============================================================

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v20b — RSA Padding + Format Variants")
    print(f"  {server}:{port}")
    print(f"{'='*55}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1
    
    # PING
    print(f"\n[1] PING (rid={rid})...")
    sock.sendto(build_ping(rid), (server, port))
    try:
        data, _ = sock.recvfrom(4096)
        print(f"    ✅ PING OK")
        rid += 1
    except socket.timeout:
        print(f"    ❌ PING timeout")
        sock.close(); return
    
    tests = []
    
    # ===== RSA-OAEP SHA1 with WoT key =====
    for proto in [51, 52, 55, 60, 72, 75]:
        for logon_fn, ldesc in [(logon_v1, "v1"), (logon_v2, "v2"), (logon_v3, "v3")]:
            bf = os.urandom(16)
            logon = logon_fn(bf_key=bf)
            rsa_data = rsa_oaep(logon, KEY_WOT, SHA1)
            body = struct.pack("<I", proto) + rsa_data
            tests.append((f"OAEP-SHA1 WoT proto={proto} {ldesc}", body, 0x01, "v32"))
    
    # ===== RSA-OAEP SHA256 with WoT key =====
    for proto in [51, 52, 55]:
        bf = os.urandom(16)
        logon = logon_v1(bf_key=bf)
        rsa_data = rsa_oaep(logon, KEY_WOT, SHA256)
        body = struct.pack("<I", proto) + rsa_data
        tests.append((f"OAEP-SHA256 WoT proto={proto}", body, 0x01, "v32"))
    
    # ===== RSA-PKCS1v15 with WoT key =====
    for proto in [51, 52, 55, 60, 72]:
        for logon_fn, ldesc in [(logon_v1, "v1"), (logon_v3, "v3")]:
            bf = os.urandom(16)
            logon = logon_fn(bf_key=bf)
            rsa_data = rsa_pkcs1v15(logon, KEY_WOT)
            body = struct.pack("<I", proto) + rsa_data
            tests.append((f"PKCS1v15 WoT proto={proto} {ldesc}", body, 0x01, "v32"))
    
    # ===== RSA-PKCS1v15 with BW key =====
    for proto in [51, 52, 55]:
        bf = os.urandom(16)
        logon = logon_v1(bf_key=bf)
        rsa_data = rsa_pkcs1v15(logon, KEY_BW)
        body = struct.pack("<I", proto) + rsa_data
        tests.append((f"PKCS1v15 BW proto={proto}", body, 0x01, "v32"))
    
    # ===== Plain (no RSA) =====
    for proto in [51, 52, 55, 72]:
        for logon_fn, ldesc in [(logon_v1, "v1"), (logon_v3, "v3")]:
            bf = os.urandom(16)
            body = struct.pack("<I", proto) + logon_fn(bf_key=bf)
            tests.append((f"Plain proto={proto} {ldesc}", body, 0x01, "v32"))
    
    # ===== Just protocol version (no LogOnParams, no RSA) =====
    for proto in [51, 52, 55, 72, 75]:
        body = struct.pack("<I", proto)
        tests.append((f"Proto-only proto={proto}", body, 0x01, "v32"))
    
    # ===== Minimal LogOnParams =====
    for proto in [51, 52]:
        bf = os.urandom(16)
        rsa_data = rsa_oaep(logon_minimal(bf), KEY_WOT)
        body = struct.pack("<I", proto) + rsa_data
        tests.append((f"OAEP minimal proto={proto}", body, 0x01, "v32"))
    
    # ===== Try Element 0x00 with V32 (maybe 0x00 is login, 0x01 is something else) =====
    for proto in [51, 52]:
        bf = os.urandom(16)
        logon = logon_v1(bf_key=bf)
        rsa_data = rsa_oaep(logon, KEY_WOT)
        body = struct.pack("<I", proto) + rsa_data
        tests.append((f"OAEP elem=0x00 proto={proto}", body, 0x00, "v32"))
    
    # ===== Try V16 format on Element 0x01 =====
    for proto in [51, 52]:
        bf = os.urandom(16)
        logon = logon_v1(bf_key=bf)
        rsa_data = rsa_oaep(logon, KEY_WOT)
        body = struct.pack("<I", proto) + rsa_data
        tests.append((f"OAEP v16 elem=0x01 proto={proto}", body, 0x01, "v16"))
    
    # ===== Try Fixed format on Element 0x01 =====
    for proto in [51, 52]:
        bf = os.urandom(16)
        logon = logon_v1(bf_key=bf)
        rsa_data = rsa_oaep(logon, KEY_WOT)
        body = struct.pack("<I", proto) + rsa_data
        tests.append((f"OAEP fixed elem=0x01 proto={proto}", body, 0x01, "fixed"))
    
    print(f"\n[2] Testing {len(tests)} combinations...")
    found_challenge = False
    found_success = False
    
    for desc, body, elem_id, fmt in tests:
        print(f"\n  [{rid}] {desc}...")
        
        if fmt == "v32":
            pkt = build_v32_request(elem_id, rid, body)
        elif fmt == "v16":
            pkt = build_v16_request(elem_id, rid, body)
        else:
            pkt = build_fixed_request(elem_id, rid, body)
        
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            print(f"      ← {r}")
            rid += 1
            
            if r.get("type") == "CHALLENGE":
                print(f"      🎯 CHALLENGE! data={r.get('data','')[:200]}")
                with open('/tmp/wot_challenge.bin', 'wb') as f:
                    f.write(data[11:])
                found_challenge = True
                break
            elif r.get("type") == "SUCCESS":
                print(f"      🎉 SUCCESS!")
                found_success = True
                break
        except socket.timeout:
            print(f"      ❌ timeout")
            rid += 1
    
    sock.close()
    
    if found_challenge:
        print("\n🎯 GOT CHALLENGE! Next step: solve Cuckoo PoW and send ChallengeResponse")
    elif found_success:
        print("\n🎉 LOGIN SUCCESS! Next step: connect to base app")
    else:
        print("\n❌ All attempts failed. Error 0x40 persists.")
        print("   Possible causes:")
        print("   1. Server requires Cuckoo challenge BEFORE login")
        print("   2. RSA key is wrong (need real loginapp_wot.pubkey)")
        print("   3. Protocol version mismatch")
        print("   4. Need WG auth token (not guest login)")
        print("\n   Next steps:")
        print("   - Run v20 to try showroom API → get real RSA key")
        print("   - Try sending Cuckoo challenge request first")
        print("   - Try with real WG account credentials")

if __name__ == "__main__":
    # Test on all EU servers
    for server, port in [
        ("login.p1.worldoftanks.eu", 20016),
        ("login.p2.worldoftanks.eu", 20018),
    ]:
        run(server, port)
        time.sleep(1)

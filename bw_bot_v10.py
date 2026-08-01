#!/usr/bin/env python3
"""WoT Bot v10 fixed — Big-endian Mercury protocol fields"""
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
    """V32 with ALL Mercury fields in big-endian (length, request_id, next_offset)."""
    rh = struct.pack(">I", rid) + struct.pack(">H", 0)  # BE request_id + BE next
    inner = rh + body
    content = bytes([elem_id]) + struct.pack(">I", len(inner)) + inner  # BE length
    raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def build_v32_mixed(elem_id, rid, body):
    """V32 with BE length but LE request_id/next."""
    rh = struct.pack("<I", rid) + struct.pack("<H", 0)  # LE request_id + LE next
    inner = rh + body
    content = bytes([elem_id]) + struct.pack(">I", len(inner)) + inner  # BE length, LE inner
    raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def build_v32_le(elem_id, rid, body):
    """V32 with ALL Mercury fields in little-endian (control — same as v9)."""
    rh = struct.pack("<I", rid) + struct.pack("<H", 0)
    inner = rh + body
    content = bytes([elem_id]) + struct.pack("<I", len(inner)) + inner
    raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def parse_reply(data):
    if len(data) < 11:
        return {"raw": data.hex(), "error": "too short"}
    flags = struct.unpack("<H", data[4:6])[0]
    if data[6] != 0xFF:
        return {"raw": data.hex(), "error": f"not reply (0x{data[6]:02X})"}
    length = struct.unpack("<I", data[7:11])[0]
    reply_data = data[11:11+length]
    result = {"flags": f"0x{flags:04X}", "length": length, "raw_data": reply_data.hex()}
    if length >= 4:
        reply_id_le = struct.unpack("<I", reply_data[:4])[0]
        reply_id_be = struct.unpack(">I", reply_data[:4])[0]
        result["rid_LE"] = f"0x{reply_id_le:08X}"
        result["rid_BE"] = f"0x{reply_id_be:08X}"
        if length >= 5:
            status = reply_data[4]
            if status == 1: result["type"] = "SUCCESS"
            elif status == 0x42: result["type"] = "CHALLENGE"
            elif status >= 64: result["type"] = f"ERROR(0x{status:02X})"
            else: result["type"] = f"STATUS(0x{status:02X})"
            if length > 5:
                try: result["message"] = reply_data[5:].decode('utf-8', errors='replace')
                except: result["message"] = reply_data[5:].hex()
    return result

def make_logon(user="guest", pwd="", bf_key=None, nonce=0):
    if bf_key is None: bf_key = os.urandom(16)
    return struct.pack("<B", 0) + pack_str(user) + pack_str(pwd) + pack_str(bf_key) + struct.pack("<I", nonce)

def run_v10(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v10 FIXED — BE Mercury Fields — {server}:{port}")
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

    tests = []
    
    # BE Mercury fields + plain body (LE body)
    for proto in [51, 52, 55, 60]:
        bf = os.urandom(16)
        body = struct.pack("<I", proto) + make_logon(bf_key=bf)
        tests.append((f"BE fields, plain LE body, proto={proto}", build_v32_be, body))
    
    # BE Mercury fields + RSA
    for proto in [51, 52]:
        bf = os.urandom(16)
        rsa_data = rsa_encrypt(make_logon(bf_key=bf), KEY_WOT)
        body = struct.pack("<I", proto) + rsa_data
        tests.append((f"BE fields, RSA WoT, proto={proto}", build_v32_be, body))
    
    # Mixed: BE length, LE request_id
    for proto in [51, 52]:
        bf = os.urandom(16)
        body = struct.pack("<I", proto) + make_logon(bf_key=bf)
        tests.append((f"Mixed BE-len/LE-rid, plain, proto={proto}", build_v32_mixed, body))
    
    # LE fields (control — should get error 0x40)
    bf = os.urandom(16)
    body = struct.pack("<I", 51) + make_logon(bf_key=bf)
    tests.append((f"LE fields (control), plain, proto=51", build_v32_le, body))
    
    # BE everything including protocol version
    for proto in [51, 52]:
        bf = os.urandom(16)
        body = struct.pack(">I", proto) + make_logon(bf_key=bf)
        tests.append((f"BE everything, plain, proto={proto}", build_v32_be, body))

    for desc, builder, body in tests:
        print(f"\n[2] {desc} (rid={rid})...")
        pkt = builder(0x01, rid, body)
        print(f"    → {len(pkt)}B")
        sock.sendto(pkt, (server, port))
        try:
            data, addr = sock.recvfrom(4096)
            r = parse_reply(data)
            print(f"    ← {r}")
            rid += 1
            if r.get("type") in ("CHALLENGE", "SUCCESS"):
                print(f"    🎯 {r['type']}!")
                break
        except socket.timeout:
            print(f"    ❌ Timeout")
            rid += 1

    sock.close()

if __name__ == "__main__":
    run_v10()

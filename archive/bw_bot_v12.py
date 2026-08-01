#!/usr/bin/env python3
"""WoT Bot v12 — Find correct LogOnParams format with WoT RSA key.

Key findings:
- BE Mercury fields confirmed
- Element ID 0x01, V32 confirmed  
- Proto 50-51 valid (0x40 = malformed, not bad version)
- WoT RSA key gives 0x40 (not 0x41) for proto=53 → key is correct!
- 0x40 = "LogOnParams malformed", 0x41 = "bad version" or "RSA failed"

Now: try different LogOnParams formats with RSA WoT key:
1. C++ format: flags + username + password + encKey + nonce
2. Rust format: encrypted_flag + flags + username + password + bf_key + context + nonce
3. With/without context field
4. With/without digest
5. Different string encodings (packed_int vs u16)
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

def pack_int(n):
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[1:]
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_int(len(b)) + b

def pack_str_u16(s):
    """String with u16 length prefix (old format)."""
    b = s.encode() if isinstance(s, str) else s
    return struct.pack("<H", len(b)) + b

def rsa_encrypt(plaintext, pem_key=KEY_WOT):
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
        if status == 1: r["type"] = "SUCCESS"
        elif status == 0x42: r["type"] = "CHALLENGE"
        elif status >= 64: r["type"] = f"ERR(0x{status:02X})"
        else: r["type"] = f"OK(0x{status:02X})"
        r["rid"] = f"0x{rid_be:08X}" if rid_be != 0xFFFFFFFF else "0xFFFFFFFF"
        if length > 5:
            try: r["msg"] = rd[5:].decode('utf-8', errors='replace')[:200]
            except: pass
    return r

def run_v12(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v12 — LogOnParams Format — {server}:{port}")
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
    
    # All tests use proto=50 (confirmed valid) + RSA WoT key
    proto = 50
    
    # Format 1: C++ plain LogOnParams (packed_int strings, no context, no encrypted flag)
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
    body = struct.pack("<I", proto) + rsa_encrypt(logon)
    tests.append(("C++ fmt: flags+user+pwd+key+nonce (packed_int)", body))
    
    # Format 2: Rust format (encrypted=true flag + flags+user+pwd+key+context+nonce)
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + pack_str("guest") + struct.pack("<I", 0)
    body = struct.pack("<I", proto) + struct.pack("<B", 1) + rsa_encrypt(logon)  # encrypted=true
    tests.append(("Rust fmt: enc=true+flags+user+pwd+key+ctx+nonce", body))
    
    # Format 3: Rust format (encrypted=false flag, plain LogOnParams)
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + pack_str("guest") + struct.pack("<I", 0)
    body = struct.pack("<I", proto) + struct.pack("<B", 0) + logon  # encrypted=false, plain
    tests.append(("Rust fmt: enc=false+flags+user+pwd+key+ctx+nonce", body))
    
    # Format 4: C++ with u16 strings (old format)
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str_u16("guest") + pack_str_u16("") + pack_str_u16(bf) + struct.pack("<I", 0)
    body = struct.pack("<I", proto) + rsa_encrypt(logon)
    tests.append(("C++ fmt u16 strings: flags+user+pwd+key+nonce", body))
    
    # Format 5: C++ with digest
    bf = os.urandom(16)
    digest = os.urandom(16)
    logon = struct.pack("<B", 1) + pack_str("guest") + pack_str("") + pack_str(bf) + digest + struct.pack("<I", 0)
    body = struct.pack("<I", proto) + rsa_encrypt(logon)
    tests.append(("C++ fmt+digest: flags(1)+user+pwd+key+digest+nonce", body))
    
    # Format 6: C++ with nonce
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 12345)
    body = struct.pack("<I", proto) + rsa_encrypt(logon)
    tests.append(("C++ fmt+nonce=12345", body))
    
    # Format 7: No RSA, just plain (encrypted=false, Rust format with context)
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + pack_str("guest") + struct.pack("<I", 0)
    body = struct.pack("<I", proto) + struct.pack("<B", 0) + logon
    tests.append(("No RSA, enc=false, Rust fmt with context", body))
    
    # Format 8: Just version, no LogOnParams (test if server reads version first)
    body = struct.pack("<I", proto)
    tests.append(("Just protocol version, no LogOnParams", body))
    
    # Format 9: RSA with empty LogOnParams
    body = struct.pack("<I", proto) + rsa_encrypt(b"")
    tests.append(("RSA with empty LogOnParams", body))
    
    # Format 10: RSA with just username
    bf = os.urandom(16)
    logon = pack_str("guest")
    body = struct.pack("<I", proto) + rsa_encrypt(logon)
    tests.append(("RSA with just username string", body))

    # Format 11: proto=51 with RSA WoT (confirmed valid version)
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
    body = struct.pack("<I", 51) + rsa_encrypt(logon)
    tests.append(("proto=51, C++ fmt RSA WoT", body))
    
    # Format 12: proto=69 with RSA WoT (anomaly — also gave 0x40)
    bf = os.urandom(16)
    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
    body = struct.pack("<I", 69) + rsa_encrypt(logon)
    tests.append(("proto=69, C++ fmt RSA WoT", body))

    for desc, body in tests:
        print(f"\n[{rid}] {desc}...")
        pkt = build_v32_be(0x01, rid, body)
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            marker = "🎯" if r.get("type") not in ("ERR(0x40)", "ERR(0x41)") else "  "
            print(f"   {marker} {r}")
            rid += 1
            if r.get("type") in ("SUCCESS", "CHALLENGE"):
                print(f"   🎯🎯🎯 BREAKTHROUGH!")
                break
        except socket.timeout:
            print(f"   ❌ Timeout")
            rid += 1

    sock.close()

if __name__ == "__main__":
    run_v12()

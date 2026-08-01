#!/usr/bin/env python3
"""WoT Bot v21 — FIXED: Uses v3's exact packet format (which had WORKING PING)

Bugs in v20 that broke PING:
1. _prefix function was completely wrong (xorshift vs v3's bit manipulation)
2. HAS_REQUESTS flag was 0x0002 (should be 0x0001)
3. Login element was 0x01 V32 (v3 uses 0x00 V16)

v21 uses v3's exact packet code via exec(), then tests:
- PING (should work like v3/v8/v9/v10)
- Login with Element 0x00 V16 (v3 format, no RSA)
- Login with Element 0x01 V32 (v8 format, with RSA)
- Login with Element 0x00 V16 + RSA (combination)
"""
import socket, struct, os, sys, time

# Import v3's EXACT packet building code
exec(open('/root/wot-grinder-bot-v8/bw_bot_v3.py' if os.path.exists('/root/wot-grinder-bot-v8/bw_bot_v3.py') else '/tmp/bw_bot_v3.py').read().split('def run(')[0])

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA1, SHA256

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
    return PKCS1_OAEP.new(key, hashAlgo=hash_algo).encrypt(plaintext)

def rsa_pkcs1v15(plaintext, pem):
    key = RSA.importKey(pem)
    return PKCS1_v1_5.new(key).encrypt(plaintext)

def parse_reply(data):
    if len(data) < 6: return {"error": "too short", "raw": data.hex()}
    prefix = struct.unpack_from("<I", data, 0)[0]
    flags = struct.unpack_from("<H", data, 4)[0]
    content = data[6:]
    
    r = {"len": len(data), "prefix": f"{prefix:08x}", "flags": f"{flags:04x}",
         "flag_names": [n for n, v in FLAGS.items() if flags & v]}
    
    if flags & FLAGS['HAS_CHECKSUM']:
        if len(content) >= 4: content = content[:-4]
    if flags & FLAGS['INDEXED_CHANNEL']:
        if len(content) >= 8: content = content[8:]
    if flags & FLAGS['HAS_CUMULATIVE_ACK']:
        if len(content) >= 2: content = content[2:]
    
    if not (flags & FLAGS['HAS_REQUESTS']):
        r["type"] = "no_requests"
        r["content"] = content.hex()[:200]
        return r
    
    pos = 0
    requests = []
    while pos < len(content):
        if pos >= len(content): break
        elem_id = content[pos]; pos += 1
        
        if elem_id == 0xFF:
            r["reply"] = True
            if pos + 4 <= len(content):
                length = struct.unpack_from("<I", content, pos)[0]; pos += 4
                rdata = content[pos:pos+length]; pos += length
                if len(rdata) >= 4:
                    rid = struct.unpack_from("<I", rdata, 0)[0]
                    r["reply_id"] = f"0x{rid:08X}"
                    if len(rdata) >= 5:
                        status = rdata[4]
                        if status == 1: r["type"] = "SUCCESS"
                        elif status == 0x42: r["type"] = "CHALLENGE"
                        elif status >= 64: r["type"] = f"ERROR(0x{status:02X})"
                        else: r["type"] = f"STATUS(0x{status:02X})"
                        if len(rdata) > 5:
                            r["data"] = rdata[5:].hex()[:200]
                            try: r["msg"] = rdata[5:].decode('utf-8', errors='replace')[:200]
                            except: pass
            break
        elif elem_id < 0x80:
            # Variable16
            if pos + 2 > len(content): break
            length = struct.unpack_from("<H", content, pos)[0]; pos += 2
            rdata = content[pos:pos+length]; pos += length
            requests.append({"elem": f"0x{elem_id:02X}", "len": length})
        elif elem_id < 0xC0:
            # Variable32
            if pos + 4 > len(content): break
            length = struct.unpack_from("<I", content, pos)[0]; pos += 4
            rdata = content[pos:pos+length]; pos += length
            requests.append({"elem": f"0x{elem_id:02X}", "len": length})
        else:
            # Fixed
            requests.append({"elem": f"0x{elem_id:02X}", "type": "fixed"})
            break
    
    if requests:
        r["requests"] = requests
    return r

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v21 — FIXED packet format — {server}:{port}")
    print(f"{'='*55}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1
    
    # PING — use v3's exact ping_packet function
    print(f"\n[1] PING (rid={rid}) using v3 ping_packet()...")
    pkt = ping_packet(rid=rid, num=0)
    print(f"    -> {len(pkt)}B: {pkt.hex()}")
    sock.sendto(pkt, (server, port))
    try:
        data, _ = sock.recvfrom(4096)
        print(f"    <- {len(data)}B: {data.hex()}")
        r = parse_reply(data)
        print(f"    PING OK! {r}")
        rid += 1
    except socket.timeout:
        print(f"    PING TIMEOUT")
        # Try p2
        print(f"\n    Trying p2...")
        sock.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        pkt = ping_packet(rid=rid, num=0)
        sock.sendto(pkt, ("login.p2.worldoftanks.eu", 20018))
        try:
            data, _ = sock.recvfrom(4096)
            print(f"    p2 PING OK! {len(data)}B")
            server = "login.p2.worldoftanks.eu"
            port = 20018
            rid += 1
        except socket.timeout:
            print(f"    p2 also timed out — waiting 5s and retrying p1...")
            time.sleep(5)
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            pkt = ping_packet(rid=rid, num=0)
            sock.sendto(pkt, (server, port))
            try:
                data, _ = sock.recvfrom(4096)
                print(f"    retry PING OK! {len(data)}B")
                rid += 1
            except socket.timeout:
                print(f"    All PING attempts failed — IP may be rate-limited")
                print(f"    Wait 5-10 min and retry")
                sock.close()
                return
    
    # Test 1: v3's exact login_packet (Element 0x00, V16, no RSA)
    print(f"\n[2] v3 login_packet (Element 0x00, V16, no RSA)...")
    for proto in [0x0144, 51, 52, 55, 72]:
        pkt, bf_key = login_packet(rid, protocol=proto)
        print(f"  [{rid}] proto=0x{proto:04X} -> {len(pkt)}B")
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            print(f"      <- {r}")
            rid += 1
            if r.get("type") == "CHALLENGE":
                print(f"      CHALLENGE! data={r.get('data','')}")
                with open('/tmp/wot_challenge.bin', 'wb') as f: f.write(data)
                break
            elif r.get("type") == "SUCCESS":
                print(f"      SUCCESS!")
                break
        except socket.timeout:
            print(f"      timeout")
            rid += 1
    
    # Test 2: Element 0x01, V32 (v8 format that got error 0x40)
    # with RSA encryption
    print(f"\n[3] Element 0x01 V32 with RSA (v8 format)...")
    
    def build_v32_le(elem_id, rid, body):
        """V32 with LE fields — same as v10's build_v32_le."""
        rh = struct.pack("<I", rid) + struct.pack("<H", 0)
        inner = rh + body
        content = bytes([elem_id]) + struct.pack("<I", len(inner)) + inner
        raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
        return struct.pack("<I", _prefix(raw)) + raw[4:]
    
    def build_v32_be(elem_id, rid, body):
        """V32 with BE Mercury fields."""
        rh = struct.pack(">I", rid) + struct.pack(">H", 0)
        inner = rh + body
        content = bytes([elem_id]) + struct.pack(">I", len(inner)) + inner
        raw = struct.pack("<IH", 0, FLAGS['HAS_REQUESTS']) + content + struct.pack("<H", 2)
        return struct.pack("<I", _prefix(raw)) + raw[4:]
    
    for proto in [51, 52, 55]:
        for desc, body in [
            (f"RSA-OAEP WoT proto={proto}", struct.pack("<I", proto) + rsa_oaep(login_packet(rid, protocol=proto)[1].__class__() if False else os.urandom(40), KEY_WOT)),
        ]:
            # Actually, let's build the logon params properly
            bf = os.urandom(16)
            # v3-style params but for V32
            logon = struct.pack("<IBB", proto, 0, 0)
            logon += struct.pack("<H", 4) + b"guest"
            logon += struct.pack("<H", 0)
            logon += struct.pack("<H", 16) + bf
            logon += struct.pack("<H", 5) + b"guest"
            logon += struct.pack("<I", 0)
            
            for key_name, key, enc_fn in [
                ("OAEP WoT", KEY_WOT, lambda p: rsa_oaep(p, KEY_WOT)),
                ("OAEP BW", KEY_BW, lambda p: rsa_oaep(p, KEY_BW)),
                ("PKCS1v15 WoT", KEY_WOT, lambda p: rsa_pkcs1v15(p, KEY_WOT)),
            ]:
                rsa_data = enc_fn(logon)
                body = struct.pack("<I", proto) + rsa_data
                
                for fmt_name, build_fn in [("V32-LE", build_v32_le), ("V32-BE", build_v32_be)]:
                    pkt = build_fn(0x01, rid, body)
                    print(f"  [{rid}] {key_name} {fmt_name} proto={proto} -> {len(pkt)}B")
                    sock.sendto(pkt, (server, port))
                    try:
                        data, _ = sock.recvfrom(4096)
                        r = parse_reply(data)
                        print(f"      <- {r}")
                        rid += 1
                        if r.get("type") == "CHALLENGE":
                            print(f"      CHALLENGE!")
                            break
                        elif r.get("type") == "SUCCESS":
                            print(f"      SUCCESS!")
                            break
                    except socket.timeout:
                        print(f"      timeout")
                        rid += 1
    
    # Test 3: Proto-only on Element 0x01 V32 (might trigger challenge)
    print(f"\n[4] Proto-only on Element 0x01 V32...")
    for proto in [51, 52, 55, 72]:
        body = struct.pack("<I", proto)
        pkt = build_v32_le(0x01, rid, body)
        print(f"  [{rid}] proto={proto} -> {len(pkt)}B")
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            print(f"      <- {r}")
            rid += 1
            if r.get("type") == "CHALLENGE":
                print(f"      CHALLENGE!")
                break
        except socket.timeout:
            print(f"      timeout")
            rid += 1
    
    sock.close()
    print("\nDone!")

if __name__ == "__main__":
    run()

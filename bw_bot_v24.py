#!/usr/bin/env python3
"""WoT Bot v24 — THE FIX: length field = body ONLY (not rid+next+body)

ROOT CAUSE of 20h failure: v3's _request_elem puts rid+next INSIDE the
length field. wg-toolkit-rs confirms length = body only.

v3:  [elem_id][len(rid+next+body)] [rid] [next] [body]  ← WRONG
v24: [elem_id][len(body)]         [rid] [next] [body]  ← CORRECT

This 6-byte offset corrupted EVERY packet. Server read 6 extra bytes
from rid/next as part of the body → MalformedRequest (0x40).
"""
import socket, struct, os, sys, time

# Import v3's _prefix, FLAGS, _pkt, ping_packet
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
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[:3]
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_u24(len(b)) + b

def build_element_v16(elem_id, rid, body):
    """FIXED: length = body ONLY, rid+next come AFTER length.
    
    [elem_id(1B)] [body_len(2B LE)] [rid(4B LE)] [next(2B LE)] [body]
    """
    header = struct.pack("<BH", elem_id, len(body))  # length = body only!
    request_header = struct.pack("<IH", rid, 0)     # rid + next
    return header + request_header + body

def build_element_v32(elem_id, rid, body):
    """FIXED: length = body ONLY for V32.
    
    [elem_id(1B)] [body_len(4B LE)] [rid(4B LE)] [next(2B LE)] [body]
    """
    header = struct.pack("<BI", elem_id, len(body))  # length = body only!
    request_header = struct.pack("<IH", rid, 0)
    return header + request_header + body

def make_pkt(content, first_req=0):
    """Build packet with v3's _pkt."""
    return _pkt(content, first_req=first_req)

def build_logon(user="guest", pwd="", bf_key=None, ctx="guest", nonce=0, has_digest=False):
    if bf_key is None: bf_key = os.urandom(16)
    p = struct.pack("<B", 0x01 if has_digest else 0x00)
    p += pack_str(user)
    p += pack_str(pwd)
    p += pack_str(bf_key)
    p += pack_str(ctx)
    if has_digest: p += os.urandom(16)
    p += struct.pack("<I", nonce)
    return p

def parse_reply(data):
    if len(data) < 6: return {"error": "short", "raw": data.hex()}
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
    print(f"  WoT Bot v24 — FIXED length field (body only)")
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
            print(f"    p2 PING OK"); rid += 1
        except socket.timeout:
            print(f"    All PING failed"); sock.close(); return
    
    tests = []
    
    # ===== Element 0x00 V16 — FIXED length (body only) =====
    for proto in [50, 51, 52, 55, 324]:
        for encrypted, key_name, key_pem in [(False, "plain", None), (True, "WoT", KEY_WOT), (True, "BW", KEY_BW)]:
            bf = os.urandom(16)
            logon = build_logon(user="guest", pwd="", bf_key=bf, ctx="guest")
            if encrypted:
                payload = rsa_oaep(logon, key_pem)
            else:
                payload = logon
            body = struct.pack("<I", proto) + struct.pack("<B", 1 if encrypted else 0) + payload
            elem = build_element_v16(0x00, rid, body)
            pkt = make_pkt(elem)
            tests.append((f"V16 elem=0x00 {key_name} proto={proto}", pkt))
    
    # ===== Element 0x01 V32 — FIXED length (body only) =====
    for proto in [50, 51, 52, 55]:
        for encrypted, key_name, key_pem in [(False, "plain", None), (True, "WoT", KEY_WOT)]:
            bf = os.urandom(16)
            logon = build_logon(user="guest", pwd="", bf_key=bf, ctx="guest")
            if encrypted:
                payload = rsa_oaep(logon, key_pem)
            else:
                payload = logon
            body = struct.pack("<I", proto) + struct.pack("<B", 1 if encrypted else 0) + payload
            elem = build_element_v32(0x01, rid, body)
            pkt = make_pkt(elem)
            tests.append((f"V32 elem=0x01 {key_name} proto={proto}", pkt))
    
    # ===== Element 0x00 V16 — no context =====
    for proto in [50, 51, 52]:
        bf = os.urandom(16)
        logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
        body = struct.pack("<I", proto) + struct.pack("<B", 0) + logon
        elem = build_element_v16(0x00, rid, body)
        pkt = make_pkt(elem)
        tests.append((f"V16 elem=0x00 plain no-ctx proto={proto}", pkt))
    
    # ===== Element 0x01 V16 — also try (maybe 0x01 uses V16 too) =====
    for proto in [50, 51, 52]:
        bf = os.urandom(16)
        logon = build_logon(user="guest", pwd="", bf_key=bf, ctx="guest")
        body = struct.pack("<I", proto) + struct.pack("<B", 0) + logon
        elem = build_element_v16(0x01, rid, body)
        pkt = make_pkt(elem)
        tests.append((f"V16 elem=0x01 plain proto={proto}", pkt))
    
    # ===== Element 0x00 V32 — also try (maybe 0x00 uses V32) =====
    for proto in [50, 51, 52]:
        bf = os.urandom(16)
        logon = build_logon(user="guest", pwd="", bf_key=bf, ctx="guest")
        body = struct.pack("<I", proto) + struct.pack("<B", 0) + logon
        elem = build_element_v32(0x00, rid, body)
        pkt = make_pkt(elem)
        tests.append((f"V32 elem=0x00 plain proto={proto}", pkt))
    
    print(f"\n[2] Testing {len(tests)} combinations with FIXED length...")
    for desc, pkt in tests:
        print(f"\n  [{rid}] {desc}...")
        print(f"      -> {len(pkt)}B")
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

#!/usr/bin/env python3
"""WoT Bot v25 — DEFINITIVE VERSION

Root cause found after 20h: v3's _request_elem put rid+next INSIDE the
length field (length = rid+next+body). Server reads length, then reads
rid+next SEPARATELY, then reads 'length' bytes for body. With 6 extra
bytes in length, server reads past body into footer → corruption → 0x40.

Server-side reading code (wg-toolkit-rs bundle.rs):
  1. read element_id (1B)
  2. read length field → elt_len (body ONLY)
  3. if request: read rid (4B) + next (2B)  ← SEPARATE from length!
  4. read body (elt_len bytes)

FIX: length = len(body) only, not len(rid+next+body).

Also confirmed:
  - LOGIN_REQUEST = Element 0x00, Variable16 (from wg-toolkit-rs)
  - Body = [protocol(4B LE)] + [encrypted_flag(1B)] + [LogOnParams]
  - LogOnParams = [flags(1B)] + [user(packed_str)] + [pwd(packed_str)] + 
                  [bf_key(packed_str)] + [ctx(packed_str)] + [nonce(4B LE)]
  - packed_str = packed_u24(len) + data (1B for <255, 0xFF+3B for >=255)
  - RSA = OAEP-SHA1
  - Footer = first_request_offset + 2 (matches v3, confirmed by wg-toolkit-rs)
  - Flags = 0x0001 (HAS_REQUESTS, confirmed by v3 PING working)
  - Prefix = v3's _prefix function (confirmed by PING working)
"""
import socket, struct, os, sys, time

# Import v3's _prefix, FLAGS, _pkt, ping_packet (all confirmed correct by PING)
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
    """packed_u24: 1 byte for <255, 0xFF + 3 bytes for >=255. Confirmed by wg-toolkit-rs."""
    if n >= 255:
        return struct.pack("<B", 0xFF) + struct.pack("<I", n)[:3]
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_u24(len(b)) + b

def build_element_v16(elem_id, rid, body):
    """V16 request element with CORRECT length = body ONLY.
    
    [elem_id(1B)] [body_len(2B LE)] [rid(4B LE)] [next(2B LE)] [body]
    
    Server reads: elem_id, then body_len, then rid, then next, then body_len bytes of body.
    """
    return struct.pack("<BH", elem_id, len(body)) + struct.pack("<IH", rid, 0) + body

def build_element_v32(elem_id, rid, body):
    """V32 request element with CORRECT length = body ONLY."""
    return struct.pack("<BI", elem_id, len(body)) + struct.pack("<IH", rid, 0) + body

def make_packet(content, first_req=0):
    """Build packet with v3's _pkt (confirmed correct by PING)."""
    return _pkt(content, first_req=first_req)

def build_logon(user="guest", pwd="", bf_key=None, ctx="guest", nonce=0):
    """LogOnParams exactly as wg-toolkit-rs write_login_request.
    
    [flags(1B=0)] + [user(packed_str)] + [pwd(packed_str)] + [bf_key(packed_str)] + [ctx(packed_str)] + [nonce(4B LE)]
    """
    if bf_key is None:
        bf_key = os.urandom(16)
    p = struct.pack("<B", 0)  # flags = 0 (no digest)
    p += pack_str(user)
    p += pack_str(pwd)
    p += pack_str(bf_key)
    p += pack_str(ctx)
    p += struct.pack("<I", nonce)
    return p

def build_login_body(protocol, encrypted, logon_params, rsa_key_pem=None):
    """Login body: [protocol(4B LE)] + [encrypted_flag(1B bool)] + [LogOnParams or RSA(LogOnParams)]"""
    if encrypted and rsa_key_pem:
        payload = rsa_oaep(logon_params, rsa_key_pem)
    else:
        payload = logon_params
    return struct.pack("<I", protocol) + struct.pack("<B", 1 if encrypted else 0) + payload

def parse_reply(data):
    if len(data) < 6:
        return {"error": "short", "raw": data.hex()}
    prefix = struct.unpack_from("<I", data, 0)[0]
    flags = struct.unpack_from("<H", data, 4)[0]
    content = data[6:]
    r = {"prefix": f"{prefix:08x}", "flags": f"{flags:04x}"}
    
    # Strip footer fields based on flags
    if flags & FLAGS.get('HAS_CHECKSUM', 0) and len(content) >= 4: content = content[:-4]
    if flags & FLAGS.get('INDEXED_CHANNEL', 0) and len(content) >= 8: content = content[8:]
    if flags & FLAGS.get('HAS_CUMULATIVE_ACK', 0) and len(content) >= 2: content = content[2:]
    
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
    print(f"\n{'='*60}")
    print(f"  WoT Bot v25 — DEFINITIVE (fixed length field)")
    print(f"  {server}:{port}")
    print(f"{'='*60}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1
    
    # PING — confirm connectivity
    print(f"\n[1] PING...")
    sock.sendto(ping_packet(rid=rid), (server, port))
    try:
        data, _ = sock.recvfrom(4096)
        print(f"    PING OK ({len(data)}B)")
        rid += 1
    except socket.timeout:
        print(f"    PING timeout — trying p2/p3...")
        for s, p in [("login.p2.worldoftanks.eu", 20018), ("login.p3.worldoftanks.eu", 20020)]:
            sock.close()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(ping_packet(rid=rid), (s, p))
            try:
                data, _ = sock.recvfrom(4096)
                print(f"    {s} PING OK")
                server, port = s, p
                rid += 1
                break
            except socket.timeout:
                print(f"    {s} timeout")
        else:
            print(f"    All PING failed")
            sock.close(); return
    
    tests = []
    
    # ===== Element 0x00 V16 (LOGIN_REQUEST, confirmed by wg-toolkit-rs) =====
    
    # Plaintext (no RSA) — server might accept this if encryption is optional
    for proto in [50, 51, 52, 55, 324]:
        bf = os.urandom(16)
        logon = build_logon(user="guest", pwd="", bf_key=bf, ctx="guest")
        body = build_login_body(proto, encrypted=False, logon_params=logon)
        elem = build_element_v16(0x00, rid, body)
        pkt = make_packet(elem)
        tests.append((f"E0x00 V16 plain proto={proto} ctx=guest", pkt))
    
    # RSA with WoT key
    for proto in [50, 51, 52, 55]:
        bf = os.urandom(16)
        logon = build_logon(user="guest", pwd="", bf_key=bf, ctx="guest")
        body = build_login_body(proto, encrypted=True, logon_params=logon, rsa_key_pem=KEY_WOT)
        elem = build_element_v16(0x00, rid, body)
        pkt = make_packet(elem)
        tests.append((f"E0x00 V16 RSA-WoT proto={proto} ctx=guest", pkt))
    
    # RSA with BW key
    for proto in [50, 51, 52]:
        bf = os.urandom(16)
        logon = build_logon(user="guest", pwd="", bf_key=bf, ctx="guest")
        body = build_login_body(proto, encrypted=True, logon_params=logon, rsa_key_pem=KEY_BW)
        elem = build_element_v16(0x00, rid, body)
        pkt = make_packet(elem)
        tests.append((f"E0x00 V16 RSA-BW proto={proto} ctx=guest", pkt))
    
    # Plaintext without context
    for proto in [50, 51, 52]:
        bf = os.urandom(16)
        logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
        body = build_login_body(proto, encrypted=False, logon_params=logon)
        elem = build_element_v16(0x00, rid, body)
        pkt = make_packet(elem)
        tests.append((f"E0x00 V16 plain proto={proto} no-ctx", pkt))
    
    # RSA without context
    for proto in [50, 51, 52]:
        bf = os.urandom(16)
        logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
        body = build_login_body(proto, encrypted=True, logon_params=logon, rsa_key_pem=KEY_WOT)
        elem = build_element_v16(0x00, rid, body)
        pkt = make_packet(elem)
        tests.append((f"E0x00 V16 RSA-WoT proto={proto} no-ctx", pkt))
    
    # ===== Element 0x01 V32 (in case WoT uses 0x01 instead of 0x00) =====
    
    for proto in [50, 51, 52]:
        for enc, kn, kp in [(False, "plain", None), (True, "WoT", KEY_WOT)]:
            bf = os.urandom(16)
            logon = build_logon(user="guest", pwd="", bf_key=bf, ctx="guest")
            body = build_login_body(proto, encrypted=enc, logon_params=logon, rsa_key_pem=kp)
            elem = build_element_v32(0x01, rid, body)
            pkt = make_packet(elem)
            tests.append((f"E0x01 V32 {kn} proto={proto} ctx=guest", pkt))
    
    # ===== Element 0x00 V32 (in case WoT uses V32 for element 0x00) =====
    
    for proto in [50, 51, 52]:
        bf = os.urandom(16)
        logon = build_logon(user="guest", pwd="", bf_key=bf, ctx="guest")
        body = build_login_body(proto, encrypted=False, logon_params=logon)
        elem = build_element_v32(0x00, rid, body)
        pkt = make_packet(elem)
        tests.append((f"E0x00 V32 plain proto={proto} ctx=guest", pkt))
    
    print(f"\n[2] Testing {len(tests)} combinations with FIXED length field...")
    print(f"    (length = body ONLY, not rid+next+body)")
    
    for desc, pkt in tests:
        print(f"\n  [{rid}] {desc}...")
        print(f"      -> {len(pkt)}B: {pkt[:40].hex()}")
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            print(f"      <- {r}")
            rid += 1
            if r.get("type") == "CHALLENGE":
                print(f"\n      *** CHALLENGE RECEIVED! ***")
                print(f"      data={r.get('data','')}")
                with open('/tmp/wot_challenge.bin', 'wb') as f:
                    f.write(data)
                print(f"      Challenge saved to /tmp/wot_challenge.bin")
                print(f"      Next step: solve Cuckoo PoW and send ChallengeResponse")
                break
            elif r.get("type") == "SUCCESS":
                print(f"\n      *** LOGIN SUCCESS! ***")
                print(f"      data={r.get('data','')}")
                break
        except socket.timeout:
            print(f"      timeout")
            rid += 1
    
    sock.close()
    print(f"\n{'='*60}")
    print("Done. Check results above.")
    print("  CHALLENGE = server accepted login, need Cuckoo PoW")
    print("  SUCCESS = fully logged in!")
    print("  ERROR(0x40) = MalformedRequest (payload still wrong)")
    print("  ERROR(0x41) = BadProtocolVersion (version field wrong)")
    print("  timeout = element ID or format not recognized")

if __name__ == "__main__":
    run()

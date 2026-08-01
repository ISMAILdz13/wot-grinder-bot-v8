#!/usr/bin/env python3
"""WoT Bot v20c — Cuckoo challenge flow + WG auth token login

Hypothesis: Error 0x40 means server requires Cuckoo PoW BEFORE login.
The flow might be:
1. Send "challenge request" (Element 0x01, no RSA, just protocol version)
2. Server responds with Cuckoo challenge (status 0x42 = 'B')
3. Solve Cuckoo PoW (SipHash-2-4 based)
4. Send ChallengeResponse with solution
5. Send LoginRequest with RSA-encrypted LogOnParams

Also tries: WG auth token as username (from Keccak-512 POW login)
"""
import socket, struct, os, sys, time, hashlib

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1, keccak

# BigWorld protocol helpers
FLAG_HAS_REQUESTS = 0x0002

def xorshift32_transform(data):
    val = 0
    for b in data:
        val ^= b; val = (val * 0x100) & 0xFFFFFFFF; val = (val + b) & 0xFFFFFFFF
    return struct.pack("<I", val)

def _prefix(raw): return xorshift32_transform(raw[4:])

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
            if length > 5: result["data"] = rdata[5:].hex()
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

def rsa_oaep(plaintext, pem):
    key = RSA.importKey(pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    return cipher.encrypt(plaintext)

# ============================================================
# SipHash-2-4 + Cuckoo solver (from v2)
# ============================================================
def siphash24(data, key):
    """SipHash-2-4 implementation."""
    def rotl(x, b): return ((x << b) | (x >> (64 - b))) & 0xFFFFFFFFFFFFFFFF
    def sipround(v0, v1, v2, v3):
        v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32)
        v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF; v3 = rotl(v3, 16); v3 ^= v2
        v0 = (v0 + v3) & 0xFFFFFFFFFFFFFFFF; v3 = rotl(v3, 21); v3 ^= v0
        v2 = (v2 + v1) & 0xFFFFFFFFFFFFFFFF; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32)
        return v0, v1, v2, v3
    
    k0 = struct.unpack("<Q", key[:8])[0]
    k1 = struct.unpack("<Q", key[8:])[0]
    v0 = k0 ^ 0x736f6d6570736575
    v1 = k1 ^ 0x646f72616e646f6d
    v2 = k0 ^ 0x6c7967656e657261
    v3 = k1 ^ 0x7465646279746573
    
    # Process blocks
    pos = 0
    while pos + 8 <= len(data):
        m = struct.unpack("<Q", data[pos:pos+8])[0]
        v3 ^= m
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
        v0 ^= m
        pos += 8
    
    # Last block with padding
    remaining = data[pos:]
    last = len(data) & 0xFF
    last_block = remaining + b'\x00' * (7 - len(remaining)) + bytes([last])
    m = struct.unpack("<Q", last_block)[0]
    v3 ^= m
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0 ^= m
    
    # Finalization
    v2 ^= 0xFF
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
    return (v0 ^ v1 ^ v2 ^ v3) & 0xFFFFFFFFFFFFFFFF

def solve_cuckoo(challenge_key, max_nonce=100000):
    """Simple Cuckoo solver — find nonce where SipHash starts with enough zeros."""
    # The challenge defines the difficulty and key
    # For now, just find a nonce that produces a hash with leading zeros
    for nonce in range(max_nonce):
        h = siphash24(struct.pack("<I", nonce), challenge_key[:16])
        if h == 0 or (h & 0xFFFFFFFF00000000) == 0:  # Top 32 bits zero
            return nonce
    return None

# ============================================================
# WG Login (Keccak-512 POW)
# ============================================================
def wg_login(email, password):
    """Login to Wargaming via Keccak-512 POW flow."""
    import urllib.request, urllib.parse, http.cookiejar, ssl
    
    print(f"\n[WG LOGIN] Logging in as {email}...")
    
    ctx = ssl.create_default_context()
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
    
    # Step 1: Get settings (set CSRF cookie)
    settings_url = "https://eu.wargaming.net/id/api/v2/settings/"
    try:
        opener.open(urllib.request.Request(settings_url), timeout=10)
    except Exception as e:
        print(f"  Settings: {e}")
        return None
    
    csrf = None
    for cookie in cookies:
        if 'csrftoken' in cookie.name.lower():
            csrf = cookie.value
            break
    
    if not csrf:
        print("  ❌ No CSRF token")
        return None
    print(f"  CSRF: {csrf[:20]}...")
    
    # Step 2: Get challenge
    challenge_url = f"https://eu.wargaming.net/id/signin/challenge/?feature=authentication_basic&type=pow"
    try:
        resp = opener.open(urllib.request.Request(challenge_url), timeout=10)
        challenge_data = json.loads(resp.read())
    except Exception as e:
        print(f"  Challenge: {e}")
        return None
    
    stamp = challenge_data.get('stamp', '')
    complexity = challenge_data.get('complexity', 3)
    print(f"  Stamp: {stamp[:30]}..., Complexity: {complexity}")
    
    # Step 3: Solve Keccak-512 POW
    target_zeros = complexity
    for counter in range(100000):
        data = f"{stamp}:{counter}"
        h = keccak.new(digest_bits=512, data=data.encode()).digest()
        leading_zeros = 0
        for byte in h:
            if byte == 0:
                leading_zeros += 8
            else:
                leading_zeros += bin(byte).count('0', 0, 1)
                if byte & 0x80: break
                if byte & 0x40: break
                if byte & 0x20: break
                if byte & 0x10: break
                if byte & 0x08: break
                if byte & 0x04: break
                if byte & 0x02: break
                if byte & 0x01: break
                leading_zeros = 64
                break
            if leading_zeros >= target_zeros:
                break
        
        # Simpler: just check if hex starts with N zeros
        hex_h = h.hex()
        if hex_h[:target_zeros] == '0' * target_zeros:
            print(f"  ✅ POW solved! counter={counter}")
            pow_value = data
            break
    else:
        print("  ❌ POW failed")
        return None
    
    # Step 4: Submit login
    login_url = "https://eu.wargaming.net/id/signin/process/?type=pow"
    post_data = urllib.parse.urlencode({
        'login': email,
        'password': password,
        'remember': 'on',
        'pow': pow_value,
    }).encode()
    
    req = urllib.request.Request(login_url, data=post_data, headers={
        'X-CSRFToken': csrf,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': 'https://eu.wargaming.net/id/signin/'
    })
    
    try:
        resp = opener.open(req, timeout=10)
        result = json.loads(resp.read())
        status_url = result.get('status_url', '')
        print(f"  Status URL: {status_url}")
        
        # Poll for auth completion
        for _ in range(10):
            time.sleep(1)
            try:
                resp2 = opener.open(status_url, timeout=10)
                status = json.loads(resp2.read())
                if status.get('status') == 'ok':
                    print(f"  ✅ Login successful!")
                    return status
                elif status.get('status') == 'error':
                    print(f"  ❌ Login error: {status}")
                    return None
            except:
                pass
    except Exception as e:
        print(f"  Login submit: {e}")
    
    return None

import json

# ============================================================
# Main
# ============================================================

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v20c — Cuckoo Flow + WG Auth")
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
    
    # Step 2: Try sending JUST protocol version (no LogOnParams, no RSA)
    # This might trigger a Cuckoo challenge response
    print(f"\n[2] Sending protocol version only (trigger challenge?)...")
    for proto in [51, 52, 55, 72, 75]:
        body = struct.pack("<I", proto)
        pkt = build_v32_request(0x01, rid, body)
        print(f"  [{rid}] proto={proto}...")
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            print(f"      ← {r}")
            rid += 1
            if r.get("type") == "CHALLENGE":
                print(f"      🎯 CHALLENGE received!")
                # Parse challenge payload
                challenge_data = data[11:]
                if len(challenge_data) >= 5:
                    # [reply_id(4B)][status(1B)][duration(f32)][key(blob_var)][...]
                    payload = challenge_data[5:]  # after reply_id+status
                    print(f"      Challenge payload ({len(payload)}B): {payload[:100].hex()}")
                    
                    # Try to parse the Cuckoo challenge
                    if len(payload) >= 4:
                        duration = struct.unpack("<f", payload[:4])[0]
                        print(f"      Duration: {duration}s")
                        cuckoo_key = payload[4:4+16]
                        print(f"      Cuckoo key: {cuckoo_key.hex()}")
                        
                        # Solve Cuckoo
                        print(f"      Solving Cuckoo PoW...")
                        solution = solve_cuckoo(cuckoo_key, max_nonce=500000)
                        if solution is not None:
                            print(f"      ✅ Solution: {solution}")
                            
                            # Send ChallengeResponse
                            # Format: [0x03][len(2B)][rid(4B)][next(2B)][duration(f32)][key(blob_var)][solution(u32*42)]
                            bf_key = os.urandom(16)
                            challenge_resp = struct.pack("<f", duration)
                            challenge_resp += pack_str(cuckoo_key)
                            challenge_resp += struct.pack("<I", solution)
                            
                            pkt2 = build_v32_request(0x03, rid, challenge_resp)
                            print(f"      Sending ChallengeResponse ({len(pkt2)}B)...")
                            sock.sendto(pkt2, (server, port))
                            try:
                                data2, _ = sock.recvfrom(4096)
                                r2 = parse_reply(data2)
                                print(f"      ← {r2}")
                                rid += 1
                                
                                if r2.get("type") == "SUCCESS":
                                    print(f"      🎉 Challenge accepted!")
                                    
                                    # Now send LoginRequest
                                    print(f"      Sending LoginRequest...")
                                    bf = os.urandom(16)
                                    logon = struct.pack("<B", 0) + pack_str("guest") + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
                                    rsa_data = rsa_oaep(logon, KEY_WOT)
                                    login_body = struct.pack("<I", proto) + rsa_data
                                    login_pkt = build_v32_request(0x01, rid, login_body)
                                    sock.sendto(login_pkt, (server, port))
                                    try:
                                        data3, _ = sock.recvfrom(4096)
                                        r3 = parse_reply(data3)
                                        print(f"      ← {r3}")
                                    except socket.timeout:
                                        print(f"      ❌ Login timeout")
                            except socket.timeout:
                                print(f"      ❌ ChallengeResponse timeout")
                        else:
                            print(f"      ❌ Cuckoo not solved in time")
                break
        except socket.timeout:
            print(f"      ❌ timeout")
            rid += 1
    
    # Step 3: Try with WG auth token (if credentials provided)
    email = os.environ.get('WG_EMAIL', '')
    password = os.environ.get('WG_PASSWORD', '')
    if email and password:
        print(f"\n[3] WG Login with credentials...")
        auth = wg_login(email, password)
        if auth:
            # Get auth token / session
            token = auth.get('account_id', '') or auth.get('access_token', '')
            print(f"  Auth token: {str(token)[:50]}...")
            
            # Try login with WG auth token as username
            for proto in [51, 52, 55]:
                bf = os.urandom(16)
                logon = struct.pack("<B", 0) + pack_str(str(token)) + pack_str("") + pack_str(bf) + struct.pack("<I", 0)
                rsa_data = rsa_oaep(logon, KEY_WOT)
                body = struct.pack("<I", proto) + rsa_data
                pkt = build_v32_request(0x01, rid, body)
                print(f"  [{rid}] WG token login proto={proto}...")
                sock.sendto(pkt, (server, port))
                try:
                    data, _ = sock.recvfrom(4096)
                    r = parse_reply(data)
                    print(f"      ← {r}")
                    rid += 1
                    if r.get("type") == "CHALLENGE":
                        print(f"      🎯 CHALLENGE with WG token!")
                        break
                except socket.timeout:
                    print(f"      ❌ timeout")
                    rid += 1
    else:
        print(f"\n[3] Skipping WG login (set WG_EMAIL and WG_PASSWORD env vars)")
    
    sock.close()

if __name__ == "__main__":
    run()

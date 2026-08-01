#!/usr/bin/env python3
"""WoT Bot v20 — Full pipeline: Showroom → Metadata → CDN → Key → Login"""
import socket, struct, os, sys, time, json, hashlib, zipfile, io, urllib.request, urllib.parse, ssl

FLAG_HAS_REQUESTS = 0x0002

def xorshift32_transform(data):
    val = 0
    for b in data:
        val ^= b
        val = (val * 0x100) & 0xFFFFFFFF
        val = (val + b) & 0xFFFFFFFF
    return val

def _prefix(raw):
    val = xorshift32_transform(raw[4:])
    return val

def pack_int(n):
    if n >= 255:
        return struct.pack("<B", 0xFF) + struct.pack("<I", n)[1:]
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
    if len(data) < 11:
        return {"raw": data.hex(), "error": "too short"}
    flags = struct.unpack("<H", data[4:6])[0]
    if data[6] != 0xFF:
        return {"raw": data.hex(), "error": f"not reply (0x{data[6]:02X})"}
    length = struct.unpack("<I", data[7:11])[0]
    rdata = data[11:11+length]
    result = {"flags": f"0x{flags:04X}", "length": length, "raw": rdata.hex()}
    if length >= 4:
        rid = struct.unpack("<I", rdata[:4])[0]
        result["reply_id"] = f"0x{rid:08X}"
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

try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA1
    HAS_CRYPTO = True
except:
    HAS_CRYPTO = False
    print("[!] pycryptodome not available")

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

def rsa_encrypt(plaintext, pem_key):
    if not HAS_CRYPTO: return None
    key = RSA.importKey(pem_key)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    return cipher.encrypt(plaintext)

def http_get(url, timeout=10):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={
        'User-Agent': 'wgc/26.04.00.3109',
        'Accept': 'application/json,text/xml,application/xml,*/*'
    })
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.read().decode('utf-8', errors='replace')
    except: return None

def http_get_bytes(url, timeout=30):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={'User-Agent': 'wgc/26.04.00.3109'})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.read()
    except: return None

def try_showroom():
    print("\n[SHOWROOM] Trying showroom API...")
    servers = ["https://wguscs-wgcru.wargaming.net", "https://wguswgc-eu.wargaming.net"]
    for server in servers:
        url = f"{server}/api/v18/content/showroom/?lang=EN&gameid=WGC.EU.PRODUCTION&wgc_publisher_id=wargaming&format=json&country_code="
        print(f"  -> {url}")
        resp = http_get(url, timeout=10)
        if resp and len(resp) > 100:
            print(f"  Got {len(resp)} bytes!")
            try:
                data = json.loads(resp)
                for product in data.get('data', {}).get('showcase', []):
                    instances = product.get('instances', [])
                    if instances:
                        app_id = instances[0].get('application_id', '')
                        if app_id.startswith('WOT'):
                            update_url = instances[0].get('update_service_url', '') or product.get('update_url', '')
                            print(f"  WoT found! app_id={app_id}, update_url={update_url}")
                            return app_id, update_url
                print(f"  WoT not found, dumping...")
                print(f"  {json.dumps(data, indent=2)[:2000]}")
            except: print(f"  Not JSON: {resp[:500]}")
        else:
            print(f"  Empty/unreachable")
    return None, None

def try_metadata(app_id, update_server):
    print(f"\n[METADATA] Trying metadata API with guid={app_id}...")
    servers = [update_server] if update_server else []
    servers.extend(["https://wguswgc-eu.wargaming.net", "https://wgusst-wgceu.wargaming.net"])
    seen = set()
    servers = [s for s in servers if s and s not in seen and not seen.add(s)]
    guids = [app_id, "WOT", "WOT.EU.PRODUCTION", "WOT.EU"]
    for server in servers:
        for guid in guids:
            url = f"{server}/api/v1/metadata/?guid={guid}&chain_id=unknown&protocol_version=7.2"
            resp = http_get(url, timeout=10)
            if resp and len(resp) > 100 and 'error' not in resp.lower():
                print(f"  {server} guid={guid} -> {len(resp)} bytes!")
                print(f"  {resp[:3000]}")
                return resp
            elif resp and 'Unknown guid' in resp: continue
            elif resp: print(f"  {server} guid={guid} -> {resp[:200]}")
    return None

def try_patches_chain():
    print("\n[PATCHES_CHAIN] Trying patches_chain API...")
    server = "https://wguswgc-eu.wargaming.net"
    base = "client_type=wot&lang=en&metadata_version=1.0&game_id=WOT&protocol_version=1.0&metadata_protocol_version=1.0"
    for vp, desc in [("0&current_version_parts=0&current_version_parts=0&current_version_parts=0","repeated"),
                     ("0,0,0,0","comma"), ("0.0.0.0","dot"),
                     ("1&current_version_parts=42&current_version_parts=0&current_version_parts=0","v1.42")]:
        url = f"{server}/api/v1/patches_chain/?{base}&current_version_parts={vp}"
        resp = http_get(url, timeout=10)
        if resp and len(resp) > 100 and 'error' not in resp.lower():
            print(f"  {desc} -> {len(resp)} bytes!")
            print(f"  {resp[:3000]}")
            return resp
        elif resp and 'current_version_parts' not in resp:
            print(f"  {desc} -> {resp[:200]}")
    return None

def try_download_pkg(cdn_url):
    print(f"\n[CDN] Trying to download .pkg files...")
    bases = [cdn_url] if cdn_url else ["https://dl-wot-gc.wargaming.net/patches/", "https://dl-wot-eu.wargaming.net/patches/"]
    for base in bases:
        for path in ["packages/auth/pkg", "content/packages/auth.pkg", "packages/loginapp_wot.pkg"]:
            url = f"{base.rstrip('/')}/{path}"
            print(f"  -> {url}")
            data = http_get_bytes(url, timeout=30)
            if data and len(data) > 100:
                print(f"  Got {len(data)} bytes!")
                try:
                    zf = zipfile.ZipFile(io.BytesIO(data))
                    for name in zf.namelist():
                        if 'pubkey' in name.lower() or 'loginapp' in name.lower():
                            print(f"  Found key: {name}")
                            return zf.read(name)
                    print(f"  Files: {zf.namelist()[:20]}")
                except: print(f"  Not ZIP")
    return None

def try_extract_key_from_local():
    print("\n[LOCAL] Searching for local WoT installation...")
    paths = ["/c/Games/World_of_Tanks", "C:\\Games\\World_of_Tanks", os.path.expanduser("~/Games/World_of_Tanks"),
             "/mnt/c/Games/World_of_Tanks", os.path.expanduser("~/.wine/drive_c/Games/World_of_Tanks")]
    for base in paths:
        if os.path.exists(base):
            print(f"  Found WoT at: {base}")
            for root, dirs, files in os.walk(base):
                for f in files:
                    if f.endswith('.pkg') and ('auth' in f.lower() or 'login' in f.lower()):
                        try:
                            zf = zipfile.ZipFile(os.path.join(root, f))
                            for name in zf.namelist():
                                if 'pubkey' in name.lower() or 'loginapp' in name.lower():
                                    return zf.read(name)
                        except: pass
    print("  No local WoT installation found")
    return None

def make_logon_params(user="guest", pwd="", bf_key=None, nonce=0, flags=0):
    if bf_key is None: bf_key = os.urandom(16)
    p = struct.pack("<B", flags)
    p += pack_str(user)
    p += pack_str(pwd)
    p += pack_str(bf_key)
    p += struct.pack("<I", nonce)
    return p

def try_login(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v20 — Login Test — {server}:{port}")
    print(f"{'='*55}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1
    print(f"\n[1] PING (rid={rid})...")
    sock.sendto(build_ping(rid), (server, port))
    try:
        data, _ = sock.recvfrom(4096)
        print(f"    PING OK ({len(data)}B)")
        rid += 1
    except socket.timeout:
        print(f"    PING timeout")
        sock.close(); return

    tests = []
    if HAS_CRYPTO:
        for proto in [51, 52, 55, 60, 72, 75, 80, 100]:
            for flags in [0, 1]:
                bf = os.urandom(16)
                logon = make_logon_params(bf_key=bf, flags=flags)
                rsa_data = rsa_encrypt(logon, KEY_WOT)
                body = struct.pack("<I", proto) + rsa_data
                tests.append((f"RSA WoT proto={proto} flags={flags}", body))
        for proto in [51, 52, 55]:
            bf = os.urandom(16)
            rsa_data = rsa_encrypt(make_logon_params(bf_key=bf), KEY_BW)
            tests.append((f"RSA BW proto={proto}", struct.pack("<I", proto) + rsa_data))
        for proto in [51, 52, 55, 72]:
            bf = os.urandom(16)
            body = struct.pack("<I", proto) + make_logon_params(bf_key=bf)
            tests.append((f"Plain proto={proto}", body))
        for proto in [51, 52, 55, 72]:
            tests.append((f"Proto-only proto={proto}", struct.pack("<I", proto)))

    print(f"\n[2] Testing {len(tests)} login combinations on Element 0x01 V32...")
    for desc, body in tests:
        print(f"\n  [{rid}] {desc}...")
        pkt = build_v32_request(0x01, rid, body)
        print(f"      -> {len(pkt)}B")
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            print(f"      <- {r}")
            rid += 1
            if r.get("type") == "CHALLENGE":
                print(f"      GOT CHALLENGE! data={r.get('data','')[:100]}")
                with open('/tmp/wot_challenge.bin', 'wb') as f: f.write(data[11:])
                break
            elif r.get("type") == "SUCCESS":
                print(f"      LOGIN SUCCESS!")
                break
        except socket.timeout:
            print(f"      timeout")
            rid += 1
    sock.close()

def main():
    print("=" * 55)
    print("  WoT Bot v20 — Full Pipeline")
    print("=" * 55)
    key_data = try_extract_key_from_local()
    if key_data:
        print(f"\nFound RSA key locally!")
        with open('/tmp/loginapp_wot.pubkey', 'wb') as f: f.write(key_data)
    app_id, update_url = try_showroom()
    if app_id:
        metadata = try_metadata(app_id, update_url)
        if metadata:
            import re
            urls = re.findall(r'https?://[^\s<>"\']+', metadata)
            cdn_urls = [u for u in urls if 'dl-' in u or 'cdn' in u or 'patch' in u.lower()]
            if cdn_urls:
                print(f"  CDN URLs: {cdn_urls[:5]}")
                for cdn in cdn_urls[:3]:
                    key_data = try_download_pkg(cdn)
                    if key_data: break
    else:
        patches = try_patches_chain()
        if patches:
            import re
            urls = re.findall(r'https?://[^\s<>"\']+', patches)
            if urls:
                for u in urls[:5]:
                    if '.pkg' in u or 'content' in u.lower():
                        try_download_pkg(u.rsplit('/', 1)[0])
    for server, port in [("login.p1.worldoftanks.eu", 20016), ("login.p2.worldoftanks.eu", 20018)]:
        try_login(server, port)
        time.sleep(1)
    print("\nDone! Check output above for CHALLENGE or SUCCESS responses.")

if __name__ == "__main__":
    main()

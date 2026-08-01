#!/usr/bin/env python3
"""WoT Bot v20 — Full pipeline: Showroom → Metadata → CDN → Key → Login

Key discoveries:
- Element ID 0x01 + Variable32 gets server response (error 0x40)
- GOG Galaxy WGC integration reveals: chain_id=unknown, protocol_version=7.2
- Showroom API at wguscs-wgcru.wargaming.net returns game metadata
- .pkg files are ZIP archives — loginapp_wot.pubkey extractable with zipfile
- game_id=WOT (uppercase), GAMES_F2P=['WOT','WOWS','WOWP']
"""
import socket, struct, os, sys, time, json, hashlib, zipfile, io, urllib.request, urllib.parse, ssl

# ============================================================
# PART 1: BigWorld protocol helpers (from v8/v9)
# ============================================================

FLAG_HAS_REQUESTS = 0x0002
FLAG_HAS Replies   = 0x0001  # not used

def xorshift32_transform(data):
    val = 0
    for b in data:
        val ^= b
        val = (val * 0x100) & 0xFFFFFFFF
        val = (val + b) & 0xFFFFFFFF
    return struct.pack("<I", val)

def _prefix(raw):
    return xorshift32_transform(raw[4:])  # prefix over content+footer

def pack_int(n):
    if n >= 255:
        return struct.pack("<B", 0xFF) + struct.pack("<I", n)[1:]  # 3-byte for <65536
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_int(len(b)) + b

def build_ping(rid):
    """PING on Element ID 0x02, Fixed(1) format."""
    content = struct.pack("<B", 0x02) + struct.pack("<I", rid) + struct.pack("<H", 0) + b'\x00'
    raw = struct.pack("<IH", 0, FLAG_HAS_REQUESTS) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def build_v32_request(elem_id, rid, body):
    """Variable32 request: [elem_id][len(4B)][rid(4B)][next(2B)][body]"""
    inner = struct.pack("<IH", rid, 0) + body
    content = struct.pack("<BI", elem_id, len(inner)) + inner
    raw = struct.pack("<IH", 0, FLAG_HAS_REQUESTS) + content + struct.pack("<H", 2)
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def parse_reply(data):
    """Parse server reply packet."""
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
            if status == 1:
                result["type"] = "SUCCESS"
                if length > 5:
                    result["payload"] = rdata[5:].hex()
            elif status == 0x42:
                result["type"] = "CHALLENGE"
                if length > 5:
                    result["payload"] = rdata[5:].hex()
            elif status >= 64:
                result["type"] = f"ERROR(0x{status:02X})"
                if length > 5:
                    try: result["message"] = rdata[5:].decode('utf-8', errors='replace')
                    except: result["payload"] = rdata[5:].hex()
            else:
                result["type"] = f"STATUS(0x{status:02X})"
                if length > 5:
                    result["payload"] = rdata[5:].hex()
    return result

# ============================================================
# PART 2: RSA encryption helpers
# ============================================================

try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA1
    HAS_CRYPTO = True
except:
    HAS_CRYPTO = False
    print("[!] pycryptodome not available — RSA encryption disabled")

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
    if not HAS_CRYPTO:
        return None
    key = RSA.importKey(pem_key)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    return cipher.encrypt(plaintext)

# ============================================================
# PART 3: WGC API — Showroom + Metadata + CDN download
# ============================================================

def http_get(url, timeout=10):
    """Simple HTTP GET with User-Agent."""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={
        'User-Agent': 'wgc/26.04.00.3109',
        'Accept': 'application/json,text/xml,application/xml,*/*'
    })
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.read().decode('utf-8', errors='replace')
    except Exception as e:
        return None

def http_get_bytes(url, timeout=30):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={'User-Agent': 'wgc/26.04.00.3109'})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.read()
    except Exception as e:
        return None

def try_showroom():
    """Try to get game metadata from the WGC showroom API."""
    print("\n[SHOWROOM] Trying showroom API...")
    
    servers = [
        "https://wguscs-wgcru.wargaming.net",
        "https://wguswgc-eu.wargaming.net",
    ]
    
    for server in servers:
        url = f"{server}/api/v18/content/showroom/?lang=EN&gameid=WGC.EU.PRODUCTION&wgc_publisher_id=wargaming&format=json&country_code="
        print(f"  → {url}")
        resp = http_get(url, timeout=10)
        if resp and len(resp) > 100:
            print(f"  ✅ Got {len(resp)} bytes!")
            try:
                data = json.loads(resp)
                # Find WoT in the showcase
                for product in data.get('data', {}).get('showcase', []):
                    instances = product.get('instances', [])
                    if instances:
                        app_id = instances[0].get('application_id', '')
                        if app_id.startswith('WOT'):
                            update_url = instances[0].get('update_service_url', '') or product.get('update_url', '')
                            print(f"  🎯 WoT found! app_id={app_id}, update_url={update_url}")
                            return app_id, update_url
                # If not found in showcase, try metadata.wgc
                for game_data in data.get('data', {}).get('product_content', []):
                    wgc = game_data.get('metadata', {}).get('wgc', {})
                    app_id = wgc.get('application_id', {}).get('data', '')
                    update_url = wgc.get('update_url', {}).get('data', '')
                    if app_id.startswith('WOT'):
                        print(f"  🎯 WoT in product_content! app_id={app_id}, update_url={update_url}")
                        return app_id, update_url
                print(f"  ⚠️ WoT not found in showroom data, dumping structure...")
                print(f"  {json.dumps(data, indent=2)[:2000]}")
            except json.JSONDecodeError:
                print(f"  Response (not JSON): {resp[:500]}")
        else:
            print(f"  ❌ Empty or unreachable")
    return None, None

def try_metadata(app_id, update_server):
    """Try to get game metadata (CDN URL) from the WGC metadata API."""
    print(f"\n[METADATA] Trying metadata API with guid={app_id}...")
    
    # Try multiple servers
    servers = [update_server] if update_server else []
    servers.extend([
        "https://wguswgc-eu.wargaming.net",
        "https://wgusst-wgceu.wargaming.net",
        "https://wguscs-wgcru.wargaming.net",
    ])
    # Remove None and duplicates
    seen = set()
    servers = [s for s in servers if s and s not in seen and not seen.add(s)]
    
    # Try multiple guid formats
    guids = [app_id, "WOT", "WOT.EU.PRODUCTION", "WOT.EU", "WOT.PC.EU"]
    
    for server in servers:
        for guid in guids:
            url = f"{server}/api/v1/metadata/?guid={guid}&chain_id=unknown&protocol_version=7.2"
            resp = http_get(url, timeout=10)
            if resp and len(resp) > 100 and 'error' not in resp.lower():
                print(f"  ✅ {server} guid={guid} → {len(resp)} bytes!")
                print(f"  {resp[:3000]}")
                return resp
            elif resp and 'Unknown guid' in resp:
                continue  # skip silently
            elif resp:
                print(f"  ⚠️ {server} guid={guid} → {resp[:200]}")
    return None

def try_patches_chain():
    """Try to get patch chain (CDN URLs) from the WGC patches_chain API."""
    print("\n[PATCHES_CHAIN] Trying patches_chain API...")
    
    server = "https://wguswgc-eu.wargaming.net"
    base_params = "client_type=wot&lang=en&metadata_version=1.0&game_id=WOT&protocol_version=1.0&metadata_protocol_version=1.0"
    
    # Try various current_version_parts formats
    version_formats = [
        ("0&current_version_parts=0&current_version_parts=0&current_version_parts=0", "repeated zeros"),
        ("0,0,0,0", "comma-separated"),
        ("0.0.0.0", "dot-separated"),
        ("1&current_version_parts=42&current_version_parts=0&current_version_parts=0", "v1.42 repeated"),
        ("1,42,0,0", "v1.42 comma"),
    ]
    
    for vp, desc in version_formats:
        url = f"{server}/api/v1/patches_chain/?{base_params}&current_version_parts={vp}"
        resp = http_get(url, timeout=10)
        if resp and len(resp) > 100 and 'error' not in resp.lower():
            print(f"  ✅ {desc} → {len(resp)} bytes!")
            print(f"  {resp[:3000]}")
            return resp
        elif resp and 'current_version_parts' not in resp:
            print(f"  ⚠️ {desc} → {resp[:200]}")
    return None

def try_download_pkg(cdn_url):
    """Try to download .pkg files from CDN and extract RSA key."""
    print(f"\n[CDN] Trying to download .pkg files from {cdn_url}...")
    
    if not cdn_url:
        # Try known CDN patterns
        cdn_urls = [
            "https://dl-wot-gc.wargaming.net/patches/",
            "https://dl-wot-eu.wargaming.net/patches/",
            "https://content.tanki.su/patches/",
        ]
    else:
        cdn_urls = [cdn_url]
    
    for base in cdn_urls:
        # Try common .pkg file paths
        pkg_paths = [
            "packages/auth/pkg",
            "content/packages/auth.pkg", 
            "packages/loginapp_wot.pkg",
            "res_mods/0.9.20/packages/loginapp_wot.pkg",
        ]
        for path in pkg_paths:
            url = f"{base.rstrip('/')}/{path}"
            print(f"  → {url}")
            data = http_get_bytes(url, timeout=30)
            if data and len(data) > 100:
                print(f"  ✅ Got {len(data)} bytes!")
                # Try to extract as ZIP
                try:
                    zf = zipfile.ZipFile(io.BytesIO(data))
                    for name in zf.namelist():
                        if 'pubkey' in name.lower() or 'loginapp' in name.lower() or 'key' in name.lower():
                            print(f"  🎯 Found key file: {name}")
                            key_data = zf.read(name)
                            print(f"  Key: {key_data[:500]}")
                            return key_data
                    # List all files
                    print(f"  Files in ZIP: {zf.namelist()[:20]}")
                except zipfile.BadZipFile:
                    print(f"  Not a ZIP file")
    
    return None

def try_extract_key_from_local():
    """Try to find the RSA key in local WoT installation."""
    print("\n[LOCAL] Searching for local WoT installation...")
    
    # Common WoT install paths
    paths = [
        "/c/Games/World_of_Tanks",
        "/c/Games/World_of_Tanks_EU",
        "C:\\Games\\World_of_Tanks",
        os.path.expanduser("~/Games/World_of_Tanks"),
        "/mnt/c/Games/World_of_Tanks",
        "/mnt/c/Games/World_of_Tanks_EU",
        os.path.expanduser("~/.wine/drive_c/Games/World_of_Tanks"),
        os.path.expanduser("~/.wine/drive_c/Games/World_of_Tanks_EU"),
    ]
    
    for base in paths:
        if os.path.exists(base):
            print(f"  Found WoT at: {base}")
            # Search for .pkg files
            for root, dirs, files in os.walk(base):
                for f in files:
                    if f.endswith('.pkg') and ('auth' in f.lower() or 'login' in f.lower() or 'content' in f.lower()):
                        pkg_path = os.path.join(root, f)
                        print(f"  → {pkg_path}")
                        try:
                            zf = zipfile.ZipFile(pkg_path)
                            for name in zf.namelist():
                                if 'pubkey' in name.lower() or 'loginapp' in name.lower():
                                    print(f"  🎯 Found: {name}")
                                    key_data = zf.read(name)
                                    return key_data
                        except:
                            pass
            # Search for metadata.xml
            for root, dirs, files in os.walk(base):
                for f in files:
                    if f == 'metadata.xml':
                        meta_path = os.path.join(root, f)
                        print(f"  → metadata.xml: {meta_path}")
                        try:
                            import xml.etree.ElementTree as ET
                            tree = ET.parse(meta_path)
                            root_elem = tree.getroot()
                            app_id = root_elem.find('app_id')
                            if app_id is not None:
                                print(f"  app_id: {app_id.text}")
                            app_id2 = root_elem.find('predefined_section/app_id')
                            if app_id2 is not None:
                                print(f"  predefined app_id: {app_id2.text}")
                            # Get update URLs
                            for elem in root_elem.iter():
                                if 'url' in elem.tag.lower() or 'update' in elem.tag.lower():
                                    print(f"  {elem.tag}: {elem.text}")
                        except:
                            pass
    
    print("  ❌ No local WoT installation found")
    return None

# ============================================================
# PART 4: WoT Login — Element 0x01, Variable32, RSA
# ============================================================

def make_logon_params(user="guest", pwd="", bf_key=None, nonce=0, flags=0):
    """Build BigWorld LogOnParams."""
    if bf_key is None:
        bf_key = os.urandom(16)
    params = struct.pack("<B", flags)  # flags
    params += pack_str(user)
    params += pack_str(pwd)
    params += pack_str(bf_key)
    params += struct.pack("<I", nonce)
    return params

def try_login(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    """Try login with Element 0x01 + Variable32 + RSA encryption."""
    print(f"\n{'='*55}")
    print(f"  WoT Bot v20 — Login Test — {server}:{port}")
    print(f"{'='*55}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1
    
    # PING first
    print(f"\n[1] PING (rid={rid})...")
    sock.sendto(build_ping(rid), (server, port))
    try:
        data, _ = sock.recvfrom(4096)
        print(f"    ✅ PING OK ({len(data)}B)")
        rid += 1
    except socket.timeout:
        print(f"    ❌ PING timeout — server unreachable")
        sock.close()
        return
    
    if not HAS_CRYPTO:
        print("[!] pycryptodome not available, trying plaintext login...")
    
    # Build all test combinations
    tests = []
    
    if HAS_CRYPTO:
        # RSA with WoT key
        for proto in [51, 52, 55, 60, 72, 75, 80, 100]:
            for flags in [0, 1]:
                bf = os.urandom(16)
                logon = make_logon_params(bf_key=bf, flags=flags)
                rsa_data = rsa_encrypt(logon, KEY_WOT)
                body = struct.pack("<I", proto) + rsa_data
                tests.append((f"RSA WoT proto={proto} flags={flags}", body))
        
        # RSA with BW default key
        for proto in [51, 52, 55]:
            bf = os.urandom(16)
            logon = make_logon_params(bf_key=bf)
            rsa_data = rsa_encrypt(logon, KEY_BW)
            body = struct.pack("<I", proto) + rsa_data
            tests.append((f"RSA BW proto={proto}", body))
        
        # RSA with just protocol version (no LogOnParams)
        for proto in [51, 52, 55, 72]:
            rsa_data = rsa_encrypt(struct.pack("<I", proto), KEY_WOT)
            body = rsa_data
            tests.append((f"RSA WoT proto-only={proto}", body))
        
        # Plain (no RSA) — protocol version + LogOnParams
        for proto in [51, 52, 55, 72]:
            bf = os.urandom(16)
            body = struct.pack("<I", proto)
            body += make_logon_params(bf_key=bf)
            tests.append((f"Plain proto={proto}", body))
        
        # Try with nonce (non-zero)
        for proto in [51, 52]:
            bf = os.urandom(16)
            logon = make_logon_params(bf_key=bf, nonce=int(time.time()))
            rsa_data = rsa_encrypt(logon, KEY_WOT)
            body = struct.pack("<I", proto) + rsa_data
            tests.append((f"RSA WoT proto={proto} nonce=timestamp", body))
        
        # Try with empty username/password
        for proto in [51, 52]:
            bf = os.urandom(16)
            logon = make_logon_params(user="", pwd="", bf_key=bf)
            rsa_data = rsa_encrypt(logon, KEY_WOT)
            body = struct.pack("<I", proto) + rsa_data
            tests.append((f"RSA WoT proto={proto} empty user", body))
    
    print(f"\n[2] Testing {len(tests)} login combinations on Element 0x01 V32...")
    for desc, body in tests:
        rid_val = rid
        print(f"\n  [{rid_val}] {desc}...")
        pkt = build_v32_request(0x01, rid, body)
        print(f"      → {len(pkt)}B")
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            print(f"      ← {r}")
            rid += 1
            
            if r.get("type") == "CHALLENGE":
                print(f"      🎯 GOT CHALLENGE! Payload: {r.get('payload', '')[:100]}")
                # Save challenge for next step
                with open('/tmp/wot_challenge.bin', 'wb') as f:
                    f.write(data[11:])
                print(f"      Challenge saved to /tmp/wot_challenge.bin")
                break
            elif r.get("type") == "SUCCESS":
                print(f"      🎉 LOGIN SUCCESS!")
                break
            elif r.get("type", "").startswith("ERROR"):
                # Log error details
                if r.get("message"):
                    print(f"      Error msg: {r['message']}")
        except socket.timeout:
            print(f"      ❌ Timeout")
            rid += 1
    
    sock.close()

# ============================================================
# PART 5: Main — Run everything in sequence
# ============================================================

def main():
    print("=" * 55)
    print("  WoT Bot v20 — Full Pipeline")
    print("  Showroom → Metadata → CDN → Key → Login")
    print("=" * 55)
    
    # Step 1: Try to get RSA key from local WoT installation
    key_data = try_extract_key_from_local()
    if key_data:
        print(f"\n✅ Found RSA key locally!")
        # Save it
        with open('/tmp/loginapp_wot.pubkey', 'wb') as f:
            f.write(key_data)
    
    # Step 2: Try showroom API to get app_id and update_url
    app_id, update_url = try_showroom()
    
    # Step 3: Try metadata API to get CDN URL
    if app_id:
        metadata = try_metadata(app_id, update_url)
        if metadata:
            # Parse metadata for CDN URLs
            print(f"\n[INFO] Parsing metadata for CDN URLs...")
            # Look for download/content/patch URLs in the metadata
            import re
            urls = re.findall(r'https?://[^\s<>"\']+', metadata)
            cdn_urls = [u for u in urls if 'dl-' in u or 'cdn' in u or 'content' in u or 'patch' in u.lower()]
            if cdn_urls:
                print(f"  CDN URLs found: {cdn_urls[:5]}")
                # Try to download .pkg files
                for cdn in cdn_urls[:3]:
                    key_data = try_download_pkg(cdn)
                    if key_data:
                        break
    else:
        # Step 3b: Try patches_chain directly
        patches = try_patches_chain()
        if patches:
            print(f"\n[INFO] Parsing patches_chain for CDN URLs...")
            import re
            urls = re.findall(r'https?://[^\s<>"\']+', patches)
            if urls:
                print(f"  URLs found: {urls[:5]}")
                for u in urls[:5]:
                    if '.pkg' in u or 'content' in u.lower():
                        key_data = try_download_pkg(u.rsplit('/', 1)[0])
                        if key_data:
                            break
    
    # Step 4: Try login on all EU servers
    servers = [
        ("login.p1.worldoftanks.eu", 20016),
        ("login.p2.worldoftanks.eu", 20018),
        ("login.p3.worldoftanks.eu", 20020),
    ]
    
    for server, port in servers:
        try_login(server, port)
        time.sleep(1)
    
    print("\n" + "=" * 55)
    print("  Pipeline complete!")
    print("=" * 55)
    
    print("\nNext steps:")
    print("  1. If showroom returned data: use app_id to call metadata API")
    print("  2. If metadata returned CDN URL: download .pkg files")
    print("  3. If .pkg downloaded: extract loginapp_wot.pubkey")
    print("  4. If login returned CHALLENGE: solve Cuckoo PoW")
    print("  5. If login returned ERROR(0x40): payload format needs fixing")
    print("     → Try different LogOnParams serialization (C++ packed_int vs protobuf)")
    print("     → Try RSA-PKCS1v15 instead of RSA-OAEP")
    print("     → Try different nonce/digest combinations")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""WoT Bot v19 — Test servers + CDN key extraction

Two-pronged approach:
1. Test CT/SB/sandbox servers — might use BW default key or allow unencrypted
2. Try to download .pkg files from WoT CDN and extract loginapp_wot.pubkey
   (WoT .pkg files are just ZIP archives — extractable with Python zipfile!)
"""
import socket, struct, os, sys, time, zipfile, io, urllib.request, ssl

exec(open('/root/wot-grinder-bot-v8/bw_bot_v3.py' if os.path.exists('/root/wot-grinder-bot-v8/bw_bot_v3.py') else '/tmp/bw_bot_v3.py').read().split('def run(')[0])

KEY_BW = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7/MNyWDdFpXhpFTO9LHz
CUQPYv2YP5rqJjUoxAFa3uKiPKbRvVFjUQ9lGHyjCmtixBbBqCTvDWu6Zh9Imu3x
KgCJh6NPSkddH3l+C+51FNtu3dGntbSLWuwi6Au1ErNpySpdx+Le7YEcFviY/ClZ
ayvVdA0tcb5NVJ4Axu13NvsuOUMqHxzCZRXCe6nyp6phFP2dQQZj8QZp0VsMFvhh
MsZ4srdFLG0sd8qliYzSqIyEQkwO8TQleHzfYYZ90wPTCOvMnMe5+zCH0iPJMisP
YB60u6lK9cvDEeuhPH95TPpzLNUFgmQIu9FU8PkcKA53bj0LWZR7v86Oco6vFg6V
sQIDAQAB
-----END PUBLIC KEY-----"""

def pack_int(n):
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[1:]
    return struct.pack("<B", n)

def pack_str(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_int(len(b)) + b

def rsa_encrypt(plaintext, pem_key=KEY_BW):
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA1
    key = RSA.importKey(pem_key)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    return cipher.encrypt(plaintext)

def make_logon(user="guest", pwd="", bf_key=None, nonce=0):
    if bf_key is None: bf_key = os.urandom(16)
    return struct.pack("<B", 0) + pack_str(user) + pack_str(pwd) + pack_str(bf_key) + struct.pack("<I", nonce)

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
        status = rd[4]
        codes = {1:"SUCCESS", 0x42:"CHALLENGE", 64:"Malformed", 65:"BadVersion",
                 67:"InvalidUser", 68:"InvalidPwd", 69:"AlreadyLoggedIn",
                 82:"LoginNotAllowed", 83:"RateLimited", 85:"ChallengeErr"}
        r["type"] = codes.get(status, f"0x{status:02X}")
        if length > 5:
            try: r["msg"] = rd[5:].decode('utf-8', errors='replace')[:200]
            except: pass
    return r

def send_login(server, port, body, timeout=5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(ping_packet(rid=1, num=0), (server, port))
        try: sock.recvfrom(4096)
        except: sock.close(); return {"error": "PING timeout"}
        pkt = build_v32_be(0x01, 2, body)
        sock.sendto(pkt, (server, port))
        try:
            data, _ = sock.recvfrom(4096)
            r = parse_reply(data)
            sock.close()
            return r
        except: sock.close(); return {"error": "timeout"}
    except Exception as e:
        sock.close()
        return {"error": str(e)}

def try_download_key():
    """Try to download .pkg files from WoT CDN and extract loginapp_wot.pubkey"""
    print(f"\n{'='*60}")
    print("  Attempting to download loginapp_wot.pubkey from WoT CDN")
    print(f"{'='*60}")
    
    # Common WoT .pkg file names
    pkg_names = [
        "system.pkg", "engine.pkg", "loginapp.pkg", "core.pkg",
        "gui-part1.pkg", "gui-part2.pkg", "content.pkg",
        "pkg0.pkg", "pkg1.pkg", "pkg2.pkg", "pkg3.pkg",
        "shared_content.pkg", "shared_content_part1.pkg",
        "locale-en.pkg", "locale.pkg",
    ]
    
    # Possible CDN base URLs
    cdn_bases = [
        "https://wgus-wot.gcdn.co/wot/eu/res/packages/",
        "https://wgus-wot.gcdn.co/wot/eeu/res/packages/",
        "https://dl.wargaming.net/wot/eu/res/packages/",
        "https://content.wargaming.net/wot/eu/res/packages/",
        "https://wgus-eu1-wot.gcdn.co/wot/eu/res/packages/",
        "http://csis.worldoftanks.eu/csis/woteu/res/packages/",
    ]
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    for cdn in cdn_bases:
        print(f"\n  Testing CDN: {cdn}")
        try:
            req = urllib.request.Request(cdn, headers={'User-Agent': 'WGC/2.0'})
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            print(f"  ✅ CDN accessible! Status: {resp.status}")
            # Try to list directory or find .pkg files
            content = resp.read(4096).decode('utf-8', errors='replace')
            print(f"  Content: {content[:200]}")
        except Exception as e:
            print(f"  ❌ {e}")
    
    # Also try direct .pkg file downloads
    for cdn in cdn_bases[:3]:
        for pkg in pkg_names[:5]:
            url = cdn + pkg
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'WGC/2.0'})
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                print(f"\n  ✅ Found: {url} ({resp.headers.get('Content-Length', '?')} bytes)")
                data = resp.read()
                # Try to open as ZIP
                try:
                    zf = zipfile.ZipFile(io.BytesIO(data))
                    for name in zf.namelist():
                        if 'pubkey' in name.lower() or 'loginapp' in name.lower():
                            print(f"  🔑 KEY FOUND IN {pkg}: {name}")
                            key_data = zf.read(name).decode('utf-8')
                            print(f"  KEY CONTENT:\n{key_data}")
                            return key_data
                    print(f"  No key in {pkg}, files: {zf.namelist()[:5]}...")
                except zipfile.BadZipFile:
                    print(f"  Not a ZIP file: {pkg}")
            except Exception as e:
                pass  # Silently skip failed downloads
    
    return None

def run_v19():
    print(f"\n{'='*60}")
    print("  WoT Bot v19 — Test Servers + CDN Key Extraction")
    print(f"{'='*60}")
    
    # LogOnParams
    logon = make_logon()
    try:
        rsa_data = rsa_encrypt(logon)
        rsa_ok = True
    except Exception as e:
        print(f"  ⚠️ RSA error: {e}")
        rsa_data = b""
        rsa_ok = False
    
    version_u32 = struct.pack("<I", 50)
    
    # Servers to test
    servers = [
        ("login.p1.worldoftanks.eu", 20016, "EU Production"),
        ("login2.p1.worldoftanks.eu", 20016, "EU Token Login"),
        ("login-ct-p1.worldoftanks.net", 20015, "CT Test"),
        ("login-sandbox.p1.worldoftanks.eu", 20014, "Sandbox/SB"),
    ]
    
    print("\n--- Phase 1: Test all servers ---")
    for server, port, name in servers:
        print(f"\n  [{name}] {server}:{port}")
        
        # Test PING first
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            sock.sendto(ping_packet(rid=1, num=0), (server, port))
            try:
                sock.recvfrom(4096)
                print(f"    PING: ✅ OK")
            except:
                print(f"    PING: ❌ timeout")
                sock.close()
                continue
        except Exception as e:
            print(f"    PING: ❌ {e}")
            sock.close()
            continue
        sock.close()
        
        # Test login with BW key (no enc flag)
        if rsa_ok:
            body = version_u32 + rsa_data
            r = send_login(server, port, body)
            print(f"    Login (BW key, no enc): {r}")
        
        # Test login with encrypted=false
        body = version_u32 + struct.pack("<B", 0) + logon
        r = send_login(server, port, body)
        print(f"    Login (enc=false): {r}")
        
        # Test login without enc flag (plain)
        body = version_u32 + logon
        r = send_login(server, port, body)
        print(f"    Login (plain, no flag): {r}")
        
        # Check for breakthrough
        if isinstance(r, dict) and r.get("type") in ("SUCCESS", "CHALLENGE", "InvalidUser", "InvalidPwd"):
            print(f"    🔥🔥🔥 BREAKTHROUGH on {name}!")
            return
    
    print("\n--- Phase 2: Try CDN key extraction ---")
    key = try_download_key()
    if key:
        print(f"\n  🔑🔑🔑 RSA KEY EXTRACTED!")
        print(f"  Key saved to /tmp/loginapp_wot.pubkey")
        with open("/tmp/loginapp_wot.pubkey", "w") as f:
            f.write(key)
        # Now try login with the real key
        rsa_data_real = rsa_encrypt(logon, key)
        body = version_u32 + rsa_data_real
        r = send_login("login.p1.worldoftanks.eu", 20016, body)
        print(f"  Login with REAL key: {r}")
    else:
        print(f"\n  ❌ Could not download key from CDN")
        print(f"  The CDN is likely not accessible from this network.")
        print(f"  You need to extract loginapp_wot.pubkey from a WoT game client.")
        print(f"  The file is inside res/packages/*.pkg (ZIP archive) in the game folder.")
        print(f"  Try: python3 -c \"import zipfile; zf=zipfile.ZipFile('PATH_TO_PKG'); [print(n) for n in zf.namelist() if 'pubkey' in n]\"")

if __name__ == "__main__":
    run_v19()

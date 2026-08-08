import os
import socket
import urllib.request
import urllib.error
import ssl
from flask import Flask, request, jsonify

app = Flask(__name__)
WOT_SERVER = ("login.p1.worldoftanks.eu", 20016)
_sock = None
_peer = None

def get_socket():
    global _sock
    if _sock is None or _sock.fileno() == -1:
        _sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _sock.settimeout(30)
    return _sock

@app.route("/health")
def health():
    return jsonify({"ok": True, "service": "wot-udp-proxy-v18"})

@app.route("/send", methods=["POST"])
def send_packet():
    global _peer
    data = request.json or {}
    packet_hex = data.get("packet", "")
    timeout_s = data.get("timeout", 30)
    sock = get_socket()
    sock.settimeout(timeout_s)
    try:
        packet = bytes.fromhex(packet_hex)
        sock.sendto(packet, WOT_SERVER)
        _peer = WOT_SERVER
        responses = []
        while True:
            try:
                resp, addr = sock.recvfrom(4096)
                responses.append({"hex": resp.hex(), "len": len(resp), "from": f"{addr[0]}:{addr[1]}"})
                sock.settimeout(3)
            except socket.timeout:
                break
        if responses:
            return jsonify({"ok": True, "responses": responses, "count": len(responses)})
        return jsonify({"ok": False, "error": "timeout"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/reset", methods=["POST"])
def reset_socket():
    global _sock
    try:
        if _sock:
            _sock.close()
    except:
        pass
    _sock = None
    return jsonify({"ok": True, "msg": "socket reset"})

@app.route("/fetch", methods=["POST"])
def fetch_url():
    data = request.json or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"ok": False, "error": "no url"})
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "Wargaming Game Center"})
        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        content = resp.read()
        return jsonify({"ok": True, "status": resp.status, "text": content.decode("utf-8", errors="replace")[:5000], "size": len(content)})
    except urllib.error.HTTPError as e:
        body = e.read()
        return jsonify({"ok": False, "status": e.code, "error": str(e), "body": body.decode("utf-8", errors="replace")[:2000], "size": len(body)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "url": url})

@app.route("/cdn", methods=["POST"])
def cdn_fetch():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    domains = [
        "http://dl-wot-gc.wargaming.net",
        "http://content.wargaming.net",
    ]
    
    paths = [
        "/wot/eu/res/loginapp_wot.pubkey",
        "/wot/eu/loginapp_wot.pubkey",
        "/wot/loginapp_wot.pubkey",
        "/loginapp_wot.pubkey",
        "/res/loginapp_wot.pubkey",
        "/wot/eu/files/client/loginapp_wot.pubkey",
        "/wot/eu/paths.xml",
        "/paths.xml",
        "/wot/eu/version.xml",
        "/version.xml",
        "/wot/eu/files/client/",
        "/wot/eu/files/",
        "/wot/eu/",
        "/wot/",
        "/",
    ]
    
    results = []
    for domain in domains:
        for path in paths:
            url = domain + path
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Wargaming Game Center"})
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                content = resp.read()
                text = content.decode("utf-8", errors="replace")
                is_key = "MIIBIj" in text
                is_dir = "Index of" in text or "<li><a" in text[:500]
                results.append({"url": url, "status": 200, "size": len(content), "is_key": is_key, "is_dir": is_dir, "preview": text[:500]})
                if is_key:
                    return jsonify({"ok": True, "found": True, "url": url, "content": text[:1000]})
            except urllib.error.HTTPError as e:
                body = e.read()
                body_text = body.decode("utf-8", errors="replace")
                results.append({"url": url, "status": e.code, "size": len(body), "body": body_text[:500]})
            except Exception as e:
                err = str(e)
                results.append({"url": url, "error": err[:100]})
    
    return jsonify({"ok": True, "found": False, "results": results})




@app.route("/extract", methods=["POST"])
def extract_installer():
    """Download WGC installer, extract with innoextract, find loginapp_wot.pubkey."""
    import subprocess, os, tempfile, shutil, urllib.request, ssl, tarfile
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tmpdir = tempfile.mkdtemp()
    
    try:
        # Step 1: Download innoextract
        inno_url = "https://github.com/dscharrer/innoextract/releases/download/1.9/innoextract-1.9-linux.tar.xz"
        inno_tar = os.path.join(tmpdir, "inno.tar.xz")
        inno_dir = os.path.join(tmpdir, "inno")
        os.makedirs(inno_dir, exist_ok=True)
        
        req = urllib.request.Request(inno_url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        with open(inno_tar, 'wb') as f:
            f.write(resp.read())
        
        with tarfile.open(inno_tar, 'r:xz') as t:
            t.extractall(inno_dir)
        
        # Find innoextract binary for correct architecture
        import platform
        arch = platform.machine()  # x86_64
        inno_bin = None
        # List all binaries first
        all_bins = []
        for root, dirs, files in os.walk(inno_dir):
            for f in files:
                if f == 'innoextract':
                    all_bins.append(os.path.join(root, f))
        # Try to find x86_64 binary
        for b in all_bins:
            os.chmod(b, 0o755)
            # Check if it's the right arch by looking at directory name
            if arch in b or 'x86_64' in b or 'x86-64' in b or 'amd64' in b:
                inno_bin = b
                break
        # If no match by name, try running each one
        if not inno_bin:
            for b in all_bins:
                os.chmod(b, 0o755)
                try:
                    r_test = subprocess.run([b, "--version"], capture_output=True, text=True, timeout=3)
                    if r_test.returncode == 0:
                        inno_bin = b
                        break
                except:
                    pass
        if not inno_bin:
            return jsonify({"ok": False, "error": "innoextract binary not found"})
        
        # Test it
        r = subprocess.run([inno_bin, "--version"], capture_output=True, text=True, timeout=5)
        
        # Step 2: Download WGC installer
        url = "https://wds.wargaming.net/wgc/releases_tTrHgLCKHBRiaL/wgc_26.03.00.2798_eu/world_of_tanks_install_eu.exe"
        installer_path = os.path.join(tmpdir, "installer.exe")
        extract_dir = os.path.join(tmpdir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        req = urllib.request.Request(url, headers={"User-Agent": "Wargaming Game Center"})
        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        with open(installer_path, 'wb') as f:
            f.write(resp.read())
        
        # Step 3: List files first (without extracting)
        r_list = subprocess.run([inno_bin, "-l", installer_path], capture_output=True, text=True, timeout=30)
        
        # Step 4: Extract all files
        r = subprocess.run([inno_bin, "-d", extract_dir, "-s", installer_path],
                         timeout=120, capture_output=True, text=True)
        
        # Step 5: Search for loginapp_wot.pubkey and read all text config files
        found_files = []
        all_files = []
        text_file_contents = {}
        for root, dirs, files in os.walk(extract_dir):
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), extract_dir)
                all_files.append(rel)
                fpath = os.path.join(root, f)
                
                # Check for key files
                if "loginapp" in f.lower() or "pubkey" in f.lower() or ".pubkey" in f.lower():
                    try:
                        with open(fpath, 'rb') as pf:
                            raw = pf.read()
                        found_files.append({"name": rel, "size": len(raw), "content": raw.decode('utf-8', errors='replace')[:1000]})
                    except:
                        found_files.append({"name": rel, "content": "[binary]"})
                
                # Read all text config files (xml, json, ini, cfg, txt)
                if any(f.endswith(ext) for ext in ['.xml', '.json', '.ini', '.cfg', '.txt', '.config']):
                    try:
                        with open(fpath, 'rb') as pf:
                            raw = pf.read()
                        text = raw.decode('utf-8', errors='replace')[:5000]
                        text_file_contents[rel] = text
                    except:
                        pass
                
                # Also search ALL files for RSA key and URLs
                try:
                    with open(fpath, 'rb') as pf:
                        raw = pf.read()
                    if b'MIIBIj' in raw:
                        idx = raw.find(b'MIIBIj')
                        found_files.append({"name": rel, "content": raw[idx:idx+500].decode('utf-8', errors='replace')})
                    if b'loginapp' in raw.lower():
                        idx = raw.lower().find(b'loginapp')
                        text_file_contents[rel + " [loginapp match]"] = raw[max(0,idx-50):idx+200].decode('utf-8', errors='replace')
                    if b'.pubkey' in raw:
                        idx = raw.find(b'.pubkey')
                        text_file_contents[rel + " [.pubkey match]"] = raw[max(0,idx-50):idx+200].decode('utf-8', errors='replace')
                except:
                    pass
        
        if found_files:
            return jsonify({"ok": True, "found": True, "found_files": found_files, "total_files": len(all_files)})
        
        return jsonify({
            "ok": True, "found": len(found_files) > 0,
            "found_files": found_files,
            "total_files": len(all_files),
            "files_sample": all_files[:50],
            "text_files": text_file_contents,
            "inno_list": r_list.stdout[:2000] if r_list.stdout else r_list.stderr[:2000],
            "inno_extract_stderr": r.stderr[:500],
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@app.route("/wgpkg", methods=["POST"])
def extract_wgpkg():
    """Download WGC core .wgpkg (7z archive) and search for loginapp_wot.pubkey and config files."""
    import subprocess, os, tempfile, shutil, urllib.request, ssl, tarfile
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tmpdir = tempfile.mkdtemp()
    
    try:
        # Step 1: Download 7z binary (from GitHub releases)
        sevenzip_url = "https://github.com/ip7z/7zip/releases/download/26.02/7z2602-linux-x64.tar.xz"
        sevenzip_tar = os.path.join(tmpdir, "7z.tar.xz")
        sevenzip_dir = os.path.join(tmpdir, "7z")
        os.makedirs(sevenzip_dir, exist_ok=True)
        
        req = urllib.request.Request(sevenzip_url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        with open(sevenzip_tar, 'wb') as f:
            f.write(resp.read())
        
        with tarfile.open(sevenzip_tar, 'r:xz') as t:
            t.extractall(sevenzip_dir)
        
        sevenzip_bin = None
        for root, dirs, files in os.walk(sevenzip_dir):
            for f in files:
                if f in ('7zz', '7z', '7zzs'):
                    sevenzip_bin = os.path.join(root, f)
                    os.chmod(sevenzip_bin, 0o755)
                    break
            if sevenzip_bin: break
        
        if not sevenzip_bin:
            return jsonify({"ok": False, "error": "7z binary not found"})
        
        # Step 2: Download .wgpkg file (112 MB)
        wgpkg_url = "https://wds.wargaming.net/wgc/releases_tTrHgLCKHBRiaL/wgc_26.04.01.3190_eu/wgc_26.04.01.3190_win64.wgpkg"
        wgpkg_path = os.path.join(tmpdir, "wgc.wgpkg")
        
        req = urllib.request.Request(wgpkg_url, headers={"User-Agent": "Wargaming Game Center"})
        resp = urllib.request.urlopen(req, timeout=120, context=ctx)
        with open(wgpkg_path, 'wb') as f:
            while True:
                chunk = resp.read(1024*1024)
                if not chunk: break
                f.write(chunk)
        
        wgpkg_size = os.path.getsize(wgpkg_path)
        
        # Step 3: List files in the 7z archive
        r_list = subprocess.run([sevenzip_bin, "l", wgpkg_path], capture_output=True, text=True, timeout=60)
        file_list = r_list.stdout
        
        # Step 4: Search for loginapp_wot.pubkey and config files
        interesting_patterns = ['loginapp', 'pubkey', '.xml', '.json', '.cfg', '.ini', 'config', 'cdn', 'wot/', 'res/']
        found_in_list = []
        for line in file_list.split('\n'):
            for pat in interesting_patterns:
                if pat in line.lower():
                    found_in_list.append(line.strip())
                    break
        
        # Step 5: Extract all files matching interesting patterns
        extract_dir = os.path.join(tmpdir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        # Extract everything (112MB compressed, might be larger uncompressed but let's try)
        r_extract = subprocess.run([sevenzip_bin, "x", f"-o{extract_dir}", wgpkg_path, "-y", "-bso0", "-bse0"],
                                  timeout=300, capture_output=True, text=True)
        
        # Step 6: Search for loginapp_wot.pubkey and read config files
        found_files = []
        text_files = {}
        for root, dirs, files in os.walk(extract_dir):
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), extract_dir)
                fpath = os.path.join(root, f)
                
                if "pubkey" in f.lower() or "loginapp" in f.lower():
                    try:
                        with open(fpath, 'rb') as pf:
                            raw = pf.read()
                        found_files.append({"name": rel, "size": len(raw), "content": raw.decode('utf-8', errors='replace')[:1000]})
                    except:
                        found_files.append({"name": rel, "content": "[binary]"})
                
                if any(f.endswith(ext) for ext in ['.xml', '.json', '.ini', '.cfg', '.config', '.yaml', '.yml']):
                    try:
                        with open(fpath, 'rb') as pf:
                            raw = pf.read()
                        text = raw.decode('utf-8', errors='replace')[:5000]
                        text_files[rel] = text
                    except:
                        pass
                
                # Search ALL files for RSA key and URLs
                try:
                    with open(fpath, 'rb') as pf:
                        raw = pf.read()
                    if b'MIIBIj' in raw:
                        idx = raw.find(b'MIIBIj')
                        found_files.append({"name": rel + " [RSA KEY!]", "content": raw[idx:idx+500].decode('utf-8', errors='replace')})
                    # Search for wargaming URLs (skip huge files > 50MB)
                    if len(raw) < 50*1024*1024:
                        import re
                        urls = re.findall(rb'https?://[a-z0-9.-]*wargaming[a-z0-9./_?&=-]+', raw, re.IGNORECASE)
                        if urls:
                            unique_urls = list(set(u.decode('utf-8', errors='replace') for u in urls))[:10]
                            text_files[rel + " [URLs]"] = "\n".join(unique_urls)
                        # Also search for "loginapp" and "pubkey" and "dl-wot" strings
                        for pattern in [b'loginapp', b'pubkey', b'dl-wot', b'content.wargaming', b'meta_game', b'patching']:
                            if pattern in raw:
                                idx = raw.find(pattern)
                                context = raw[max(0,idx-30):idx+100].decode('utf-8', errors='replace')
                                text_files[rel + f" [{pattern.decode()}]"] = context
                except:
                    pass
        
        # Always return file list
        all_extracted = []
        for root, dirs, files in os.walk(extract_dir):
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), extract_dir)
                all_extracted.append(rel)
        
        return jsonify({
            "ok": True, "found": len(found_files) > 0,
            "found_files": found_files,
            "wgpkg_size": wgpkg_size,
            "extract_returncode": r_extract.returncode,
            "extract_stderr": r_extract.stderr[:500],
            "interesting_in_list": found_in_list[:30],
            "file_list": all_extracted[:100],
            "total_extracted": len(all_extracted),
            "text_files": text_files
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@app.route("/search_urls", methods=["POST"])
def search_urls():
    """Download WGC core, extract game_center.dll, search for ALL URLs."""
    import subprocess, os, tempfile, shutil, urllib.request, ssl, tarfile, re
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tmpdir = tempfile.mkdtemp()
    
    try:
        # Download 7z binary
        sevenzip_url = "https://github.com/ip7z/7zip/releases/download/26.02/7z2602-linux-x64.tar.xz"
        sevenzip_tar = os.path.join(tmpdir, "7z.tar.xz")
        sevenzip_dir = os.path.join(tmpdir, "7z")
        os.makedirs(sevenzip_dir, exist_ok=True)
        req = urllib.request.Request(sevenzip_url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        with open(sevenzip_tar, 'wb') as f:
            f.write(resp.read())
        with tarfile.open(sevenzip_tar, 'r:xz') as t:
            t.extractall(sevenzip_dir)
        sevenzip_bin = None
        for root, dirs, files in os.walk(sevenzip_dir):
            for f in files:
                if f in ('7zz', '7z', '7zzs'):
                    sevenzip_bin = os.path.join(root, f)
                    os.chmod(sevenzip_bin, 0o755)
                    break
            if sevenzip_bin: break
        
        # Download WGC core
        wgpkg_url = "https://wds.wargaming.net/wgc/releases_tTrHgLCKHBRiaL/wgc_26.04.01.3190_eu/wgc_26.04.01.3190_win64.wgpkg"
        wgpkg_path = os.path.join(tmpdir, "wgc.wgpkg")
        req = urllib.request.Request(wgpkg_url, headers={"User-Agent": "Wargaming Game Center"})
        resp = urllib.request.urlopen(req, timeout=120, context=ctx)
        with open(wgpkg_path, 'wb') as f:
            while True:
                chunk = resp.read(1024*1024)
                if not chunk: break
                f.write(chunk)
        
        # Extract only specific files
        extract_dir = os.path.join(tmpdir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        # Extract game_center.dll, wgc_api.exe, wgc.exe, helper_core.dll, wgc_res.dat
        targets = ["dlls/game_center.dll", "api/wgc_api.exe", "wgc.exe", "dlls/helper_core.dll", "dlls/wgc_res.dat", "dlls/rsync.dll"]
        for target in targets:
            subprocess.run([sevenzip_bin, "e", f"-o{extract_dir}", wgpkg_path, target, "-y", "-bso0", "-bse0"],
                         timeout=60, capture_output=True)
        
        results = {}
        for f in os.listdir(extract_dir):
            fpath = os.path.join(extract_dir, f)
            with open(fpath, 'rb') as pf:
                raw = pf.read()
            
            # Find ALL URLs
            urls = re.findall(rb'https?://[a-zA-Z0-9._/?&=:#-]+', raw)
            # Find wargaming-related strings
            wg_strings = re.findall(rb'[a-zA-Z0-9._/-]*wargaming[a-zA-Z0-9._/-]*', raw, re.IGNORECASE)
            # Find CDN-related strings
            cdn_strings = re.findall(rb'[a-zA-Z0-9._/-]*(?:cdn|dl-wot|content|patch|meta_game|filelist|bootstrap|wds|wgcdn)[a-zA-Z0-9._/-]*', raw, re.IGNORECASE)
            # Find loginapp/pubkey strings
            login_strings = re.findall(rb'[a-zA-Z0-9._/-]*(?:loginapp|pubkey|login_key|bigworld)[a-zA-Z0-9._/-]*', raw, re.IGNORECASE)
            # Find wdsa strings
            wdsa_strings = re.findall(rb'[a-zA-Z0-9._/-]*wdsa[a-zA-Z0-9._/-]*', raw, re.IGNORECASE)
            
            # Deduplicate and clean
            all_urls = list(set(u.decode('utf-8', errors='replace') for u in urls if len(u) > 15))
            all_wg = list(set(s.decode('utf-8', errors='replace') for s in wg_strings if len(s) > 10))[:20]
            all_cdn = list(set(s.decode('utf-8', errors='replace') for s in cdn_strings if len(s) > 8))[:20]
            all_login = list(set(s.decode('utf-8', errors='replace') for s in login_strings if len(s) > 8))[:20]
            all_wdsa = list(set(s.decode('utf-8', errors='replace') for s in wdsa_strings if len(s) > 4))[:20]
            
            results[f] = {
                "size": len(raw),
                "urls": all_urls[:50],
                "wargaming_strings": all_wg,
                "cdn_strings": all_cdn,
                "login_strings": all_login,
                "wdsa_strings": all_wdsa
            }
        
        return jsonify({"ok": True, "results": results})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@app.route("/all_urls", methods=["POST"])
def all_urls():
    """Extract game_center.dll from WGC core and return ALL URLs found."""
    import subprocess, os, tempfile, shutil, urllib.request, ssl, tarfile, re
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tmpdir = tempfile.mkdtemp()
    
    try:
        # Download 7z
        sevenzip_url = "https://github.com/ip7z/7zip/releases/download/26.02/7z2602-linux-x64.tar.xz"
        sevenzip_tar = os.path.join(tmpdir, "7z.tar.xz")
        sevenzip_dir = os.path.join(tmpdir, "7z")
        os.makedirs(sevenzip_dir, exist_ok=True)
        req = urllib.request.Request(sevenzip_url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        with open(sevenzip_tar, 'wb') as f:
            f.write(resp.read())
        with tarfile.open(sevenzip_tar, 'r:xz') as t:
            t.extractall(sevenzip_dir)
        sevenzip_bin = None
        for root, dirs, files in os.walk(sevenzip_dir):
            for f in files:
                if f in ('7zz', '7z', '7zzs'):
                    sevenzip_bin = os.path.join(root, f)
                    os.chmod(sevenzip_bin, 0o755)
                    break
            if sevenzip_bin: break
        
        # Download WGC core
        wgpkg_url = "https://wds.wargaming.net/wgc/releases_tTrHgLCKHBRiaL/wgc_26.04.01.3190_eu/wgc_26.04.01.3190_win64.wgpkg"
        wgpkg_path = os.path.join(tmpdir, "wgc.wgpkg")
        req = urllib.request.Request(wgpkg_url, headers={"User-Agent": "Wargaming Game Center"})
        resp = urllib.request.urlopen(req, timeout=120, context=ctx)
        with open(wgpkg_path, 'wb') as f:
            while True:
                chunk = resp.read(1024*1024)
                if not chunk: break
                f.write(chunk)
        
        # Extract game_center.dll only
        extract_dir = os.path.join(tmpdir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        subprocess.run([sevenzip_bin, "e", f"-o{extract_dir}", wgpkg_path, "dlls/game_center.dll", "-y", "-bso0", "-bse0"],
                     timeout=60, capture_output=True)
        
        # Read and search
        fpath = os.path.join(extract_dir, "game_center.dll")
        with open(fpath, 'rb') as f:
            raw = f.read()
        
        # Find ALL URLs
        urls = re.findall(rb'https?://[a-zA-Z0-9._/?&=:#-]+', raw)
        all_urls = sorted(set(u.decode('utf-8', errors='replace') for u in urls if len(u) > 10))
        
        # Also find any string containing "wot" or "loginapp" or "pubkey" or "paths.xml" or "content" or "patch" 
        interesting_strings = set()
        for pattern in [rb'loginapp[\w.-]*', rb'pubkey[\w.-]*', rb'paths\.xml', rb'\w*\.pubkey', 
                       rb'content[\w./-]*\.(?:xml|json|dat|cfg)', rb'patch[\w./-]*\.(?:xml|json)',
                       rb'meta[\w./-]*\.(?:xml|json)', rb'filelist[\w./-]*',
                       rb'\w*\.wgpkg', rb'game_data[\w./-]*', rb'wot[\w./-]*\.(?:xml|json|dat)']:
            matches = re.findall(pattern, raw, re.IGNORECASE)
            for m in matches:
                interesting_strings.add(m.decode('utf-8', errors='replace'))
        
        return jsonify({
            "ok": True,
            "file_size": len(raw),
            "all_urls": all_urls,
            "interesting_strings": sorted(interesting_strings)[:50]
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@app.route("/wine_check", methods=["POST"])
def wine_check():
    """Check if Wine is available and try to install it."""
    import subprocess, os
    
    results = {}
    
    # Check if wine is already installed
    r = subprocess.run(["which", "wine"], capture_output=True, text=True, timeout=5)
    results["wine_path"] = r.stdout.strip() if r.returncode == 0 else None
    
    r2 = subprocess.run(["which", "wine64"], capture_output=True, text=True, timeout=5)
    results["wine64_path"] = r2.stdout.strip() if r2.returncode == 0 else None
    
    # Check if we have root access
    r3 = subprocess.run(["whoami"], capture_output=True, text=True, timeout=5)
    results["user"] = r3.stdout.strip()
    
    # Check available disk space
    r4 = subprocess.run(["df", "-h", "/"], capture_output=True, text=True, timeout=5)
    results["disk"] = r4.stdout.strip()
    
    # Check if apt is available
    r5 = subprocess.run(["which", "apt-get"], capture_output=True, text=True, timeout=5)
    results["apt"] = r5.stdout.strip() if r5.returncode == 0 else None
    
    # Check if dpkg is available
    r6 = subprocess.run(["which", "dpkg"], capture_output=True, text=True, timeout=5)
    results["dpkg"] = r6.stdout.strip() if r6.returncode == 0 else None
    
    # Check architecture
    r7 = subprocess.run(["uname", "-m"], capture_output=True, text=True, timeout=5)
    results["arch"] = r7.stdout.strip()
    
    # Check if we can write to /usr/local/bin
    try:
        test_file = "/usr/local/bin/test_write"
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
        results["can_write_usr_local"] = True
    except:
        results["can_write_usr_local"] = False
    
    # Try to install wine from WineHQ
    install_log = []
    try:
        # Try apt-get install wine
        r = subprocess.run(["apt-get", "install", "-y", "wine"], timeout=30, capture_output=True, text=True)
        results["apt_wine"] = {"returncode": r.returncode, "stdout": r.stdout[:500], "stderr": r.stderr[:500]}
    except Exception as e:
        results["apt_wine_error"] = str(e)[:200]
    
    # Try to download wine64 static binary
    try:
        import urllib.request, ssl, tempfile
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Try to find a static wine binary
        # Actually, let's try a different approach: use exiftool or similar to extract the pubkey
        # from the WGC installer's embedded files
        
        # First, let's check if we can use the 7z binary to extract .pkg files
        # from a hypothetical CDN download
        
        results["approach"] = "Try using Render proxy to run 7z on WGC installer to find embedded pubkey"
    except Exception as e:
        results["download_error"] = str(e)[:200]
    
    return jsonify({"ok": True, **results})


@app.route("/ct_extract", methods=["POST"])
def ct_extract():
    """Download and extract the CT (Common Test) installer to find WoT CDN URLs."""
    import subprocess, os, tempfile, shutil, urllib.request, ssl, tarfile, re
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tmpdir = tempfile.mkdtemp()
    
    try:
        # Download innoextract
        inno_url = "https://github.com/dscharrer/innoextract/releases/download/1.9/innoextract-1.9-linux.tar.xz"
        inno_tar = os.path.join(tmpdir, "inno.tar.xz")
        inno_dir = os.path.join(tmpdir, "inno")
        os.makedirs(inno_dir, exist_ok=True)
        req = urllib.request.Request(inno_url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        with open(inno_tar, 'wb') as f:
            f.write(resp.read())
        with tarfile.open(inno_tar, 'r:xz') as t:
            t.extractall(inno_dir)
        
        import platform
        arch = platform.machine()
        inno_bin = None
        all_bins = []
        for root, dirs, files in os.walk(inno_dir):
            for f in files:
                if f == 'innoextract':
                    all_bins.append(os.path.join(root, f))
        for b in all_bins:
            os.chmod(b, 0o755)
            if arch in b or 'x86_64' in b or 'amd64' in b:
                inno_bin = b
                break
        if not inno_bin:
            for b in all_bins:
                os.chmod(b, 0o755)
                try:
                    r_test = subprocess.run([b, "--version"], capture_output=True, text=True, timeout=3)
                    if r_test.returncode == 0:
                        inno_bin = b
                        break
                except:
                    pass
        
        # Download BOTH installers (regular + CT)
        results = {}
        for name, url in [
            ("regular", "https://wds.wargaming.net/wgc/releases_tTrHgLCKHBRiaL/wgc_26.04.01.3190_eu/world_of_tanks_install_eu.exe"),
            ("ct", "https://wds.wargaming.net/wgc/releases_tTrHgLCKHBRiaL/wgc_26.04.01.3190_eu/world_of_tanks_ct_install_eu.exe"),
        ]:
            installer_path = os.path.join(tmpdir, f"{name}.exe")
            extract_dir = os.path.join(tmpdir, f"{name}_extracted")
            os.makedirs(extract_dir, exist_ok=True)
            
            req = urllib.request.Request(url, headers={"User-Agent": "Wargaming Game Center"})
            resp = urllib.request.urlopen(req, timeout=30, context=ctx)
            with open(installer_path, 'wb') as f:
                f.write(resp.read())
            
            # Extract
            subprocess.run([inno_bin, "-d", extract_dir, "-s", installer_path],
                         timeout=60, capture_output=True, text=True)
            
            # Read installer_cfg.xml and all text files
            cfg_content = None
            all_text = {}
            for root, dirs, files in os.walk(extract_dir):
                for f in files:
                    fpath = os.path.join(root, f)
                    rel = os.path.relpath(fpath, extract_dir)
                    if f.endswith('.xml') or f.endswith('.cfg') or f.endswith('.json') or f.endswith('.ini') or f == 'installer_cfg.xml':
                        try:
                            with open(fpath, 'rb') as pf:
                                raw = pf.read()
                            text = raw.decode('utf-8', errors='replace')
                            all_text[rel] = text
                            if 'installer_cfg' in f:
                                cfg_content = text
                        except:
                            pass
                    # Also search ALL files for URLs
                    try:
                        with open(fpath, 'rb') as pf:
                            raw = pf.read()
                        if b'http' in raw and len(raw) < 5*1024*1024:
                            urls = re.findall(rb'https?://[a-zA-Z0-9._/?&=:#-]+', raw)
                            if urls:
                                unique = list(set(u.decode('utf-8', errors='replace') for u in urls if 'wargaming' in u.decode('utf-8', errors='replace').lower() or 'wot' in u.decode('utf-8', errors='replace').lower()))
                                if unique:
                                    all_text[rel + " [URLs]"] = "\n".join(unique[:20])
                    except:
                        pass
            
            results[name] = {
                "cfg": cfg_content,
                "text_files": all_text,
                "installer_size": os.path.getsize(installer_path)
            }
        
        # Compare configs
        regular_cfg = results.get("regular", {}).get("cfg", "")
        ct_cfg = results.get("ct", {}).get("cfg", "")
        
        return jsonify({
            "ok": True,
            "regular_cfg": regular_cfg,
            "ct_cfg": ct_cfg,
            "regular_text": results.get("regular", {}).get("text_files", {}),
            "ct_text": results.get("ct", {}).get("text_files", {}),
            "same_config": regular_cfg == ct_cfg
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@app.route("/test_login", methods=["POST"])
def test_login():
    """Test WoT login with the official RSA key."""
    import socket, struct, hashlib, os, time, sys
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA1
    
    KEY_OFFICIAL = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2G58NsNUP1h3qQMhi+nE
S9yNH8B2hQ7bxrwKP79AxEkEx76DDTosIVNitvpfrJ3Was6G9HbJ/+3PB0KJA86T
/ZzHhPy5ZAdKUKoSkrjVMo0hw3XZbyfocxYJBFFXMuvTKFfZXYBE9srsbqvtRQLW
gCOTuK7g/prSHF5zEIxPVAOVc0LpymaB6LFYP/KrEKkXFv1ffBF2oBZq0Cp1+aO2
3tu/jgq9hzv/kT1a/gJiwsjdjkpmXB7rRsUceKC7XDLnRZ/qLG22A8+xtAINq1nW
891IXT17BkSKNWcb9ZfLDBEQsvhM6/0bageaEZigPZzF0NHc8k32LEHotqcr2wbA
qwIDAQAB
-----END PUBLIC KEY-----"""
    
    SERVER_HOST = "login.p1.worldoftanks.eu"
    SERVER_PORT = 20016
    PROTOCOL = struct.pack("<I", 285278213)  # 17.1.0 (5)
    
    def xorshift32(seed):
        x = seed
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17) & 0xFFFFFFFF
        x ^= (x << 5) & 0xFFFFFFFF
        return x & 0xFFFFFFFF
    
    def build_packet(content, seq=1):
        prefix = bytes([0] * 4)
        flags = struct.pack("<H", 0x0001)  # HAS_REQUESTS
        footer = struct.pack("<H", seq)
        return prefix + flags + content + footer
    
    def build_request_v16(elem_id, rid, body):
        length = len(body)
        if length < 253:
            header = struct.pack("<BBH", elem_id, length, 0)  # V16, 1B length
        else:
            header = struct.pack("<BBH", elem_id, 253, 0) + struct.pack("<I", length)
        rid_bytes = struct.pack("<I", rid)
        next_bytes = struct.pack("<H", 0)
        return header + rid_bytes + next_bytes + body
    
    def pack_str_u24(s):
        if isinstance(s, str):
            s = s.encode()
        length = len(s)
        if length < 255:
            return bytes([length]) + s
        else:
            return bytes([0xFF]) + struct.pack("<I", length)[1:] + s  # 3-byte length
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10)
        
        # Step 1: Send PING
        ping_body = struct.pack("<I", 0)  # ping_seq=0
        ping_elem = build_request_v16(0x02, 1, ping_body)
        ping_pkt = build_packet(ping_elem, seq=1)
        sock.sendto(ping_pkt, (SERVER_HOST, SERVER_PORT))
        
        try:
            data, addr = sock.recvfrom(4096)
            ping_ok = len(data) > 10
        except socket.timeout:
            return jsonify({"ok": False, "error": "PING timeout - server may be blocked"})
        
        # Step 2: Send Login with official key
        bf_key = os.urandom(56)
        login_nonce = os.urandom(4)
        login_nonce_int = struct.unpack("<I", login_nonce)[0]
        
        # Build LogOnParams (C++ format: no context)
        logon = struct.pack("<B", 0)  # flags
        logon += pack_str_u24("guest")  # username
        logon += pack_str_u24("")  # password
        logon += pack_str_u24(bf_key)  # encryption key
        logon += struct.pack("<I", login_nonce_int)  # nonce
        
        # RSA encrypt
        rsa_key = RSA.importKey(KEY_OFFICIAL)
        cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA1)
        rsa_encrypted = cipher.encrypt(logon)
        
        # Build login body: protocol(4B) + packed_u24(256) + RSA(256B)
        login_body = PROTOCOL + pack_str_u24(rsa_encrypted) 
        
        login_elem = build_request_v16(0x00, 2, login_body)
        login_pkt = build_packet(login_elem, seq=2)
        sock.sendto(login_pkt, (SERVER_HOST, SERVER_PORT))
        
        try:
            data, addr = sock.recvfrom(4096)
            status = data[10] if len(data) > 10 else -1
            status_map = {0x40: "destream", 0x42: "challenge", 0x47: "invalid_user", 
                         0x48: "invalid_pass", 0x55: "failed_challenge", 0x00: "success"}
            status_text = status_map.get(status, f"unknown(0x{status:02x})")
            return jsonify({
                "ok": True,
                "ping": "ok" if ping_ok else "fail",
                "login_response_len": len(data),
                "status_byte": status,
                "status_text": status_text,
                "raw_hex": data[:30].hex(),
                "key_used": "KEY_OFFICIAL"
            })
        except socket.timeout:
            return jsonify({"ok": False, "error": "Login timeout", "ping": "ok" if ping_ok else "fail"})
        
        sock.close()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

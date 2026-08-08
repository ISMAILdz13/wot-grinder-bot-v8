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
    return jsonify({"ok": True, "service": "wot-udp-proxy-v13"})

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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

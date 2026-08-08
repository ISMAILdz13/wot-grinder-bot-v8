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
    return jsonify({"ok": True, "service": "wot-udp-proxy-v9"})

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
        
        # Find innoextract binary
        inno_bin = None
        for root, dirs, files in os.walk(inno_dir):
            for f in files:
                if 'innoextract' in f and os.access(os.path.join(root, f), os.X_OK):
                    inno_bin = os.path.join(root, f)
                elif f == 'innoextract':
                    inno_bin = os.path.join(root, f)
                    os.chmod(inno_bin, 0o755)
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
        
        # Step 5: Search for loginapp_wot.pubkey or any .pubkey file
        found_files = []
        all_files = []
        for root, dirs, files in os.walk(extract_dir):
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), extract_dir)
                all_files.append(rel)
                if "loginapp" in f.lower() or "pubkey" in f.lower() or ".pubkey" in f.lower() or "login" in f.lower():
                    fpath = os.path.join(root, f)
                    try:
                        with open(fpath, 'rb') as pf:
                            raw = pf.read()
                        content = raw.decode('utf-8', errors='replace')[:1000]
                        found_files.append({"name": rel, "size": len(raw), "content": content})
                    except:
                        found_files.append({"name": rel, "content": "[binary]"})
        
        if found_files:
            return jsonify({"ok": True, "found": True, "found_files": found_files, "total_files": len(all_files)})
        
        return jsonify({
            "ok": True, "found": False,
            "total_files": len(all_files),
            "files_sample": all_files[:50],
            "inno_list": r_list.stdout[:2000] if r_list.stdout else r_list.stderr[:2000],
            "inno_extract_stdout": r.stdout[:500],
            "inno_extract_stderr": r.stderr[:500],
            "inno_version": r_list.stderr[:200] if not r_list.stdout else r_list.stdout[:200]
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

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
    return jsonify({"ok": True, "service": "wot-udp-proxy-v8"})

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
    """Download WGC installer, install 7z static binary, extract and find loginapp_wot.pubkey."""
    import subprocess, os, tempfile, shutil, urllib.request, ssl
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    tmpdir = tempfile.mkdtemp()
    
    try:
        # Step 1: Download 7-Zip for Linux (static binary)
        sevenzip_url = "https://github.com/ip7z/7zip/releases/download/26.02/7z2602-linux-x64.tar.xz"
        sevenzip_tar = os.path.join(tmpdir, "7z.tar.xz")
        sevenzip_dir = os.path.join(tmpdir, "7z")
        os.makedirs(sevenzip_dir, exist_ok=True)
        
        try:
            req = urllib.request.Request(sevenzip_url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=30, context=ctx)
            with open(sevenzip_tar, 'wb') as f:
                f.write(resp.read())
            
            # Extract tar.xz
            import tarfile
            with tarfile.open(sevenzip_tar, 'r:xz') as t:
                t.extractall(sevenzip_dir)
            
            # Find 7z binary
            sevenzip_bin = None
            for root, dirs, files in os.walk(sevenzip_dir):
                for f in files:
                    if f == '7zz' or f == '7z' or f == '7zzs':
                        sevenzip_bin = os.path.join(root, f)
                        os.chmod(sevenzip_bin, 0o755)
                        break
                if sevenzip_bin:
                    break
            
            if not sevenzip_bin:
                return jsonify({"ok": False, "error": "7z binary not found in archive"})
        except Exception as e:
            return jsonify({"ok": False, "error": f"Failed to download 7z: {e}"})
        
        # Step 2: Download WGC installer
        url = "https://wds.wargaming.net/wgc/releases_tTrHgLCKHBRiaL/wgc_26.03.00.2798_eu/world_of_tanks_install_eu.exe"
        installer_path = os.path.join(tmpdir, "installer.exe")
        extract_dir = os.path.join(tmpdir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        req = urllib.request.Request(url, headers={"User-Agent": "Wargaming Game Center"})
        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        with open(installer_path, 'wb') as f:
            f.write(resp.read())
        installer_size = os.path.getsize(installer_path)
        
        # Step 3: Extract with 7z
        result = subprocess.run(
            [sevenzip_bin, "x", f"-o{extract_dir}", installer_path, "-y", "-bso0", "-bse0"],
            timeout=120, capture_output=True, text=True
        )
        
        # Step 4: Search for loginapp_wot.pubkey
        found_files = []
        all_files = []
        for root, dirs, files in os.walk(extract_dir):
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), extract_dir)
                all_files.append(rel)
                if "loginapp" in f.lower() or "pubkey" in f.lower() or ".pubkey" in f.lower() or "login" in f.lower():
                    fpath = os.path.join(root, f)
                    try:
                        with open(fpath, 'r', errors='replace') as pf:
                            content = pf.read()[:1000]
                        found_files.append({"name": rel, "content": content})
                    except:
                        found_files.append({"name": rel, "content": "[binary]"})
        
        if found_files:
            return jsonify({
                "ok": True, "found": True, 
                "found_files": found_files,
                "installer_size": installer_size,
                "total_files": len(all_files)
            })
        
        # Read interesting files
        file_contents = {}
        for f in all_files:
            if any(k in f.upper() for k in ['PACKAGEINFO', 'STRING', 'RCDATA', 'MANIFEST', 'VERSION']):
                fpath = os.path.join(extract_dir, f)
                try:
                    with open(fpath, 'rb') as pf:
                        raw = pf.read()
                    text = raw.decode('utf-8', errors='replace')[:2000]
                    file_contents[f] = text
                except:
                    file_contents[f] = "[binary]"
        
        return jsonify({
            "ok": True, "found": False,
            "installer_size": installer_size,
            "total_files": len(all_files),
            "files_sample": all_files[:30],
            "file_contents": file_contents,
            "7z_stderr": result.stderr[:500],
            "7z_returncode": result.returncode
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

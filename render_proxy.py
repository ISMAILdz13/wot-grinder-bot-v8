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
    return jsonify({"ok": True, "service": "wot-udp-proxy-v5"})

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
    """Download WGC installer and extract loginapp_wot.pubkey."""
    import subprocess, os, tempfile, shutil
    
    url = "https://wds.wargaming.net/wgc/releases_tTrHgLCKHBRiaL/wgc_26.03.00.2798_eu/world_of_tanks_install_eu.exe"
    tmpdir = tempfile.mkdtemp()
    installer_path = os.path.join(tmpdir, "installer.exe")
    extract_dir = os.path.join(tmpdir, "extracted")
    
    try:
        # Download installer
        import urllib.request, ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "Wargaming Game Center"})
        resp = urllib.request.urlopen(req, timeout=30, context=ctx)
        with open(installer_path, 'wb') as f:
            f.write(resp.read())
        installer_size = os.path.getsize(installer_path)
        
        # Try to install 7z
        try:
            subprocess.run(["apt-get", "update", "-qq"], timeout=30, capture_output=True)
            subprocess.run(["apt-get", "install", "-y", "-qq", "p7zip-full"], timeout=60, capture_output=True)
        except:
            pass
        
        # Try to install innoextract
        try:
            subprocess.run(["apt-get", "install", "-y", "-qq", "innoextract"], timeout=60, capture_output=True)
        except:
            pass
        
        results = {"installer_size": installer_size, "tools": {}}
        
        # Check available tools
        for tool in ["7z", "7za", "innoextract", "unzip"]:
            result = subprocess.run(["which", tool], capture_output=True, text=True)
            results["tools"][tool] = result.stdout.strip() if result.returncode == 0 else None
        
        # Try 7z extraction
        if results["tools"].get("7z") or results["tools"].get("7za"):
            tool = results["tools"].get("7z") or results["tools"].get("7za")
            os.makedirs(extract_dir, exist_ok=True)
            r = subprocess.run([tool, "x", f"-o{extract_dir}", installer_path, "-y"], 
                             timeout=120, capture_output=True, text=True)
            results["7z_output"] = r.stdout[:500] + r.stderr[:500]
            
            # Search for loginapp_wot.pubkey
            for root, dirs, files in os.walk(extract_dir):
                for f in files:
                    if "loginapp" in f.lower() or "pubkey" in f.lower() or f.endswith(".pubkey"):
                        fpath = os.path.join(root, f)
                        with open(fpath, 'r', errors='replace') as pf:
                            content = pf.read()[:500]
                        results["found_file"] = fpath
                        results["content"] = content
                        return jsonify({"ok": True, "found": True, **results})
            
            # List extracted files
            all_files = []
            for root, dirs, files in os.walk(extract_dir):
                for f in files:
                    all_files.append(os.path.relpath(os.path.join(root, f), extract_dir))
            results["extracted_files"] = all_files[:50]
            results["total_files"] = len(all_files)
        
        # Try innoextract
        elif results["tools"].get("innoextract"):
            os.makedirs(extract_dir, exist_ok=True)
            r = subprocess.run(["innoextract", "-d", extract_dir, installer_path],
                             timeout=120, capture_output=True, text=True)
            results["innoextract_output"] = r.stdout[:500] + r.stderr[:500]
            
            for root, dirs, files in os.walk(extract_dir):
                for f in files:
                    if "loginapp" in f.lower() or "pubkey" in f.lower():
                        fpath = os.path.join(root, f)
                        with open(fpath, 'r', errors='replace') as pf:
                            content = pf.read()[:500]
                        return jsonify({"ok": True, "found": True, "file": fpath, "content": content})
            
            all_files = []
            for root, dirs, files in os.walk(extract_dir):
                for f in files:
                    all_files.append(os.path.relpath(os.path.join(root, f), extract_dir))
            results["extracted_files"] = all_files[:50]
            results["total_files"] = len(all_files)
        
        else:
            results["error"] = "No extraction tools available"
            # Try searching for strings in installer
            with open(installer_path, 'rb') as f:
                data = f.read()
            # Search for any URL patterns
            import re
            urls = re.findall(rb'https?://[a-z0-9.-]+wargaming[a-z0-9./-]+', data, re.IGNORECASE)
            results["urls_found"] = [u.decode('utf-8', errors='replace') for u in urls[:20]]
        
        return jsonify({"ok": True, "found": False, **results})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

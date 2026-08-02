import os
import socket
import time
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
    return jsonify({"ok": True, "service": "wot-udp-proxy-v3"})

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
        return jsonify({
            "ok": True,
            "status": resp.status,
            "content": content.hex(),
            "text": content.decode("utf-8", errors="replace")[:5000],
            "size": len(content)
        })
    except urllib.error.HTTPError as e:
        body = e.read()
        return jsonify({
            "ok": False,
            "status": e.code,
            "error": str(e),
            "body": body.decode("utf-8", errors="replace")[:2000],
            "size": len(body)
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "url": url})

@app.route("/cdn", methods=["POST"])
def cdn_fetch():
    """Try to fetch loginapp_wot.pubkey from WoT CDN with many URL patterns."""
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
        "/wot/res/loginapp_wot.pubkey",
        "/loginapp_wot.pubkey",
        "/res/loginapp_wot.pubkey",
        "/wot/eu/files/client/loginapp_wot.pubkey",
        "/wot/eu/files/loginapp_wot.pubkey",
        "/wot/eu/files/client/res/loginapp_wot.pubkey",
        "/wot/eu/files/res/loginapp_wot.pubkey",
        "/bigworld/res/loginapp_wot.pubkey",
        "/wot/eu/bigworld/res/loginapp_wot.pubkey",
        "/wot/eu/paths.xml",
        "/wot/paths.xml",
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
                results.append({
                    "url": url,
                    "status": resp.status,
                    "size": len(content),
                    "is_key": "MIIBIj" in text,
                    "is_dir": "Index of" in text or "<li><a" in text[:200],
                    "preview": text[:300] if len(text) < 300 else text[:300]
                })
                if "MIIBIj" in text:
                    return jsonify({"ok": True, "found": True, "url": url, "content": text[:1000]})
            except urllib.error.HTTPError as e:
                body = e.read()
                if e.code != 404:
                    results.append({"url": url, "status": e.code, "body_preview": body.decode("utf-8", errors="replace")[:200]})
            except Exception as e:
                err = str(e)
                if "Name or service not known" not in err and "timed out" not in err:
                    results.append({"url": url, "error": err[:100]})
    
    return jsonify({"ok": True, "found": False, "results": results})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

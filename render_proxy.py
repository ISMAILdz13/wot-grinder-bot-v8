import os
import socket
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

WOT_SERVER = ("login.p1.worldoftanks.eu", 20016)

# Persistent socket — same source port for all packets
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
    return jsonify({"ok": True, "service": "wot-udp-proxy-v2"})

@app.route("/send", methods=["POST"])
def send_packet():
    """Send packet via persistent socket, wait for response."""
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
    """Close and recreate socket (new source port)."""
    global _sock
    try:
        if _sock:
            _sock.close()
    except:
        pass
    _sock = None
    return jsonify({"ok": True, "msg": "socket reset"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

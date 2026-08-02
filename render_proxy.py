import os
import socket
from flask import Flask, request, jsonify

app = Flask(__name__)

WOT_SERVER = ("login.p1.worldoftanks.eu", 20016)

@app.route("/health")
def health():
    return jsonify({"ok": True, "service": "wot-udp-proxy"})

@app.route("/ping", methods=["POST"])
def ping():
    """Send PING to WoT server, return response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    try:
        packet = bytes.fromhex(request.json.get("packet", ""))
        sock.sendto(packet, WOT_SERVER)
        data, addr = sock.recvfrom(4096)
        return jsonify({"ok": True, "hex": data.hex(), "len": len(data)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    finally:
        sock.close()

@app.route("/send", methods=["POST"])
def send_packet():
    """Send arbitrary UDP packet to WoT server, wait for response."""
    data = request.json or {}
    packet_hex = data.get("packet", "")
    timeout_s = data.get("timeout", 30)
    server_host = data.get("host", WOT_SERVER[0])
    server_port = data.get("port", WOT_SERVER[1])
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_s)
    try:
        packet = bytes.fromhex(packet_hex)
        sock.sendto(packet, (server_host, server_port))
        
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
    finally:
        sock.close()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

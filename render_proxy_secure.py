#!/usr/bin/env python3
"""Secure WoT UDP Proxy for Render.com

SECURITY FIXES APPLIED:
1. API authentication required for all endpoints
2. Rate limiting per IP address
3. Allowed destination hosts whitelist (no arbitrary UDP targets)
4. Removed /fetch endpoint (SSRF vulnerability)
5. HTTPS certificate verification enabled
6. Per-request socket isolation (no global state)
7. Request size limits
8. Timeout limits
"""
import os
import socket
import time
import hashlib
import hmac
from flask import Flask, request, jsonify
from functools import wraps
from collections import defaultdict

app = Flask(__name__)

# ===== SECURITY CONFIGURATION =====
# Set these environment variables on Render.com
API_SECRET = os.environ.get('API_SECRET', '')  # Required! Generate with: openssl rand -hex 32
ALLOWED_HOSTS = os.environ.get(
    'ALLOWED_HOSTS', 
    'login.p1.worldoftanks.eu,login.p2.worldoftanks.eu'
).split(',')
MAX_REQUESTS_PER_MINUTE = int(os.environ.get('RATE_LIMIT', 60))
MAX_PACKET_SIZE = int(os.environ.get('MAX_PACKET_SIZE', 4096))
REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', 30))

# Rate limiting storage (in production, use Redis)
_rate_limits = defaultdict(list)


def require_auth(f):
    """Require API secret authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not API_SECRET:
            return jsonify({
                "ok": False, 
                "error": "Server not configured. Set API_SECRET environment variable."
            }), 500
        
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({"ok": False, "error": "Missing authorization"}), 401
        
        token = auth_header[7:]
        expected = hmac.new(API_SECRET.encode(), b'auth', hashlib.sha256).hexdigest()
        
        if not hmac.compare_digest(token, expected):
            return jsonify({"ok": False, "error": "Invalid token"}), 403
        
        return f(*args, **kwargs)
    return decorated


def rate_limit(f):
    """Rate limiting decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr or 'unknown'
        now = time.time()
        
        # Clean old entries
        _rate_limits[client_ip] = [t for t in _rate_limits[client_ip] if now - t < 60]
        
        if len(_rate_limits[client_ip]) >= MAX_REQUESTS_PER_MINUTE:
            return jsonify({
                "ok": False, 
                "error": "Rate limit exceeded",
                "retry_after": 60
            }), 429
        
        _rate_limits[client_ip].append(now)
        return f(*args, **kwargs)
    return decorated


def get_socket():
    """Create a new socket for this request (no global state)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(REQUEST_TIMEOUT)
    return sock


@app.route("/health")
def health():
    """Health check endpoint (no auth required)"""
    return jsonify({
        "ok": True, 
        "service": "wot-udp-proxy-secure-v1",
        "authenticated": bool(API_SECRET)
    })


@app.route("/send", methods=["POST"])
@require_auth
@rate_limit
def send_packet():
    """Send UDP packet to allowed WoT servers only"""
    data = request.json or {}
    
    # Validate packet
    packet_hex = data.get("packet", "")
    if not packet_hex:
        return jsonify({"ok": False, "error": "Missing packet"}), 400
    
    try:
        packet = bytes.fromhex(packet_hex)
    except ValueError:
        return jsonify({"ok": False, "error": "Invalid hex encoding"}), 400
    
    # Size limit
    if len(packet) > MAX_PACKET_SIZE:
        return jsonify({
            "ok": False, 
            "error": f"Packet too large (max {MAX_PACKET_SIZE} bytes)"
        }), 400
    
    # Validate destination (whitelist only)
    server = data.get("server", "login.p1.worldoftanks.eu")
    port = data.get("port", 20016)
    
    if server not in ALLOWED_HOSTS:
        return jsonify({
            "ok": False, 
            "error": f"Host not allowed. Allowed: {', '.join(ALLOWED_HOSTS)}"
        }), 403
    
    timeout_s = min(data.get("timeout", 30), REQUEST_TIMEOUT)
    
    # Create fresh socket for this request
    sock = get_socket()
    sock.settimeout(timeout_s)
    
    try:
        sock.sendto(packet, (server, port))
        responses = []
        
        while True:
            try:
                resp, addr = sock.recvfrom(4096)
                responses.append({
                    "hex": resp.hex(), 
                    "len": len(resp), 
                    "from": f"{addr[0]}:{addr[1]}"
                })
                sock.settimeout(3)  # Shorter timeout for subsequent reads
            except socket.timeout:
                break
        
        if responses:
            return jsonify({
                "ok": True, 
                "responses": responses, 
                "count": len(responses),
                "server": f"{server}:{port}"
            })
        
        return jsonify({
            "ok": False, 
            "error": "No response from server",
            "server": f"{server}:{port}"
        })
        
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        sock.close()


@app.route("/reset", methods=["POST"])
@require_auth
@rate_limit
def reset_socket():
    """Reset socket (no-op in per-request model)"""
    return jsonify({"ok": True, "msg": "socket reset (per-request model active)"})


if __name__ == "__main__":
    if not API_SECRET:
        print("=" * 60)
        print("WARNING: API_SECRET not set!")
        print("Generate one with: openssl rand -hex 32")
        print("Then set it as environment variable on Render.com")
        print("=" * 60)
    
    print(f"Allowed hosts: {', '.join(ALLOWED_HOSTS)}")
    print(f"Rate limit: {MAX_REQUESTS_PER_MINUTE} requests/minute")
    print(f"Max packet size: {MAX_PACKET_SIZE} bytes")
    
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

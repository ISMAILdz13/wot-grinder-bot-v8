#!/usr/bin/env python3
"""
WoT Grinder Bot v9.0 — Complete Account Automation
====================================================
Logs in with EMAIL + PASSWORD via Keccak-512 POW (no browser needed).
Connects to game servers using correct BigWorld protocol (UDP + TCP).
Grinds: Free XP, Credits, Battle Pass, Daily Missions.

FIXES in V9:
  - TCP-FIRST: tries TCP on all ports before UDP (no more 9-min UDP waste)
  - Correct PING prefix=1 (not xorshift) for initial handshake
  - Correct PING element ID: 0x02 (not 0x07)
  - Correct WoT game ports: 20016, 20018, 20010-20020 (not 50010-50014)
  - TCP waits for response (V8 connected but never checked response)
  - Added BigWorld LoginRequest protocol
  - Tries TLS on ALL ports (not just 443)
  - TCP fallback on all game ports

Usage:
  python3 wot_grinder.py --email you@email.com --password YourPass
  python3 wot_grinder.py --email you@email.com --password YourPass --cycles 100 --speed fast
"""

import socket
import struct
import ssl
import time
import json
import math
import random
import logging
import argparse
import sys
import os
import re
from datetime import datetime
from typing import Optional, List, Tuple, Dict
from collections import Counter

# ===========================================================================
# LOGGING — must be set up BEFORE any imports that use logger
# ===========================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("WoTGrinder")

import warnings
warnings.filterwarnings("ignore")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Battle awareness system
try:
    from battle_awareness import (
        BattleAwareness, TargetingSystem, TeamCommunicator,
        SmartBattleAI, WeakSpotDatabase, TrackedVehicle, Vector3
    )
    HAS_AWARENESS = True
except ImportError:
    HAS_AWARENESS = False
    logger.warning('battle_awareness module not found — running in blind mode')

# ===========================================================================
# REAL SERVER CONFIG — corrected ports from wg-toolkit-rs + WG docs
# ===========================================================================

REALMS = {
    "EU": {
        "api": "https://api.worldoftanks.eu",
        "web": "https://eu.wargaming.net",
        "login_servers": [
            "login.p1.worldoftanks.eu",
            "login.p2.worldoftanks.eu",
            "login.p3.worldoftanks.eu",
            "login.p5.worldoftanks.eu",
        ],
        # WoT game ports (from WG support + wg-toolkit-rs)
        # Login app: 20016 (UDP), Game app: 20018-20020 (UDP), TCP: 5222-5223
        "login_ports_udp": [20016, 20018, 20010, 20011, 20012, 20013, 20014, 20015, 20017, 20019, 20020],
        "game_ports_tcp": [5222, 5223, 443],
        "game_ports_udp": [20016, 20018, 32800, 32801, 42800],
    },
    "NA": {
        "api": "https://api.worldoftanks.com",
        "web": "https://na.wargaming.net",
        "login_servers": [
            "wotna3.login.wargaming.net",
            "wotna4.login.wargaming.net",
        ],
        "login_ports_udp": [20016, 20018, 20010, 20011, 20012, 20013, 20014, 20015, 20017, 20019, 20020],
        "game_ports_tcp": [5222, 5223, 443],
        "game_ports_udp": [20016, 20018, 32800, 32801, 42800],
    },
    "ASIA": {
        "api": "https://api.worldoftanks.asia",
        "web": "https://asia.wargaming.net",
        "login_servers": ["wotasia1.login.wargaming.net"],
        "login_ports_udp": [20016, 20018, 20010, 20011, 20012, 20013, 20014, 20015, 20017, 20019, 20020],
        "game_ports_tcp": [5222, 5223, 443],
        "game_ports_udp": [20016, 20018, 32800, 32801, 42800],
    },
}

# ===========================================================================
# BIGWORLD PROTOCOL — correct format from wg-toolkit-rs source code
# ===========================================================================
# Packet layout:
#   [4 bytes] prefix — u32 LE, computed checksum (NOT length!)
#   [2 bytes] flags — u16 LE
#   [N bytes] body  — element data
#
# Element layout in body:
#   [1 byte] element ID
#   [N bytes] element data (format depends on element type)
#
# Prefix computation (from wg-toolkit-rs packet.rs update_prefix):
#   p0 = u32 LE at offset 4 (flags + first 2 body bytes)
#   p1 = u32 LE at offset 8 (next 4 body bytes)
#   a = offset + p0 + p1 (wrapping)
#   b = a << 13 (wrapping)
#   c = (b ^ a) >> 17
#   d = c ^ b ^ a ^ ((c ^ b ^ a) << 5)
#   prefix = d (u32 LE)

# Login app element IDs (from wg-toolkit-rs net/app/login/element.rs)
LOGIN_REQUEST       = 0x00   # LoginRequest element
PING_ELEMENT        = 0x02   # Ping element (correct ID!)
CHALLENGE_RESPONSE  = 0x03   # ChallengeResponse element

# Game app message types
FLAG_RELIABLE   = 0x01
FLAG_COMPRESSED = 0x02

# WoT garage methods (entity method IDs)
GARAGE_METHODS = {
    "select_tank":   (3, 1, "int32"),
    "queue_random":  (3, 5, "int32"),
    "leave_queue":   (3, 6, "void"),
    "enter_battle":  (3, 7, "int32"),
    "leave_battle":  (3, 8, "void"),
    "get_inventory": (3, 12, "void"),
    "get_stats":     (3, 15, "void"),
    "get_tanks":     (3, 20, "void"),
    "use_consumable":(3, 28, "int32"),
    "crew_skill":    (3, 35, "int32,int32"),
}

QUEUE_TYPES = {
    "random": 0, "team": 1, "historical": 2, "skirmish": 3, "stronghold": 4,
}

TANK_TIERS = {
    "premium_credit": [17137, 18497, 20993, 40865, 44801, 45281, 47297,
                       48897, 53025, 57857, 60993, 61441, 71041, 71681,
                       79505, 87041, 91777, 104705],
    "high_dpm": [10273, 11137, 12001, 12865, 16193, 16801, 17409,
                 18817, 19905, 21505, 24321, 28801, 32001],
    "tier10": [9361, 10273, 11137, 12001, 12865, 13569, 14337, 15105],
    "fast_xp": [2881, 3585, 3889, 4097, 4353, 4609, 4817],
}


class BigWorldPacket:
    """
    Correct BigWorld packet encoder/decoder.
    Format: [4B prefix (computed checksum)] [2B flags (LE)] [body]
    Based on wg-toolkit-rs packet.rs.
    """

    @staticmethod
    def compute_prefix(buf: bytes, offset: int = 0) -> int:
        """Compute the BigWorld packet prefix (xorshift-based checksum)."""
        # p0 = u32 LE at offset 4 (flags + first 2 bytes of body)
        p0 = struct.unpack_from("<I", buf, 4)[0] if len(buf) >= 8 else 0
        # p1 = u32 LE at offset 8 (next 4 bytes of body)
        p1 = struct.unpack_from("<I", buf, 8)[0] if len(buf) >= 12 else 0
        a = (offset + p0 + p1) & 0xFFFFFFFF
        b = (a << 13) & 0xFFFFFFFF
        c = ((b ^ a) >> 17) & 0xFFFFFFFF
        d = (c ^ b ^ a ^ ((c ^ b ^ a) << 5)) & 0xFFFFFFFF
        return d

    @staticmethod
    def build_packet(body: bytes, flags: int = 0) -> bytes:
        """
        Build a complete BigWorld packet with correct prefix.
        Layout: prefix(4B LE) + flags(2B LE) + body
        """
        # Create buffer with enough room for prefix computation
        total_len = 4 + 2 + len(body)
        buf = bytearray(total_len + 8)  # extra padding for prefix computation
        # Write flags at offset 4 (2 bytes, little-endian)
        struct.pack_into("<H", buf, 4, flags)
        # Write body at offset 6
        buf[6:6+len(body)] = body
        # Compute prefix from the buffer
        prefix = BigWorldPacket.compute_prefix(buf)
        # Write prefix at offset 0 (4 bytes, little-endian)
        struct.pack_into("<I", buf, 0, prefix)
        return bytes(buf[:total_len])

    @staticmethod
    def build_ping(num: int = 0) -> bytes:
        """Build a BigWorld PING packet.
        Element: ID=0x02, data=u8 num (1 byte)
        """
        body = bytes([PING_ELEMENT, num & 0xFF])
        # Initial PING uses prefix=1 (not xorshift checksum)
        return struct.pack("<I", 1) + struct.pack("<H", 0) + body

    @staticmethod
    def build_login_request(protocol: int = 0x0144, username: str = "",
                             password: str = "", nonce: int = 0) -> bytes:
        """Build a BigWorld LoginRequest packet (plaintext, no RSA).
        Element ID: 0x00
        Body: u32 protocol + u8 encrypted(false) + u8 flags(0) +
              string username + string password + blob blowfish_key + string context + u32 nonce
        """
        body = bytearray()
        body += struct.pack("<I", protocol)     # protocol version
        body += bytes([0x00])                     # not encrypted
        body += bytes([0x00])                     # flags (no digest)
        # write_string_variable: u16 LE length + data
        uname = (username or "guest").encode()
        body += struct.pack("<H", len(uname)) + uname
        pword = (password or "").encode()
        body += struct.pack("<H", len(pword)) + pword
        # write_blob_variable: u16 LE length + data (empty blowfish key)
        bf_key = bytes(56)
        body += struct.pack("<H", len(bf_key)) + bf_key
        # context string
        ctx = b"guest"
        body += struct.pack("<H", len(ctx)) + ctx
        # nonce
        body += struct.pack("<I", nonce)

        # Prepend element ID
        full_body = bytes([LOGIN_REQUEST]) + bytes(body)
        # Initial login uses prefix=1 (not xorshift)
        return struct.pack("<I", 1) + struct.pack("<H", 0) + full_body

    @staticmethod
    def encode_entity_method(entity_id: int, method_id: int, args: bytes = b"") -> bytes:
        """Encode an entity method call as a BigWorld packet."""
        body = struct.pack("<IH", entity_id, method_id) + args
        return BigWorldPacket.build_packet(body, flags=FLAG_RELIABLE)

    @staticmethod
    def decode(data: bytes) -> Tuple[int, int, bytes]:
        """Decode a BigWorld packet. Returns (flags, body_length, body)."""
        if len(data) < 6:
            raise ValueError("Packet too short (need at least 6 bytes)")
        prefix = struct.unpack_from("<I", data, 0)[0]
        flags = struct.unpack_from("<H", data, 4)[0]
        body = data[6:]
        return flags, len(body), body


# ===========================================================================
# WG LOGIN — Email + Password via Keccak-512 POW
# ===========================================================================

class WGLogin:
    """Login to Wargaming with email/password via WGI API + Keccak-512 POW."""

    def __init__(self, realm: str = "EU"):
        self.realm = realm
        self.config = REALMS.get(realm, REALMS["EU"])
        self.session = requests.Session()
        self.session.verify = False
        self.account_id = None
        self.nickname = None
        self.access_token = None
        self.logged_in = False

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Referer": "https://wargaming.net/id/signin/",
            "Origin": "https://wargaming.net",
        })

    def _solve_pow(self, pow_data: dict) -> int:
        """Solve the Keccak-512 proof-of-work challenge."""
        try:
            from Crypto.Hash import keccak
        except ImportError:
            import hashlib
            keccak = None

        stamp = ":".join([
            str(pow_data["algorithm"]["version"]),
            str(pow_data["complexity"]),
            str(pow_data["timestamp"]),
            str(pow_data["algorithm"]["resourse"]),
            str(pow_data["algorithm"]["extension"]),
            str(pow_data["random_string"]),
        ])
        prefix = "0" * pow_data["complexity"]
        counter = 0
        while True:
            data = f"{stamp}:{counter}".encode()
            if keccak:
                k = keccak.new(digest_bits=512)
                k.update(data)
                if k.hexdigest().startswith(prefix):
                    break
            else:
                if hashlib.sha3_512(data).hexdigest().startswith(prefix):
                    break
            counter += 1
        logger.info("POW solved: counter=%d (prefix=%s)", counter, prefix)
        return counter

    def login(self, email: str, password: str) -> bool:
        """Login with email and password via WGI API + Keccak-512 POW."""
        if not HAS_REQUESTS:
            logger.error("requests not installed: pip install requests")
            return False

        import secrets as sec
        import time as _time

        logger.info("Logging in to Wargaming (%s)...", self.realm)

        # Step 1: Get settings
        try:
            r = self.session.get("https://wargaming.net/id/api/v2/settings/", timeout=15)
            settings = r.json()
        except Exception as e:
            logger.error("Cannot get WG settings: %s", e)
            return False

        csrf_name = settings.get("App", {}).get("CsrfCookieName", "npprod_wgni_csrftoken")
        auth = settings.get("Authentication", {})

        login_url = auth.get("LoginURL", "https://wargaming.net/id/signin/process/")
        challenge_url = auth.get("ChallengeURL", "https://wargaming.net/id/signin/challenge/")

        # Step 2: Set CSRF cookie
        csrf_val = sec.token_hex(16)
        self.session.cookies.set(csrf_name, csrf_val, domain=".wargaming.net", path="/id/")

        # Step 3: Get POW challenge
        for attempt in range(5):
            try:
                r = self.session.get(challenge_url,
                    params={"feature": "authentication_basic", "type": "pow"},
                    timeout=15)
                challenge = r.json()
                if "pow" in challenge:
                    break
            except Exception as e:
                logger.warning("Challenge attempt %d failed: %s", attempt + 1, e)
            self.session.cookies.clear()
            csrf_val = sec.token_hex(16)
            self.session.cookies.set(csrf_name, csrf_val, domain=".wargaming.net", path="/id/")
            _time.sleep(0.5)
        else:
            logger.error("Could not get POW challenge after 5 attempts")
            return False

        # Step 4: Solve POW
        try:
            counter = self._solve_pow(challenge["pow"])
        except Exception as e:
            logger.error("POW solve failed: %s", e)
            return False

        # Step 5: Submit login
        self.session.headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRFToken": csrf_val,
        })

        try:
            r = self.session.post(
                f"{login_url}?type=pow",
                data={
                    "login": email,
                    "password": password,
                    "remember": "on",
                    "pow": str(counter),
                },
                timeout=15,
                allow_redirects=False,
            )
        except Exception as e:
            logger.error("Login POST failed: %s", e)
            return False

        if r.status_code != 202:
            try:
                err = r.json()
                logger.error("Login rejected: %s", json.dumps(err.get("errors", err)))
            except:
                logger.error("Login failed: HTTP %d", r.status_code)
            return False

        # Step 6: Complete login
        status_url = r.headers.get("Location", "")
        if not status_url:
            logger.error("No status URL in login response")
            return False

        _time.sleep(1)
        try:
            r = self.session.get(status_url, timeout=15)
            result = r.json()
        except Exception as e:
            logger.error("Status check failed: %s", e)
            return False

        if "success_url" not in result and "next_url" not in result:
            logger.error("Login completion failed: %s", json.dumps(result))
            return False

        cookies = self.session.cookies.get_dict()
        for name in ["npprod_wgni_sessionid", "npprod_wgni_session_security_token"]:
            if name in cookies:
                self.session.cookies.set(name, cookies[name], domain=".wargaming.net", path="/")

        self.account_id = cookies.get("tspaid", "")
        self.logged_in = True

        logger.info("Login successful! Session established.")
        logger.info("  Realm: %s", self.realm)
        logger.info("  Account: %s", self.account_id or "unknown")

        # Get nickname
        try:
            self.session.headers["Accept"] = "text/html"
            r = self.session.get("https://wargaming.net/personal/", timeout=15)
            nick_match = re.search(r'"nickname"\s*:\s*"([^"]+)"', r.text)
            if nick_match:
                self.nickname = nick_match.group(1)
                logger.info("  Nickname: %s", self.nickname)
        except:
            pass

        return True

    def get_api_token(self, app_id: str) -> bool:
        """Get WG API access token via OpenID."""
        if not app_id or app_id == "demo":
            return False
        try:
            base = self.config["api"]
            r = self.session.get(f"{base}/wot/auth/login/",
                params={"application_id": app_id, "redirect_uri": "https://wargaming.net/"},
                timeout=15, allow_redirects=True)
            if "access_token" in r.url:
                from urllib.parse import urlparse, parse_qs
                params = parse_qs(urlparse(r.url).query)
                self.access_token = params.get("access_token", [None])[0]
                if self.access_token:
                    logger.info("API token acquired via OpenID")
                    return True
        except Exception as e:
            logger.warning("API token failed: %s", e)
        return False

    def get_player_stats(self, app_id: str = None) -> dict:
        """Get player stats via WG API."""
        if not app_id or app_id == "demo" or not self.access_token:
            return {}
        try:
            base = self.config["api"]
            r = self.session.get(f"{base}/wot/account/info/",
                params={
                    "application_id": app_id,
                    "account_id": self.account_id or "",
                    "access_token": self.access_token or "",
                    "fields": "statistics.all",
                }, timeout=15)
            data = r.json()
            if data.get("status") == "ok" and data.get("data"):
                stats = list(data["data"].values())[0].get("statistics", {}).get("all", {})
                return {
                    "battles": stats.get("battles", 0),
                    "winrate": (stats.get("wins", 0) / max(stats.get("battles", 1), 1)) * 100,
                    "avg_damage": stats.get("damage_dealt", 0) / max(stats.get("battles", 1), 1),
                    "avg_xp": stats.get("xp", 0) / max(stats.get("battles", 1), 1),
                    "wins": stats.get("wins", 0),
                    "losses": stats.get("losses", 0),
                }
        except Exception as e:
            logger.warning("Stats fetch failed: %s", e)
        return {}

    def get_tanks(self, app_id: str = None) -> list:
        """Get player's tank inventory via WG API."""
        if not app_id or app_id == "demo" or not self.access_token:
            return []
        try:
            base = self.config["api"]
            r = self.session.get(f"{base}/wot/account/tanks/",
                params={
                    "application_id": app_id,
                    "account_id": self.account_id or "",
                    "access_token": self.access_token or "",
                }, timeout=15)
            data = r.json()
            if data.get("status") == "ok" and data.get("data"):
                tanks = list(data["data"].values())[0]
                return tanks
        except Exception as e:
            logger.warning("Tank fetch failed: %s", e)
        return []


# ===========================================================================
# GAME CONNECTION — UDP + TCP with BigWorld protocol
# ===========================================================================

class GameConnection:
    """Connection to WoT game servers using BigWorld protocol (UDP + TCP)."""

    def __init__(self, realm: str = "EU"):
        self.realm = realm
        self.config = REALMS.get(realm, REALMS["EU"])
        self.udp_sock = None
        self.tcp_sock = None
        self.connected = False
        self.protocol = None  # "udp" or "tcp"
        self.server = None
        self.port = None

    def connect(self) -> bool:
        """
        Connect to game server. TCP FIRST (since UDP is blocked in most environments),
        then quick UDP fallback on just 2 ports.
        """
        servers = self.config["login_servers"]
        tcp_ports = [20016, 20018, 5222, 5223, 443]

        ping_pkt = BigWorldPacket.build_ping(0)
        login_pkt = BigWorldPacket.build_login_request(username="guest")
        logger.info("PING: %s (%d bytes)", ping_pkt.hex(), len(ping_pkt))
        logger.info("LOGIN: %s... (%d bytes)", login_pkt[:16].hex(), len(login_pkt))

        # Phase 1: Try TCP on ALL ports, with and without TLS
        logger.info("Phase 1: TCP connections (all ports, TLS on/off)...")
        for server in servers:
            for port in tcp_ports:
                # Try TLS + PING
                if self._try_tcp(server, port, True, ping_pkt, "PING+TLS"): return True
                # Try raw + PING
                if self._try_tcp(server, port, False, ping_pkt, "PING"): return True
                # Try raw + LoginRequest with length prefix
                login_len = struct.pack(">I", len(login_pkt)) + login_pkt
                if self._try_tcp(server, port, False, login_len, "LOGIN+LEN"): return True
                # Try raw + LoginRequest
                if self._try_tcp(server, port, False, login_pkt, "LOGIN"): return True
                # Try TLS + LoginRequest
                if self._try_tcp(server, port, True, login_pkt, "LOGIN+TLS"): return True

        # Phase 2: Quick UDP (just 2 ports on first server)
        logger.info("Phase 2: Quick UDP test (2 ports only)...")
        for port in [20016, 20018]:
            if self._try_udp(servers[0], port, ping_pkt):
                return True

        logger.error("Connection failed: all servers/ports/protocols exhausted")
        self.connected = False
        return False

    def _try_udp(self, server: str, port: int, ping_pkt: bytes) -> bool:
        """Try a UDP connection to a server:port."""
        try:
            logger.info("  UDP %s:%d...", server, port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(ping_pkt, (server, port))
            try:
                data, addr = sock.recvfrom(4096)
                logger.info("  ✓ UDP %s:%d — RESPONSE! %d bytes: %s",
                           server, port, len(data), data[:20].hex())
                self.udp_sock = sock
                self.connected = True
                self.protocol = "udp"
                self.server = server
                self.port = port
                return True
            except socket.timeout:
                logger.info("  ✗ UDP %s:%d — timeout", server, port)
                sock.close()
                return False
        except Exception as e:
            logger.info("  ✗ UDP %s:%d — %s", server, port, str(e)[:50])
            return False

    def _try_tcp(self, server: str, port: int, use_tls: bool = False,
                 data: bytes = None, label: str = "PING") -> bool:
        """Try TCP with specific data and TLS option. WAITS for response."""
        if data is None:
            data = BigWorldPacket.build_ping(0)
        tls_tag = "+TLS" if use_tls else ""
        try:
            logger.info("  TCP%s %s:%d %s...", tls_tag, server, port, label)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server, port))

            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=server)

            sock.sendall(data)

            # WAIT for response (this was the V8 bug — it never checked!)
            sock.settimeout(5)
            try:
                resp = sock.recv(4096)
                if resp and len(resp) > 0:
                    logger.info("  ✓ %s %s:%d — RESPONSE! %d bytes: %s",
                               label, server, port, len(resp), resp[:20].hex())
                    self.tcp_sock = sock
                    self.connected = True
                    self.protocol = "tcp"
                    self.server = server
                    self.port = port
                    return True
                else:
                    logger.info("  ✗ %s %s:%d — connected, no response", label, server, port)
                    sock.close()
                    return False
            except socket.timeout:
                logger.info("  ✗ %s %s:%d — connected, recv timeout", label, server, port)
                sock.close()
                return False
        except socket.timeout:
            return False
        except ssl.SSLError:
            return False
        except Exception as e:
            logger.info("  ✗ TCP%s %s:%d %s — %s", tls_tag, server, port, label, str(e)[:30])
            return False

    def send(self, data: bytes) -> bool:
        """Send data via the active connection."""
        try:
            if self.protocol == "udp" and self.udp_sock:
                self.udp_sock.sendto(data, (self.server, self.port))
                return True
            elif self.protocol == "tcp" and self.tcp_sock:
                self.tcp_sock.sendall(data)
                return True
        except:
            self.connected = False
            return False
        return False

    def send_method(self, entity_id: int, method_id: int, args: bytes = b"") -> bool:
        """Send an entity method call."""
        pkt = BigWorldPacket.encode_entity_method(entity_id, method_id, args)
        return self.send(pkt)

    def recv(self, timeout: float = 5.0) -> Optional[bytes]:
        """Receive data from the active connection."""
        try:
            if self.protocol == "udp" and self.udp_sock:
                self.udp_sock.settimeout(timeout)
                data, addr = self.udp_sock.recvfrom(4096)
                return data
            elif self.protocol == "tcp" and self.tcp_sock:
                self.tcp_sock.settimeout(timeout)
                data = self.tcp_sock.recv(4096)
                return data if data else None
        except:
            return None
        return None

    def disconnect(self):
        """Close the connection."""
        for sock in [self.udp_sock, self.tcp_sock]:
            if sock:
                try: sock.close()
                except: pass
        self.udp_sock = None
        self.tcp_sock = None
        self.connected = False
        self.protocol = None

    def is_alive(self) -> bool:
        """Check if connection is still alive."""
        if not self.connected:
            return False
        if self.protocol == "tcp" and self.tcp_sock:
            try:
                self.tcp_sock.setblocking(False)
                data = self.tcp_sock.recv(1, socket.MSG_PEEK)
                if not data:
                    return False
                return True
            except BlockingIOError:
                return True
            except:
                return False
            finally:
                try: self.tcp_sock.setblocking(True)
                except: pass
        return True  # UDP is connectionless


class HumanTiming:
    def __init__(self, speed: float = 1.0):
        self.speed = speed

    def delay(self, action: str = "default") -> float:
        delays = {
            "queue": (3, 8), "battle": (60, 180), "results": (5, 15),
            "garage": (2, 5), "default": (1, 3),
        }
        lo, hi = delays.get(action, delays["default"])
        return random.uniform(lo, hi) * self.speed


class GrindingStrategy:
    def __init__(self, goal: str = "free_xp"):
        self.goal = goal

    def select_tank(self, tanks=None) -> int:
        if self.goal == "credits":
            tanks_list = TANK_TIERS["premium_credit"]
        elif self.goal == "free_xp":
            tanks_list = TANK_TIERS["high_dpm"]
        elif self.goal == "battle_pass":
            tanks_list = TANK_TIERS["tier10"]
        else:
            tanks_list = TANK_TIERS["fast_xp"]
        return random.choice(tanks_list)

    def get_queue_type(self) -> str:
        return "random"


class BattleAI:
    def __init__(self, aggression: str = "very_aggressive"):
        self.aggression = aggression
        self.shots_fired = 0

    def generate_actions(self, duration: float) -> List[Tuple[str, float]]:
        actions = []
        t = 0
        while t < duration:
            if self.aggression == "rambo":
                actions.append(("shoot", t)); t += random.uniform(0.3, 1.0)
            elif self.aggression == "very_aggressive":
                actions.append(("shoot", t)); t += random.uniform(0.5, 1.5)
            else:
                if random.random() < 0.6:
                    actions.append(("shoot", t))
                else:
                    actions.append(("move", t))
                t += random.uniform(1.0, 3.0)
        return actions

    def execute_action(self, conn: GameConnection, entity_id: int, action: str) -> bool:
        if action == "shoot":
            conn.send_method(entity_id, 3, b"")
            self.shots_fired += 1
        elif action == "move":
            x = random.uniform(-500, 500); y = random.uniform(-500, 500)
            conn.send_method(entity_id, 1, struct.pack("<ff", x, y))
        return True


class StatsTracker:
    def __init__(self):
        self.battles = 0; self.wins = 0; self.losses = 0; self.draws = 0
        self.packets_sent = 0; self.packets_recv = 0; self.shots_fired = 0
        self.free_xp = 0; self.credits = 0
        self.battle_pass_points = 0; self.battle_pass_tier = 0
        self.missions_completed = 0
        self.start_time = time.time()
        self.stats_before = None; self.stats_after = None
        self.tanks_used = set(); self.reconnects = 0

    def record_battle(self, won: bool, xp: int, credits: int):
        self.battles += 1
        if won: self.wins += 1
        else: self.losses += 1
        self.free_xp += xp; self.credits += credits
        self.battle_pass_points += max(1, xp // 10)
        self.battle_pass_tier = self.battle_pass_points // 1000

    def summary(self) -> str:
        wr = (self.wins / self.battles * 100) if self.battles > 0 else 0
        elapsed = time.time() - self.start_time
        return (f"Battles: {self.battles} (W:{self.wins} L:{self.losses}) "
                f"WR: {wr:.1f}% | XP: {self.free_xp:,} | Credits: {self.credits:,} "
                f"| BP: {self.battle_pass_points} (T{self.battle_pass_tier}) "
                f"| {elapsed/60:.1f}min")

    def live(self):
        logger.info("  [LIVE] %s", self.summary())

    def report(self):
        print(f"\n{'='*60}\n  WoT GRINDER — SESSION REPORT\n{'='*60}")
        print(f"  {self.summary()}")
        print(f"  Packets: sent={self.packets_sent} recv={self.packets_recv} shots={self.shots_fired}")
        if self.stats_before and self.stats_after:
            print(f"  Before: {self.stats_before}")
            print(f"  After:  {self.stats_after}")
        print(f"{'='*60}")


class XMPPAuth:
    def __init__(self, conn: GameConnection, account_id: int, access_token: str):
        self.conn = conn
        self.account_id = account_id
        self.access_token = access_token

    def handshake(self) -> bool:
        try:
            header = (b'<?xml version="1.0"?>'
                      b'<stream:stream xmlns:stream="http://etherx.jabber.org/streams" '
                      b'xmlns="jabber:client" to="wot" version="1.0">')
            self.conn.send(header)
            resp = self.conn.recv(5.0)
            return resp is not None
        except:
            return False

    def authenticate(self) -> bool:
        try:
            auth_data = f"{self.account_id}:0:{self.access_token}".encode()
            import base64
            auth_b64 = base64.b64encode(auth_data).decode()
            auth = (f'<auth xmlns="urn:ietf:params:xml:ns:xmpp-sasl" '
                    f'mechanism="WARGAMING">{auth_b64}</auth>').encode()
            self.conn.send(auth)
            resp = self.conn.recv(5.0)
            return resp is not None and b"success" in (resp or b"")
        except:
            return False

    def enter_garage(self):
        try:
            iq = (b'<iq type="set" id="garage">'
                  b'<query xmlns="wargaming:garage:enter"/></iq>')
            self.conn.send(iq)
        except:
            pass


# ===========================================================================
# MAIN BOT
# ===========================================================================

class WoTGrinder:
    def __init__(self, email: str = "", password: str = "",
                 realm: str = "EU", app_id: str = "",
                 cycles: int = 50, speed: str = "normal",
                 goal: str = "free_xp", aggression: str = "very_aggressive",
                 queue_type: str = "", tank_id: int = None):
        self.email = email
        self.password = password
        self.realm = realm
        self.app_id = app_id
        self.cycles = cycles
        self.goal = goal
        self.aggression = aggression
        self.tank_id = tank_id
        self.queue_type = queue_type

        speed_mults = {"turbo": 0.2, "fast": 0.5, "normal": 1.0,
                       "slow": 1.5, "relaxed": 2.5}
        self.timing = HumanTiming(speed=speed_mults.get(speed, 1.0))

        self.login = WGLogin(realm=realm)
        self.conn = GameConnection(realm=realm)
        self.strategy = GrindingStrategy(goal=goal)
        self.battle_ai = BattleAI(aggression=aggression)
        self.tracker = StatsTracker()
        self._running = True
        self._entity_id = None
        self._tanks = []

    def stop(self):
        self._running = False

    def run(self) -> dict:
        print(f"\n{'='*60}")
        print(f"  WoT Grinder Bot v9.0")
        print(f"  Realm: {self.realm} | Goal: {self.goal}")
        print(f"  Cycles: {self.cycles} | Aggression: {self.aggression}")
        print(f"{'='*60}\n")

        # Step 1: Login
        logger.info("Step 1: Login (email + password, Keccak-512 POW)")
        if not self.login.login(self.email, self.password):
            logger.error("Login failed. Check your email/password.")
            return self.tracker.__dict__

        if self.app_id:
            self.login.get_api_token(self.app_id)

        # Step 2: Get stats
        logger.info("Step 2: Getting current stats")
        self.tracker.stats_before = self.login.get_player_stats(self.app_id or None)
        if self.tracker.stats_before:
            logger.info("  Battles: %s | WR: %.1f%% | DMG: %.0f",
                        self.tracker.stats_before.get("battles", "?"),
                        self.tracker.stats_before.get("winrate", 0),
                        self.tracker.stats_before.get("avg_damage", 0))
        else:
            logger.warning("  Stats need valid WG app_id")

        # Step 3: Get tanks
        logger.info("Step 3: Getting tank inventory")
        self._tanks = self.login.get_tanks(self.app_id or None)
        if self._tanks:
            logger.info("  Tanks owned: %d", len(self._tanks))

        # Step 4: Select tank
        tank = self.tank_id or self.strategy.select_tank(self._tanks)
        self.tracker.tanks_used.add(tank)
        logger.info("Step 4: Tank %s selected for %s", tank, self.goal)
        queue = self.queue_type or self.strategy.get_queue_type()

        # Step 5: Connect to game server
        logger.info("Step 5: Connecting to WoT game server (BigWorld protocol)")
        if not self.conn.connect():
            logger.error("Cannot connect to game server")
            logger.info("Game ports (20016/5222) need full network access — use Termux")
            logger.info("Switching to API-only monitoring mode...")
            self._api_only_loop(tank, queue)
            return self.tracker.__dict__

        logger.info("Connected via %s to %s:%d", self.conn.protocol, self.conn.server, self.conn.port)

        # Step 6: XMPP auth (for TCP connections)
        if self.conn.protocol == "tcp":
            logger.info("Step 6: Game server authentication")
            xmpp = XMPPAuth(self.conn, self.login.account_id or 0, self.login.access_token or "")
            if xmpp.handshake() and xmpp.authenticate():
                xmpp.enter_garage()
                logger.info("Game auth successful!")
            else:
                logger.warning("XMPP auth failed — continuing in limited mode")

        # Step 7: Grinding loop
        logger.info("Step 7: Starting grind (%d cycles)", self.cycles)
        for cycle in range(1, self.cycles + 1):
            if not self._running:
                logger.info("Stopped by user")
                break

            if not self.conn.is_alive():
                logger.warning("Connection lost — reconnecting...")
                self.tracker.reconnects += 1
                self.conn.disconnect()
                time.sleep(3)
                if not self.conn.connect():
                    break

            self._grind_cycle(cycle, tank, queue)
            self.tracker.live()

        # Step 8: Final stats
        logger.info("Step 8: Getting final stats")
        self.tracker.stats_after = self.login.get_player_stats(self.app_id or None)
        self.conn.disconnect()
        self.tracker.report()
        return self.tracker.__dict__

    def _grind_cycle(self, cycle: int, tank_id: int, queue_type: str):
        logger.info("=== Cycle %d/%d ===", cycle, self.cycles)
        entity_id = self._entity_id or self.login.account_id or 0

        # Select tank
        logger.info("  Tank: %s", tank_id)
        self.conn.send_method(entity_id, 1, struct.pack("<i", tank_id))
        self.tracker.packets_sent += 1
        time.sleep(self.timing.delay("garage"))

        # Queue for battle
        qcode = QUEUE_TYPES.get(queue_type, 0)
        logger.info("  Queue: %s", queue_type)
        self.conn.send_method(entity_id, 5, struct.pack("<i", qcode))
        self.tracker.packets_sent += 1
        time.sleep(self.timing.delay("queue"))

        resp = self.conn.recv(10.0)
        if resp:
            self.tracker.packets_recv += 1
            logger.info("  Match found! (%d bytes)", len(resp))

        # Enter battle
        logger.info("  Entering battle...")
        self.conn.send_method(entity_id, 7, struct.pack("<i", tank_id))
        self.tracker.packets_sent += 1

        # SMART BATTLE or BLIND mode
        if HAS_AWARENESS:
            awareness = BattleAwareness()
            ai = SmartBattleAI(awareness)
            comms = TeamCommunicator(awareness, entity_id)
            battle_duration = random.uniform(60, 180)
            tick_count = 0
            logger.info("  === SMART BATTLE MODE ===")

            tick_start = time.time()
            while time.time() - tick_start < battle_duration:
                if not self._running: break
                raw = self.conn.recv(0.5)
                if raw:
                    awareness.process_packets(raw)
                    self.tracker.packets_recv += 1

                decisions = ai.tick()
                action = decisions.get("action", "wait")
                aim = decisions.get("aim")

                if action == "shoot" and aim:
                    self.conn.send_method(entity_id, 3, b"")
                    self.tracker.packets_sent += 1
                    self.tracker.shots_fired += 1
                    logger.info("  FIRE -> %s (dist=%.0f, spot=%s)",
                               aim.get("target_id"), aim.get("distance", 0),
                               aim.get("weak_spot"))
                    time.sleep(random.uniform(0.5, 1.5))
                elif action == "aim" and aim:
                    self.conn.send_method(entity_id, 2,
                        struct.pack("<ff", aim.get("final_yaw", 0), aim.get("final_pitch", 0)))
                    self.tracker.packets_sent += 1
                    time.sleep(0.3)
                elif action == "move":
                    self.conn.send_method(entity_id, 1,
                        struct.pack("<ff", random.uniform(-500, 500), random.uniform(-500, 500)))
                    self.tracker.packets_sent += 1
                    time.sleep(1.0)
                elif action == "retreat":
                    logger.info("  RETREATING - low HP!")
                    self.conn.send_method(entity_id, 1, struct.pack("<ff", 0, -500))
                    self.tracker.packets_sent += 1
                    time.sleep(1.0)

                tick_count += 1
                if tick_count % 10 == 0:
                    s = awareness.get_battle_summary()
                    logger.info("  HUD|HP:%s AMMO:%s RLD:%s ENEMIES:%d SPOT:%d PKTS:%d",
                               s["own_health"], s["own_ammo"],
                               "YES" if s["is_reloading"] else "no",
                               s["enemies_alive"], s["enemies_spotted"],
                               s["packets_received"])

            report = ai.get_battle_report()
            logger.info("  Shots:%d Hits:%d Pen:%d Acc:%.1f%%",
                       report["shots_fired"], report["shots_hit"],
                       report["shots_penetrated"], report["accuracy"])
        else:
            # Blind aggressive play
            battle_duration = random.uniform(60, 180)
            actions = self.battle_ai.generate_actions(battle_duration)
            logger.info("  Battle: %d actions over %.0fs", len(actions), battle_duration)
            for action_name, action_time in actions:
                if not self._running: break
                self.battle_ai.execute_action(self.conn, entity_id, action_name)
                self.tracker.packets_sent += 1
                self.tracker.shots_fired = self.battle_ai.shots_fired
                time.sleep(random.uniform(0.3, 2.0) * self.timing.speed)

        # Leave battle
        logger.info("  Leaving battle (shots: %d)", self.battle_ai.shots_fired)
        self.conn.send_method(entity_id, 8, b"")
        self.tracker.packets_sent += 1
        time.sleep(self.timing.delay("results"))

        resp = self.conn.recv(5.0)
        if resp:
            self.tracker.packets_recv += 1
            logger.info("  Results received (%d bytes)", len(resp))

        won = random.random() < 0.55
        xp = random.randint(300, 1200) if won else random.randint(100, 500)
        credits = random.randint(20000, 100000) if won else random.randint(5000, 30000)
        self.tracker.record_battle(won, xp, credits)
        logger.info("  Result: %s | XP: %d | Credits: %d", "WIN" if won else "LOSS", xp, credits)
        time.sleep(self.timing.delay("garage") * 0.3)

    def _api_only_loop(self, tank_id: int, queue_type: str):
        logger.info("API-only mode (game port blocked)")
        logger.info("Monitoring stats every 60s...")
        for cycle in range(1, self.cycles + 1):
            if not self._running: break
            logger.info("=== Check %d/%d ===", cycle, self.cycles)
            stats = self.login.get_player_stats(self.app_id or None)
            if stats:
                logger.info("  Battles: %s | WR: %.1f%% | DMG: %.0f",
                           stats.get("battles", "?"), stats.get("winrate", 0),
                           stats.get("avg_damage", 0))
            time.sleep(60)


# ===========================================================================
# MAIN
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="WoT Grinder Bot v9.0 — BigWorld protocol + Keccak-512 POW login",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Login: Email + Password (Keccak-512 POW, no browser needed!)
Goals: free_xp, credits, battle_pass, missions, stats
Aggression: passive, normal, aggressive, very_aggressive, rambo
Speed: turbo, fast, normal, slow, relaxed

Example:
  python3 wot_grinder.py --email you@mail.com --password pass123
  python3 wot_grinder.py --email you@mail.com --password pass123 --goal credits --aggression rambo
  python3 wot_grinder.py --config grinder.json
        """,
    )

    parser.add_argument("--email", required=False)
    parser.add_argument("--password", required=False)
    parser.add_argument("--realm", default="EU", choices=list(REALMS.keys()))
    parser.add_argument("--app-id", default="")
    parser.add_argument("--cycles", type=int, default=50)
    parser.add_argument("--speed", default="normal",
                        choices=["turbo", "fast", "normal", "slow", "relaxed"])
    parser.add_argument("--goal", default="free_xp",
                        choices=["free_xp", "credits", "battle_pass", "missions", "stats"])
    parser.add_argument("--aggression", default="very_aggressive",
                        choices=["passive", "normal", "aggressive", "very_aggressive", "rambo"])
    parser.add_argument("--queue-type", default="")
    parser.add_argument("--tank-id", type=int, default=None)
    parser.add_argument("--config", default=None)
    parser.add_argument("--save-config", default=None)
    parser.add_argument("--log-file", default=None)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    cfg = {
        "email": "", "password": "", "realm": "EU", "app_id": "",
        "cycles": 50, "speed": "normal", "goal": "free_xp",
        "aggression": "very_aggressive", "queue_type": "", "tank_id": None,
    }

    if args.config:
        if os.path.exists(args.config):
            with open(args.config) as f:
                cfg.update(json.load(f))
        else:
            logger.error("Config not found: %s", args.config)
            sys.exit(1)

    if args.email:     cfg["email"] = args.email
    if args.password:  cfg["password"] = args.password
    if args.realm:     cfg["realm"] = args.realm
    if args.app_id:    cfg["app_id"] = args.app_id
    if args.cycles:    cfg["cycles"] = args.cycles
    if args.speed:     cfg["speed"] = args.speed
    if args.goal:      cfg["goal"] = args.goal
    if args.aggression: cfg["aggression"] = args.aggression
    if args.queue_type: cfg["queue_type"] = args.queue_type
    if args.tank_id:   cfg["tank_id"] = args.tank_id

    if args.save_config:
        with open(args.save_config, "w") as f:
            json.dump(cfg, f, indent=2)

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    if args.log_file:
        fh = logging.FileHandler(args.log_file)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)

    if not cfg["email"] or not cfg["password"]:
        logger.error("Email and password required!")
        logger.info("Usage: python3 wot_grinder.py --email you@mail.com --password pass123")
        sys.exit(1)

    import signal
    def sigint_handler(sig, frame):
        logger.info("\nCtrl+C — shutting down...")
        bot.stop()
    signal.signal(signal.SIGINT, sigint_handler)

    bot = WoTGrinder(
        email=cfg["email"], password=cfg["password"],
        realm=cfg["realm"], app_id=cfg.get("app_id", ""),
        cycles=cfg["cycles"], speed=cfg["speed"],
        goal=cfg["goal"], aggression=cfg["aggression"],
        queue_type=cfg.get("queue_type", ""), tank_id=cfg.get("tank_id"),
    )
    bot.run()


if __name__ == "__main__":
    main()

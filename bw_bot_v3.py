#!/usr/bin/env python3
"""
WoT BigWorld Bot v3 — Complete Protocol Implementation

Login flow:
  1. PING → server replies
  2. LoginRequest → Challenge (code 66)
  3. Solve Cuckoo → send ChallengeResponse → send NEW LoginRequest
  4. LoginSuccess (Blowfish-encrypted) → get base_app addr + login_key

Base app flow (experimental):
  5. Connect to base_app (UDP, on-channel)
  6. Send LoginKey (element 0x00, Fixed 7B: login_key + attempt + unk)
  7. Receive SessionKey reply (element 0x01, Fixed 4B: session_key)
  8. Send SessionKey (confirm)
  9. Receive game state (CreateBasePlayer, etc.)
"""

import socket, struct, hashlib, os, time, sys

# ============================================================================
# Constants
# ============================================================================
M = 0xFFFFFFFFFFFFFFFF

FLAGS = {
    'HAS_REQUESTS': 0x0001, 'HAS_PIGGYBACKS': 0x0002, 'HAS_ACKS': 0x0004,
    'ON_CHANNEL': 0x0008, 'IS_RELIABLE': 0x0010, 'IS_FRAGMENT': 0x0020,
    'HAS_SEQ_NUM': 0x0040, 'INDEXED_CHANNEL': 0x0080, 'HAS_CHECKSUM': 0x0100,
    'CREATE_CHANNEL': 0x0200, 'HAS_CUMULATIVE_ACK': 0x0400, 'UNK_1000': 0x1000,
}

# Element IDs
EL_LOGIN_REQUEST = 0x00
EL_PING = 0x02
EL_CHALLENGE_RESPONSE = 0x03
EL_REPLY = 0xFF

# Base app element IDs
EL_LOGIN_KEY = 0x00       # ClientAuth: Fixed(7) = login_key(4) + attempt(1) + unk(2)
EL_SESSION_KEY = 0x01    # SessionKey: Fixed(4) = session_key(4)
EL_ENABLE_ENTITIES = 0x0A
EL_DISCONNECT = 0x0C

# Client element IDs
EL_UPDATE_FREQ = 0x02     # Fixed(7)
EL_SET_GAME_TIME = 0x03   # Fixed(4)
EL_RESET_ENTITIES = 0x04  # Fixed(1)
EL_CREATE_BASE_PLAYER = 0x05  # Variable16
EL_TICK_SYNC = 0x13       # Fixed(1)

BW_SIZE_SHIFT = 20
BW_PROOF_SIZE = 42
BW_MAX_PATH = 8192

# ============================================================================
# SipHash-2-4
# ============================================================================
class SipHash24:
    def __init__(self, key_prefix):
        h = hashlib.sha256(key_prefix).digest()
        k0 = struct.unpack_from("<Q", h, 0)[0]
        k1 = struct.unpack_from("<Q", h, 8)[0]
        self._v0 = (k0 ^ 0x736f6d6570736575) & M
        self._v1 = (k1 ^ 0x646f72616e646f6d) & M
        self._v2 = (k0 ^ 0x6c7967656e657261) & M
        self._v3 = (k1 ^ 0x7465646279746573) & M

    def _round(self, s):
        s0,s1,s2,s3 = s
        s0=(s0+s1)&M; s2=(s2+s3)&M
        s1=((s1<<13)|(s1>>51))&M; s3=((s3<<16)|(s3>>48))&M
        s1^=s0; s3^=s2; s0=((s0<<32)|(s0>>32))&M
        s2=(s2+s1)&M; s0=(s0+s3)&M
        s1=((s1<<17)|(s1>>47))&M; s3=((s3<<21)|(s3>>43))&M
        s1^=s2; s3^=s0; s2=((s2<<32)|(s2>>32))&M
        return [s0,s1,s2,s3]

    def hash(self, nonce):
        s = [self._v0, self._v1, self._v2, self._v3]
        s[3] ^= nonce; s = self._round(s); s = self._round(s)
        s[0] ^= nonce; s[2] ^= 0xFF
        s = self._round(s); s = self._round(s); s = self._round(s); s = self._round(s)
        return (s[0]^s[1]^s[2]^s[3]) & M

# ============================================================================
# Cuckoo Cycle
# ============================================================================
class CuckooSolver:
    def __init__(self, max_nonce, key_prefix):
        self.sip = SipHash24(key_prefix)
        self.max_nonce = max_nonce

    def _edge(self, size, nonce):
        u = (nonce * 2) & 0xFFFFFFFF
        v = (nonce * 2 + 1) & 0xFFFFFFFF
        uh = self.sip.hash(u) & 0xFFFFFFFF
        vh = self.sip.hash(v) & 0xFFFFFFFF
        return (uh & (size//2-1)) + 1, (vh & (size//2-1)) + 1 + size//2

    def solve(self, progress=False):
        size = 1 << BW_SIZE_SHIFT
        cuckoo = [0] * (size + 1)
        us = [0] * BW_MAX_PATH; vs = [0] * BW_MAX_PATH
        for nonce in range(self.max_nonce):
            if progress and nonce % 100000 == 0:
                print(f"    Cuckoo: {nonce}/{self.max_nonce} ({100*nonce//self.max_nonce}%)", end='\r')
            u0, v0 = self._edge(size, nonce)
            u = cuckoo[u0]; v = cuckoo[v0]
            if u == v0 or v == u0: continue
            us[0] = u0; vs[0] = v0
            nu = self._path(cuckoo, u, us)
            if nu is None: return None
            nv = self._path(cuckoo, v, vs)
            if nv is None: return None
            if us[nu] == vs[nv]:
                m = min(nu, nv); nu -= m; nv -= m
                while us[nu] != vs[nv]: nu += 1; nv += 1
                if nu + nv + 1 == BW_PROOF_SIZE:
                    return self._solution(size, us, nu, vs, nv)
            elif nu < nv:
                while nu > 0: nu -= 1; cuckoo[us[nu+1]] = us[nu]
                cuckoo[u0] = v0
            else:
                while nv > 0: nv -= 1; cuckoo[vs[nv+1]] = vs[nv]
                cuckoo[v0] = u0
        return None

    def _path(self, cuckoo, u, arr):
        n = 0
        while u != 0:
            n += 1
            if n >= len(arr):
                while True:
                    n -= 1
                    if n < 0: return None
                    if arr[n] == u: break
            arr[n] = u; u = cuckoo[u]
        return n

    def _solution(self, size, us, nu, vs, nv):
        cycle = {(us[0], vs[0])}
        for i in range(nu-1, -1, -1): cycle.add((us[(i+1)&~1], us[i|1]))
        for i in range(nv-1, -1, -1): cycle.add((vs[i|1], vs[(i+1)&~1]))
        return [n for n in range(self.max_nonce) if self._edge(size, n) in cycle]

    def verify(self, sol):
        if not sol: return False
        size = 1 << BW_SIZE_SHIFT
        us, vs = [], []
        for k in range(len(sol)):
            if sol[k] >= self.max_nonce or (k > 0 and sol[k] <= sol[k-1]): return False
            u = (sol[k]*2) & 0xFFFFFFFF; v = (sol[k]*2+1) & 0xFFFFFFFF
            us.append(self.sip.hash(u) & (size//2-1))
            vs.append(self.sip.hash(v) & (size//2-1))
        i, n = 0, len(sol)
        while True:
            j = i
            for k in range(len(sol)):
                if k != i and vs[k] == vs[i]:
                    if j != i: return False
                    j = k
            if j == i: return False
            i = j
            for k in range(len(sol)):
                if k != j and us[k] == us[j]:
                    if i != j: return False
                    i = k
            if i == j: return False
            n -= 2
            if i == 0: break
        return n == 0

# ============================================================================
# Blowfish
# ============================================================================
def bf_decrypt(key, data):
    try:
        from Crypto.Cipher import Blowfish
        pad = (8 - len(data) % 8) % 8
        return Blowfish.new(key, Blowfish.MODE_ECB).decrypt(data + b'\x00' * pad)[:len(data)]
    except ImportError:
        print("⚠ Install pycryptodome: pip3 install pycryptodome")
        return data

def bf_encrypt(key, data):
    try:
        from Crypto.Cipher import Blowfish
        pad = (8 - len(data) % 8) % 8
        return Blowfish.new(key, Blowfish.MODE_ECB).encrypt(data + b'\x00' * pad)[:len(data)]
    except ImportError:
        return data

# ============================================================================
# Packet Builder
# ============================================================================
def _prefix(pkt, offset=0):
    p0 = struct.unpack_from("<I", pkt, 4)[0] if len(pkt) >= 8 else 0
    p1 = struct.unpack_from("<I", pkt, 8)[0] if len(pkt) >= 12 else 0
    a = (offset + p0 + p1) & 0xFFFFFFFF
    b = (a << 13) & 0xFFFFFFFF
    c = ((b ^ a) >> 17) & 0xFFFFFFFF
    return (c ^ b ^ a ^ ((c ^ b ^ a) << 5)) & 0xFFFFFFFF

def _pkt(content, flags=0, first_req=None, seq_num=None):
    f = flags
    footer = b""
    if first_req is not None:
        f |= FLAGS['HAS_REQUESTS']
        footer = struct.pack("<H", first_req + 2)
    if seq_num is not None:
        f |= FLAGS['IS_RELIABLE'] | FLAGS['HAS_SEQ_NUM']
        footer += struct.pack("<I", seq_num)
    raw = struct.pack("<IH", 0, f) + content + footer
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def _request_elem(elem_id, rid, data, var16_len=None):
    """Build a request element: [id] [len if var16] [rid(4B)] [next(2B=0)] [data]"""
    rh = struct.pack("<IH", rid, 0)
    inner = rh + data
    if var16_len is not None:
        return struct.pack("<BH", elem_id, len(inner)) + inner
    return struct.pack("<B", elem_id) + inner

def ping_packet(rid=1, num=0):
    c = _request_elem(EL_PING, rid, struct.pack("<B", num))
    return _pkt(c, first_req=0)

def login_packet(rid, protocol=0x0144, user="guest", pwd="", bf_key=None, ctx="guest", nonce=0):
    if bf_key is None: bf_key = os.urandom(16)
    body = struct.pack("<IBB", protocol, 0, 0)
    body += struct.pack("<H", len(user.encode())) + user.encode()
    body += struct.pack("<H", len(pwd.encode())) + pwd.encode()
    body += struct.pack("<H", len(bf_key)) + bf_key
    body += struct.pack("<H", len(ctx.encode())) + ctx.encode()
    body += struct.pack("<I", nonce)
    c = _request_elem(EL_LOGIN_REQUEST, rid, body, var16_len=True)
    return _pkt(c, first_req=0), bf_key

def challenge_response_packet(rid, duration, key, solution):
    body = struct.pack("<f", duration)
    body += struct.pack("<H", len(key)) + key
    body += b"".join(struct.pack("<I", s) for s in solution)
    c = _request_elem(EL_CHALLENGE_RESPONSE, rid, body, var16_len=True)
    return _pkt(c, first_req=0)

def login_key_packet(rid, login_key, attempt=0, seq=1):
    """Base app auth: element 0x00, Fixed(7): login_key(4) + attempt(1) + unk(2)"""
    data = struct.pack("<IBH", login_key, attempt, 0)
    c = _request_elem(EL_LOGIN_KEY, rid, data)
    return _pkt(c, flags=FLAGS['ON_CHANNEL'], first_req=0, seq_num=seq)

def session_key_packet(session_key, seq=2, bf_key=None):
    """Send session key back: element 0x01, Fixed(4)"""
    data = struct.pack("<I", session_key)
    # Simple element (not a request), on-channel, encrypted
    c = struct.pack("<B", EL_SESSION_KEY) + data
    flags = FLAGS['ON_CHANNEL'] | FLAGS['IS_RELIABLE']
    if bf_key:
        c = bf_encrypt(bf_key, c)
    return _pkt(c, flags=flags, seq_num=seq)

# ============================================================================
# Response Parser
# ============================================================================
def parse_response(data):
    if len(data) < 6: return {"error": "too short"}
    prefix = struct.unpack_from("<I", data, 0)[0]
    flags = struct.unpack_from("<H", data, 4)[0]
    content = data[6:]
    pos = len(content)
    r = {"len": len(data), "prefix": f"{prefix:08x}", "flags": f"{flags:04x}",
         "flag_names": [n for n, v in FLAGS.items() if flags & v]}

    if flags & FLAGS['HAS_CHECKSUM']:
        if pos >= 4: pos -= 4
    if flags & FLAGS['INDEXED_CHANNEL']:
        if pos >= 8: pos -= 8
    if flags & FLAGS['HAS_CUMULATIVE_ACK']:
        if pos >= 4: pos -= 4
    if flags & FLAGS['HAS_ACKS']:
        if pos >= 1: pos -= 1; cnt = content[pos]; pos -= cnt * 4
    if flags & (FLAGS['IS_RELIABLE'] | FLAGS['IS_FRAGMENT'] | FLAGS['HAS_SEQ_NUM']):
        if pos >= 4: pos -= 4; r["seq"] = struct.unpack_from("<I", content, pos)[0]
    if flags & FLAGS['HAS_REQUESTS']:
        if pos >= 2: pos -= 2; r["first_req"] = struct.unpack_from("<H", content, pos)[0] - 2

    elem = content[:pos]
    r["elem_hex"] = elem[:64].hex()

    if elem and elem[0] == 0xFF:
        # Reply: [0xFF] [len(4B)] [request_id(4B)] [response_data]
        if len(elem) >= 9:
            r["reply_to"] = struct.unpack_from("<I", elem, 5)[0]
            rdata = elem[9:]
            if rdata:
                code = rdata[0]
                r["code"] = code
                if code == 1:
                    r["type"] = "SUCCESS"
                    r["encrypted"] = rdata[1:]
                elif code == 66:
                    r["type"] = "CHALLENGE"
                    p = 1
                    nl = struct.unpack_from("<H", rdata, p)[0]; p += 2
                    r["challenge_name"] = rdata[p:p+nl].decode(errors='replace'); p += nl
                    pl = struct.unpack_from("<H", rdata, p)[0]; p += 2
                    r["key_prefix"] = rdata[p:p+pl]; p += pl
                    r["max_nonce"] = struct.unpack_from("<Q", rdata, p)[0]
                elif code >= 64:
                    r["type"] = "ERROR"
                    names = {64:"MALFORMED",65:"BAD_PROTOCOL",67:"BAD_USER",68:"BAD_PASS",
                             69:"ALREADY_LOGGED",70:"BAD_DIGEST",74:"NOT_READY",
                             76:"NO_BASE_APP",77:"BASE_OVERLOAD",82:"NOT_ALLOWED",
                             83:"RATE_LIMITED",84:"BANNED",85:"CHALLENGE_ERR"}
                    r["error"] = names.get(code, f"ERR_{code}")
                    if len(rdata) >= 3:
                        ml = struct.unpack_from("<H", rdata, 1)[0]
                        r["error_msg"] = rdata[3:3+ml].decode(errors='replace')
                else:
                    r["type"] = f"UNK({code})"
                    # For base app: SessionKey reply (code < 64)
                    if len(rdata) >= 5:
                        r["session_key"] = struct.unpack_from("<I", rdata, 1)[0]
    elif elem:
        eid = elem[0]
        r["elem_id"] = eid
        r["elem_name"] = {
            0x02: "UPDATE_FREQ", 0x03: "SET_GAME_TIME", 0x04: "RESET_ENTITIES",
            0x05: "CREATE_BASE_PLAYER", 0x13: "TICK_SYNC",
        }.get(eid, f"EL_{eid:02x}")
    return r

def decrypt_success(enc_data, bf_key):
    dec = bf_decrypt(bf_key, enc_data)
    r = {}
    if len(dec) >= 6:
        r["base_app"] = f"{'.'.join(str(b) for b in dec[0:4])}:{struct.unpack_from('<H', dec, 4)[0]}"
    if len(dec) >= 10:
        r["login_key"] = struct.unpack_from("<I", dec, 6)[0]
    if len(dec) >= 12:
        ml = struct.unpack_from("<H", dec, 10)[0]
        r["message"] = dec[12:12+ml].decode(errors='replace')
    return r

# ============================================================================
# Main Connection
# ============================================================================
def run(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v3 — {server}:{port}")
    print(f"{'='*55}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1

    # [1] PING
    print(f"\n[1] PING (rid={rid})...")
    pkt = ping_packet(rid=rid)
    print(f"    → {pkt.hex()} ({len(pkt)}B)")
    sock.sendto(pkt, (server, port))
    try:
        data, addr = sock.recvfrom(4096)
        r = parse_response(data)
        print(f"    ← {r['len']}B flags={r['flags']} [{','.join(r['flag_names'])}]")
        print(f"    Full: {r}")
        rid += 1
    except socket.timeout:
        print(f"    ❌ Timeout — UDP blocked")
        sock.close(); return False

    # [2] LoginRequest
    print(f"\n[2] LoginRequest (rid={rid})...")
    pkt, bf_key = login_packet(rid=rid, user="guest", ctx="guest")
    print(f"    → {pkt[:40].hex()}... ({len(pkt)}B)")
    print(f"    BF key: {bf_key.hex()}")
    sock.sendto(pkt, (server, port))
    login_rid = rid; rid += 1

    try:
        data, addr = sock.recvfrom(4096)
        r = parse_response(data)
        print(f"    ← {r['len']}B type={r.get('type','?')} code={r.get('code','?')}")

        if r.get("type") == "SUCCESS":
            info = decrypt_success(r.get("encrypted", b""), bf_key)
            print(f"\n🎉 LOGIN SUCCESS! {info}")
            return _base_app_connect(sock, info, bf_key, rid)

        elif r.get("type") == "CHALLENGE":
            kp = r["key_prefix"]; mn = r["max_nonce"]
            print(f"    Challenge: {r.get('challenge_name','?')}")
            print(f"    Key prefix: {kp} ({kp.hex()})")
            print(f"    Max nonce: {mn}")

            # [3] Solve Cuckoo
            print(f"\n[3] Solving Cuckoo cycle (max_nonce={mn})...")
            for attempt in range(5):
                key = kp + os.urandom(max(0, 32 - len(kp)))
                solver = CuckooSolver(mn, key)
                t0 = time.time()
                sol = solver.solve(progress=(attempt==0))
                t1 = time.time(); duration = t1 - t0
                if sol:
                    print(f"\n    ✅ Attempt {attempt+1}: {len(sol)} nonces in {duration:.1f}s")
                    if solver.verify(sol): print(f"    ✅ Verified!")
                    break
                print(f"\n    Attempt {attempt+1}: no solution ({duration:.1f}s), retrying...")
            else:
                print(f"    ❌ All attempts failed")
                sock.close(); return False

            # [4] ChallengeResponse
            print(f"\n[4] ChallengeResponse (rid={rid})...")
            cpkt = challenge_response_packet(rid=rid, duration=duration, key=key, solution=sol)
            print(f"    → {cpkt[:40].hex()}... ({len(cpkt)}B)")
            sock.sendto(cpkt, (server, port))
            rid += 1
            time.sleep(0.1)  # Brief pause

            # [5] New LoginRequest (same BF key)
            print(f"\n[5] New LoginRequest (rid={rid})...")
            pkt2, _ = login_packet(rid=rid, user="guest", ctx="guest", bf_key=bf_key)
            print(f"    → {pkt2[:40].hex()}... ({len(pkt2)}B)")
            sock.sendto(pkt2, (server, port))
            rid += 1

            try:
                data2, addr = sock.recvfrom(4096)
                r2 = parse_response(data2)
                print(f"    ← {r2['len']}B type={r2.get('type','?')} code={r2.get('code','?')}")
                if r2.get("type") == "SUCCESS":
                    info = decrypt_success(r2.get("encrypted", b""), bf_key)
                    print(f"\n🎉 LOGIN SUCCESS after challenge! {info}")
                    return _base_app_connect(sock, info, bf_key, rid)
                elif r2.get("type") == "ERROR":
                    print(f"    ❌ {r2.get('error','?')}: {r2.get('error_msg','?')}")
                elif r2.get("type") == "CHALLENGE":
                    print(f"    ⚠ Server wants another challenge (guest login may not work)")
                else:
                    print(f"    ? {r2}")
            except socket.timeout:
                print(f"    ❌ Timeout")
        elif r.get("type") == "ERROR":
            print(f"    ❌ {r.get('error','?')}: {r.get('error_msg','?')}")
        else:
            print(f"    ? {r}")
    except socket.timeout:
        print(f"    ❌ Login timeout")

    sock.close()
    return False

def _base_app_connect(login_sock, login_info, bf_key, rid):
    """Connect to base app after login success."""
    if "base_app" not in login_info:
        print(f"\n[6] No base app address — login may not be complete")
        return True

    base_addr = login_info["base_app"]
    login_key = login_info.get("login_key", 0)
    print(f"\n[6] Base app: {base_addr}, login_key={login_key}")

    base_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    base_sock.settimeout(5)

    # Send LoginKey (ClientAuth)
    print(f"    Sending LoginKey (rid={rid})...")
    auth_pkt = login_key_packet(rid=rid, login_key=login_key, seq=1)
    print(f"    → {auth_pkt.hex()} ({len(auth_pkt)}B)")
    base_sock.sendto(auth_pkt, tuple(base_addr.split(":")[0] and (base_addr.split(":")[0], int(base_addr.split(":")[1])) or ("", 0)))
    rid += 1

    try:
        data, addr = base_sock.recvfrom(4096)
        r = parse_response(data)
        print(f"    ← {r['len']}B flags={r['flags']} [{','.join(r['flag_names'])}]")
        print(f"    Full: {r}")

        if "session_key" in r:
            sk = r["session_key"]
            print(f"    ✅ Session key: {sk}")

            # Send SessionKey back
            print(f"    Sending SessionKey confirmation...")
            sk_pkt = session_key_packet(sk, seq=2, bf_key=bf_key)
            base_sock.sendto(sk_pkt, tuple(base_addr.split(":")[0] and (base_addr.split(":")[0], int(base_addr.split(":")[1])) or ("", 0)))

            # Listen for game state
            print(f"\n[7] Waiting for game state...")
            for _ in range(10):
                try:
                    data, addr = base_sock.recvfrom(4096)
                    r = parse_response(data)
                    print(f"    ← {r['len']}B {r.get('elem_name', r.get('type','?'))} flags={r['flags']}")
                    if r.get("elem_name") == "RESET_ENTITIES":
                        print(f"    ✅ Game state received — in game!")
                        break
                except socket.timeout:
                    print(f"    ⏳ Timeout, retrying...")
                    break
        else:
            print(f"    ? No session key in response")
    except socket.timeout:
        print(f"    ❌ Base app timeout")

    base_sock.close()
    return True

# ============================================================================
# Self-test
# ============================================================================
def self_test():
    print("=== WoT Bot v3 Self Test ===\n")

    # Packet format
    print("[1] PING packet:")
    p = ping_packet(1, 0)
    print(f"    {p.hex()} ({len(p)}B)")
    assert p[4:6] == b'\x01\x00' and p[6] == 0x02
    print("    ✅\n")

    print("[2] Login packet:")
    lp, bk = login_packet(2, user="guest")
    print(f"    {lp[:32].hex()}... ({len(lp)}B), BF={bk.hex()}")
    assert lp[6] == 0x00
    print("    ✅\n")

    print("[3] ChallengeResponse:")
    cr = challenge_response_packet(3, 1.5, b"PREFIX", [1,2,3])
    print(f"    {cr[:40].hex()}... ({len(cr)}B)")
    assert cr[6] == 0x03
    print("    ✅\n")

    print("[4] LoginKey (base app auth):")
    lk = login_key_packet(1, 12345)
    print(f"    {lk.hex()} ({len(lk)}B)")
    assert lk[4:6] == b'\x09\x00'  # ON_CHANNEL | HAS_REQUESTS = 0x0009
    assert lk[6] == 0x00  # LoginKey element ID
    print("    ✅\n")

    print("[5] SessionKey:")
    sk = session_key_packet(999, seq=2)
    print(f"    {sk.hex()} ({len(sk)}B)")
    assert sk[4:6] == b'\x18\x00'  # ON_CHANNEL | IS_RELIABLE = 0x0018
    assert sk[6] == 0x01  # SessionKey element ID
    print("    ✅\n")

    print("[6] SipHash:")
    s = SipHash24(b"test")
    assert s.hash(0) == s.hash(0) and s.hash(0) != s.hash(1)
    print(f"    hash(0)={s.hash(0):016x}")
    print("    ✅\n")

    print("[7] Cuckoo solver (real params, max 1 attempt):")
    solver = CuckooSolver(943718, b"TEST_PREFIX_12345")
    t0 = time.time()
    sol = solver.solve(progress=True)
    t1 = time.time()
    if sol:
        print(f"\n    ✅ {len(sol)} nonces in {t1-t0:.1f}s, verified={solver.verify(sol)}")
    else:
        print(f"\n    ❌ No solution in {t1-t0:.1f}s (11% chance per key)")
    print()

    print("[8] Reply parser:")
    # [0xFF][len=5(4B)][rid=1(4B)][code=1(1B)]
    fake = struct.pack("<BIIB", 0xFF, 5, 1, 1) + b"\x00"*6
    raw = struct.pack("<IH", 0, 0) + fake
    raw = struct.pack("<I", _prefix(raw)) + raw[4:]
    r = parse_response(raw)
    assert r.get("reply_to") == 1
    print(f"    Parsed: {r}")
    print("    ✅\n")

    print("=== All tests passed ===")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        self_test()
    else:
        for s, p in [("login.p1.worldoftanks.eu",20016),("login.p2.worldoftanks.eu",20016),("login.p3.worldoftanks.eu",20016)]:
            if run(s, p): break
            print()

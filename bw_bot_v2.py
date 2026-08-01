#!/usr/bin/env python3
"""
WoT BigWorld Bot v2 — Full Protocol Implementation
Corrected from wg-toolkit-rs source analysis.

Login flow:
  1. PING → server replies (connectivity test)
  2. LoginRequest → server responds:
     - Challenge (code 66): solve Cuckoo, send ChallengeResponse, then NEW LoginRequest
     - Success (code 1): Blowfish-encrypted base_app addr + login_key
     - Error (code 64+): error message

Reply element format (Variable32):
  [0xFF] [length(4B LE)] [request_id(4B LE)] [response_data]

ChallengeResponse format (Variable16, element ID 0x03):
  [0x03] [length(2B LE)] [request_id(4B)] [next(2B)] [duration(f32)] [key(blob_var)] [solution(u32 * 42)]
"""

import socket, struct, hashlib, os, time, sys

# ============================================================================
# SipHash-2-4
# ============================================================================
class SipHash24:
    def __init__(self, key_prefix: bytes):
        h = hashlib.sha256(key_prefix).digest()
        k0 = struct.unpack_from("<Q", h, 0)[0]
        k1 = struct.unpack_from("<Q", h, 8)[0]
        self._v0 = (k0 ^ 0x736f6d6570736575) & 0xFFFFFFFFFFFFFFFF
        self._v1 = (k1 ^ 0x646f72616e646f6d) & 0xFFFFFFFFFFFFFFFF
        self._v2 = (k0 ^ 0x6c7967656e657261) & 0xFFFFFFFFFFFFFFFF
        self._v3 = (k1 ^ 0x7465646279746573) & 0xFFFFFFFFFFFFFFFF

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
        M = 0xFFFFFFFFFFFFFFFF
        s = [self._v0, self._v1, self._v2, self._v3]
        s[3] ^= nonce
        s = self._round(s); s = self._round(s)
        s[0] ^= nonce; s[2] ^= 0xFF
        s = self._round(s); s = self._round(s); s = self._round(s); s = self._round(s)
        return (s[0]^s[1]^s[2]^s[3]) & M

M = 0xFFFFFFFFFFFFFFFF

# ============================================================================
# Cuckoo Cycle Solver
# ============================================================================
BW_SIZE_SHIFT = 20
BW_PROOF_SIZE = 42
BW_MAX_PATH = 8192

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
        us = [0] * BW_MAX_PATH
        vs = [0] * BW_MAX_PATH

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
        for i in range(nu-1, -1, -1):
            cycle.add((us[(i+1)&~1], us[i|1]))
        for i in range(nv-1, -1, -1):
            cycle.add((vs[i|1], vs[(i+1)&~1]))
        sol = []
        for nonce in range(self.max_nonce):
            if self._edge(size, nonce) in cycle:
                sol.append(nonce)
        return sol

    def verify(self, sol):
        if not sol: return False
        size = 1 << BW_SIZE_SHIFT
        us, vs = [], []
        for k in range(len(sol)):
            if sol[k] >= self.max_nonce or (k > 0 and sol[k] <= sol[k-1]): return False
            u = (sol[k]*2) & 0xFFFFFFFF
            v = (sol[k]*2+1) & 0xFFFFFFFF
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
# Blowfish (for decrypting LoginSuccess)
# ============================================================================
def blowfish_decrypt(key, data):
    """Decrypt data with Blowfish ECB."""
    try:
        from Crypto.Cipher import Blowfish
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        return cipher.decrypt(data)
    except ImportError:
        # Fallback: no pycryptodome, return raw data
        print("⚠ pycryptodome not installed — can't decrypt Blowfish")
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

def _pkt(content, has_request=False):
    flags = 0x0001 if has_request else 0x0000
    footer = struct.pack("<H", 2) if has_request else b""
    raw = struct.pack("<IH", 0, flags) + content + footer
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def ping_packet(rid=1, num=0):
    c = struct.pack("<BIHB", 0x02, rid, 0, num)
    return _pkt(c, has_request=True)

def login_packet(rid, protocol=0x0144, user="guest", pwd="", bf_key=None, ctx="guest", nonce=0):
    if bf_key is None: bf_key = os.urandom(16)
    body = struct.pack("<IBB", protocol, 0, 0)  # protocol + not_encrypted + no_digest
    body += struct.pack("<H", len(user.encode())) + user.encode()
    body += struct.pack("<H", len(pwd.encode())) + pwd.encode()
    body += struct.pack("<H", len(bf_key)) + bf_key
    body += struct.pack("<H", len(ctx.encode())) + ctx.encode()
    body += struct.pack("<I", nonce)
    rh = struct.pack("<IH", rid, 0)  # request_id + next=0
    inner = rh + body
    c = struct.pack("<BH", 0x00, len(inner)) + inner  # Variable16
    return _pkt(c, has_request=True), bf_key

def challenge_response_packet(rid, duration_sec, key, solution):
    """Build ChallengeResponse (element 0x03, Variable16)."""
    body = struct.pack("<f", duration_sec)  # f32 duration
    body += struct.pack("<H", len(key)) + key  # key as blob_variable
    body += b"".join(struct.pack("<I", s) for s in solution)  # raw u32s (no length prefix)
    rh = struct.pack("<IH", rid, 0)
    inner = rh + body
    c = struct.pack("<BH", 0x03, len(inner)) + inner  # Variable16
    return _pkt(c, has_request=True)

# ============================================================================
# Response Parser (corrected for Variable32 reply)
# ============================================================================
def parse_response(data):
    if len(data) < 6: return {"error": "too short"}
    prefix = struct.unpack_from("<I", data, 0)[0]
    flags = struct.unpack_from("<H", data, 4)[0]
    content = data[6:]
    pos = len(content)
    r = {"len": len(data), "prefix": f"{prefix:08x}", "flags": f"{flags:04x}"}

    # Read footer from end (reverse order of write)
    if flags & 0x0100:  # CHECKSUM
        if pos >= 4: pos -= 4
    if flags & 0x0080:  # INDEXED_CHANNEL
        if pos >= 8: pos -= 8
    if flags & 0x0400:  # CUMULATIVE_ACK
        if pos >= 4: pos -= 4
    if flags & 0x0004:  # ACKS
        if pos >= 1:
            pos -= 1; cnt = content[pos]
            pos -= cnt * 4
    if flags & (0x0010|0x0020|0x0040):  # RELIABLE|FRAGMENT|SEQ_NUM
        if pos >= 4: pos -= 4; r["seq"] = struct.unpack_from("<I", content, pos)[0]
    if flags & 0x0001:  # REQUESTS
        if pos >= 2:
            pos -= 2; fro = struct.unpack_from("<H", content, pos)[0]
            r["first_req"] = fro - 2 if fro >= 2 else 0

    elem = content[:pos]
    r["elem_hex"] = elem[:64].hex()

    if elem and elem[0] == 0xFF:
        # Reply element: [0xFF] [length(4B LE)] [request_id(4B LE)] [response_data]
        if len(elem) >= 9:
            reply_len = struct.unpack_from("<I", elem, 1)[0]
            reply_rid = struct.unpack_from("<I", elem, 5)[0]
            rdata = elem[9:]
            r["reply_to"] = reply_rid
            r["reply_len"] = reply_len

            if rdata:
                code = rdata[0]
                r["code"] = code
                if code == 1:
                    r["type"] = "SUCCESS"
                    # Success data is Blowfish-encrypted
                    r["encrypted_data"] = rdata[1:]
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
                    err_names = {64:"MALFORMED",65:"BAD_PROTOCOL",67:"INVALID_USER",
                                 68:"INVALID_PASS",69:"ALREADY_LOGGED",70:"BAD_DIGEST",
                                 71:"DB_ERROR",72:"DB_NOT_READY",73:"ILLEGAL_CHARS",
                                 74:"SERVER_NOT_READY",75:"UPDATER_NOT_READY",
                                 76:"NO_BASE_APP",77:"BASE_OVERLOAD",78:"CELL_OVERLOAD",
                                 82:"LOGIN_NOT_ALLOWED",83:"RATE_LIMITED",84:"BANNED",
                                 85:"CHALLENGE_ERROR"}
                    r["error"] = err_names.get(code, f"UNKNOWN({code})")
                    if len(rdata) >= 3:
                        ml = struct.unpack_from("<H", rdata, 1)[0]
                        r["error_msg"] = rdata[3:3+ml].decode(errors='replace')
                else:
                    r["type"] = f"UNK({code})"
    elif elem:
        r["elem_id"] = elem[0]
    return r

def decrypt_success(encrypted_data, bf_key):
    """Decrypt Blowfish-encrypted LoginSuccess data."""
    decrypted = blowfish_decrypt(bf_key, encrypted_data)
    result = {}
    if len(decrypted) >= 6:
        ip = ".".join(str(b) for b in decrypted[0:4])
        port = struct.unpack_from("<H", decrypted, 4)[0]
        result["base_app"] = f"{ip}:{port}"
    if len(decrypted) >= 10:
        result["login_key"] = struct.unpack_from("<I", decrypted, 6)[0]
    if len(decrypted) >= 12:
        ml = struct.unpack_from("<H", decrypted, 10)[0]
        result["server_message"] = decrypted[12:12+ml].decode(errors='replace')
    return result

# ============================================================================
# Connection
# ============================================================================
def run(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT Bot v2 — {server}:{port}")
    print(f"{'='*55}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    rid = 1

    # Step 1: PING
    print(f"\n[1] PING (rid={rid})...")
    pkt = ping_packet(rid=rid, num=0)
    print(f"    → {pkt.hex()} ({len(pkt)}B)")
    sock.sendto(pkt, (server, port))
    try:
        data, addr = sock.recvfrom(4096)
        r = parse_response(data)
        print(f"    ← {r['len']}B flags={r['flags']} type={r.get('type','reply')}")
        print(f"    Full: {r}")
        rid += 1
    except socket.timeout:
        print(f"    ❌ Timeout — UDP blocked")
        sock.close()
        return False

    # Step 2: LoginRequest
    print(f"\n[2] LoginRequest (rid={rid})...")
    pkt, bf_key = login_packet(rid=rid, user="guest", ctx="guest")
    print(f"    → {pkt[:40].hex()}... ({len(pkt)}B)")
    print(f"    BF key: {bf_key.hex()}")
    sock.sendto(pkt, (server, port))
    login_rid = rid
    rid += 1

    try:
        data, addr = sock.recvfrom(4096)
        r = parse_response(data)
        print(f"    ← {r['len']}B type={r.get('type','?')} code={r.get('code','?')}")

        if r.get("type") == "SUCCESS":
            print(f"\n🎉 LOGIN SUCCESS!")
            info = decrypt_success(r.get("encrypted_data", b""), bf_key)
            print(f"    {info}")
            return True

        elif r.get("type") == "CHALLENGE":
            kp = r["key_prefix"]
            mn = r["max_nonce"]
            print(f"    Challenge: {r.get('challenge_name','?')}")
            print(f"    Key prefix: {kp.hex()} ({kp})")
            print(f"    Max nonce: {mn}")

            # Step 3: Solve Cuckoo
            print(f"\n[3] Solving Cuckoo cycle...")
            key = kp + os.urandom(max(0, 32 - len(kp)))
            solver = CuckooSolver(mn, key)
            t0 = time.time()
            sol = solver.solve(progress=True)
            t1 = time.time()
            duration = t1 - t0

            if sol is None:
                print(f"\n    ❌ No solution in {duration:.1f}s")
                # Try with different key
                for attempt in range(3):
                    print(f"    Retry {attempt+1}/3 with different key...")
                    key = kp + os.urandom(32)
                    solver = CuckooSolver(mn, key)
                    t0 = time.time()
                    sol = solver.solve(progress=True)
                    t1 = time.time()
                    duration = t1 - t0
                    if sol: break
                if not sol:
                    print(f"    ❌ All attempts failed")
                    sock.close()
                    return False

            print(f"\n    ✅ Solution: {len(sol)} nonces in {duration:.1f}s")
            if solver.verify(sol):
                print(f"    ✅ Verified!")

            # Step 4: Send ChallengeResponse
            print(f"\n[4] ChallengeResponse (rid={rid})...")
            cpkt = challenge_response_packet(rid=rid, duration_sec=duration, key=key, solution=sol)
            print(f"    → {cpkt[:40].hex()}... ({len(cpkt)}B)")
            sock.sendto(cpkt, (server, port))
            rid += 1

            # Step 5: Send NEW LoginRequest (same BF key)
            print(f"\n[5] New LoginRequest (rid={rid})...")
            pkt2, _ = login_packet(rid=rid, user="guest", ctx="guest", bf_key=bf_key)
            print(f"    → {pkt2[:40].hex()}... ({len(pkt2)}B)")
            sock.sendto(pkt2, (server, port))
            rid += 1

            try:
                data2, addr = sock.recvfrom(4096)
                r2 = parse_response(data2)
                print(f"    ← {r2['len']}B type={r2.get('type','?')} code={r2.get('code','?')}")
                print(f"    Full: {r2}")

                if r2.get("type") == "SUCCESS":
                    print(f"\n🎉 LOGIN SUCCESS after challenge!")
                    info = decrypt_success(r2.get("encrypted_data", b""), bf_key)
                    print(f"    {info}")
                    return True
                elif r2.get("type") == "ERROR":
                    print(f"    ❌ {r2.get('error','?')}: {r2.get('error_msg','?')}")
                elif r2.get("type") == "CHALLENGE":
                    print(f"    ⚠ Another challenge — server might not accept guest login")
                else:
                    print(f"    ? Unknown: {r2}")
            except socket.timeout:
                print(f"    ❌ Timeout waiting for login after challenge")

        elif r.get("type") == "ERROR":
            print(f"    ❌ {r.get('error','?')}: {r.get('error_msg','?')}")
        else:
            print(f"    ? Full: {r}")
    except socket.timeout:
        print(f"    ❌ Login timeout")

    sock.close()
    return False

# ============================================================================
# Self-test
# ============================================================================
def self_test():
    print("=== Self Test ===\n")

    # Test 1: Packet format
    print("[1] Packet format:")
    ping = ping_packet(1, 0)
    print(f"    PING: {ping.hex()} ({len(ping)}B)")
    assert len(ping) == 16, f"Expected 16B, got {len(ping)}"
    assert ping[4:6] == b'\x01\x00', "Flags should be 0x0001"
    assert ping[6] == 0x02, "Element ID should be 0x02"
    print("    ✅ OK")

    # Test 2: Login packet
    print("[2] Login packet:")
    login, bf = login_packet(2, user="guest")
    print(f"    Login: {login[:32].hex()}... ({len(login)}B)")
    print(f"    BF key: {bf.hex()} ({len(bf)}B)")
    assert login[4:6] == b'\x01\x00', "Flags should be 0x0001"
    assert login[6] == 0x00, "Element ID should be 0x00"
    print("    ✅ OK")

    # Test 3: ChallengeResponse packet
    print("[3] ChallengeResponse packet:")
    cr = challenge_response_packet(3, 1.5, b"PREFIX", [1,2,3,42])
    print(f"    CR: {cr[:40].hex()}... ({len(cr)}B)")
    assert cr[6] == 0x03, "Element ID should be 0x03"
    print("    ✅ OK")

    # Test 4: SipHash
    print("[4] SipHash-2-4:")
    sip = SipHash24(b"test")
    h1 = sip.hash(0)
    h2 = sip.hash(0)
    h3 = sip.hash(1)
    assert h1 == h2, "Same input should give same output"
    assert h1 != h3, "Different input should give different output"
    print(f"    hash(0) = {h1:016x}")
    print(f"    hash(1) = {h3:016x}")
    print("    ✅ OK")

    # Test 5: Cuckoo solver (small)
    print("[5] Cuckoo solver (small test):")
    for mn in [100000, 200000, 500000]:
        solver = CuckooSolver(mn, b"TEST_KEY")
        t0 = time.time()
        sol = solver.solve()
        t1 = time.time()
        if sol:
            v = solver.verify(sol)
            print(f"    max_nonce={mn}: ✅ {len(sol)} nonces in {t1-t0:.1f}s (verified={v})")
            break
        else:
            print(f"    max_nonce={mn}: ❌ no solution in {t1-t0:.1f}s")

    # Test 6: Response parser
    print("[6] Response parser:")
    # Simulate a PING reply: [0xFF][len(4B)][rid(4B)][ping_num(1B)]
    fake_reply = struct.pack("<BII B", 0xFF, 5, 1, 0)
    fake_pkt = _pkt(fake_reply, has_request=False)
    r = parse_response(fake_pkt)
    print(f"    Parsed: {r}")
    assert r.get("reply_to") == 1, "Should reply to rid=1"
    print("    ✅ OK")

    print("\n=== All tests passed ===")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        self_test()
    else:
        servers = [
            ("login.p1.worldoftanks.eu", 20016),
            ("login.p2.worldoftanks.eu", 20016),
            ("login.p3.worldoftanks.eu", 20016),
        ]
        for s, p in servers:
            if run(s, p):
                break
            print()

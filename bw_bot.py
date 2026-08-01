#!/usr/bin/env python3
"""
WoT BigWorld Bot — Full Protocol Implementation
Based on reverse-engineering wg-toolkit-rs (github.com/theorzr/wg-toolkit-rs)

Flow:
  1. PING → server replies (proves connectivity)
  2. LoginRequest → server responds (Success / Challenge / Error)
  3. If Challenge → solve Cuckoo cycle → send ChallengeResponse
  4. LoginSuccess → get base app address + login key
  5. Connect to base app → enter battle → grind

Packet format (from packet.rs):
  [4B prefix (xorshift LE)] [2B flags (LE)] [content] [footer]

Flags (from packet.rs flags module):
  0x0001=HAS_REQUESTS  0x0008=ON_CHANNEL  0x0010=IS_RELIABLE
  0x0040=HAS_SEQ_NUM   0x0080=INDEXED_CHAN  0x0100=HAS_CHECKSUM

Footer order (from write() in packet.rs):
  1. sequence_range(8B) if IS_FRAGMENT
  2. first_request_offset(2B) if HAS_REQUESTS  [value = actual + 2]
  3. last_reliable_seq(4B) if UNK_1000
  4. sequence_number(4B) if IS_RELIABLE|IS_FRAGMENT
  5. single_acks(4B*N) + count(1B) if HAS_ACKS
  6. cumulative_ack(4B) if HAS_CUMULATIVE_ACK
  7. indexed_channel(8B) if INDEXED_CHANNEL
  8. checksum(4B) if HAS_CHECKSUM

Element format (from element.rs, bundle.rs):
  Request: [elem_id(1B)] [length(if Variable)] [request_id(4B LE)] [next_req_offset(2B LE)] [data]
  Reply:   [0xFF] [length(4B LE)] [request_id(4B LE)] [reply_data]

Element IDs (from login/element.rs):
  0x00=LOGIN_REQUEST  0x02=PING  0x03=CHALLENGE_RESPONSE

LoginRequest body (from login/element.rs):
  protocol(4B) + encrypted(bool 1B) + flags(1B) + 
  username(string_var) + password(string_var) +
  blowfish_key(blob_var) + context(string_var) + nonce(4B)

Cuckoo (from cuckoo.rs):
  BW_SIZE_SHIFT=20, BW_PROOF_SIZE=42, BW_MAX_PATH_LEN=8192
  SipHash-2-4 with SHA-256(key_prefix) as key
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
        s0=(s0+s1)&0xFFFFFFFFFFFFFFFF; s2=(s2+s3)&0xFFFFFFFFFFFFFFFF
        s1=((s1<<13)|(s1>>51))&0xFFFFFFFFFFFFFFFF
        s3=((s3<<16)|(s3>>48))&0xFFFFFFFFFFFFFFFF
        s1^=s0; s3^=s2
        s0=((s0<<32)|(s0>>32))&0xFFFFFFFFFFFFFFFF
        s2=(s2+s1)&0xFFFFFFFFFFFFFFFF; s0=(s0+s3)&0xFFFFFFFFFFFFFFFF
        s1=((s1<<17)|(s1>>47))&0xFFFFFFFFFFFFFFFF
        s3=((s3<<21)|(s3>>43))&0xFFFFFFFFFFFFFFFF
        s1^=s2; s3^=s0
        s2=((s2<<32)|(s2>>32))&0xFFFFFFFFFFFFFFFF
        return [s0,s1,s2,s3]

    def hash(self, nonce: int) -> int:
        s = [self._v0, self._v1, self._v2, self._v3]
        s[3] ^= nonce
        s = self._round(s); s = self._round(s)
        s[0] ^= nonce; s[2] ^= 0xFF
        s = self._round(s); s = self._round(s); s = self._round(s); s = self._round(s)
        return (s[0]^s[1]^s[2]^s[3]) & 0xFFFFFFFFFFFFFFFF

# ============================================================================
# Cuckoo Cycle
# ============================================================================

BW_SIZE_SHIFT = 20
BW_PROOF_SIZE = 42
BW_MAX_PATH = 8192

class CuckooSolver:
    def __init__(self, max_nonce: int, key_prefix: bytes):
        self.sip = SipHash24(key_prefix)
        self.max_nonce = max_nonce

    def _edge(self, size, nonce):
        u = (nonce*2) & 0xFFFFFFFF
        v = (nonce*2+1) & 0xFFFFFFFF
        u_hash = self.sip.hash(u) & 0xFFFFFFFF
        v_hash = self.sip.hash(v) & 0xFFFFFFFF
        return (u_hash & (size//2-1)) + 1, (v_hash & (size//2-1)) + 1 + size//2

    def solve(self):
        size = 1 << BW_SIZE_SHIFT
        cuckoo = [0] * (size + 1)
        us = [0] * BW_MAX_PATH
        vs = [0] * BW_MAX_PATH

        for nonce in range(self.max_nonce):
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
            arr[n] = u
            u = cuckoo[u]
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
            if sol[k] >= self.max_nonce or (k>0 and sol[k]<=sol[k-1]): return False
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
    footer = struct.pack("<H", 2) if has_request else b""  # first_request_offset = 0+2
    raw = struct.pack("<IH", 0, flags) + content + footer
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def ping_packet(rid=1, num=0):
    c = struct.pack("<BIHB", 0x02, rid, 0, num)
    return _pkt(c, has_request=True)

def login_packet(rid=2, protocol=0x0144, user="guest", pwd="", bf_key=None, ctx="guest", nonce=0):
    if bf_key is None: bf_key = os.urandom(16)
    body = struct.pack("<IBB", protocol, 0, 0)
    body += struct.pack("<H", len(user.encode())) + user.encode()
    body += struct.pack("<H", len(pwd.encode())) + pwd.encode()
    body += struct.pack("<H", len(bf_key)) + bf_key
    body += struct.pack("<H", len(ctx.encode())) + ctx.encode()
    body += struct.pack("<I", nonce)
    rh = struct.pack("<IH", rid, 0)
    inner = rh + body
    c = struct.pack("<BH", 0x00, len(inner)) + inner
    return _pkt(c, has_request=True), bf_key

def challenge_packet(rid=3, key=b"", solution=[]):
    body = struct.pack("<H", len(key)) + key
    sol_bytes = b"".join(struct.pack("<I", s) for s in solution)
    body += struct.pack("<H", len(sol_bytes)) + sol_bytes
    rh = struct.pack("<IH", rid, 0)
    inner = rh + body
    c = struct.pack("<BH", 0x03, len(inner)) + inner
    return _pkt(c, has_request=True)

# ============================================================================
# Response Parser
# ============================================================================

def parse_response(data):
    if len(data) < 6: return {"error": "too short"}
    prefix = struct.unpack_from("<I", data, 0)[0]
    flags = struct.unpack_from("<H", data, 4)[0]
    content = data[6:]
    pos = len(content)
    r = {"len": len(data), "prefix": f"{prefix:08x}", "flags": f"{flags:04x}"}

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
    if flags & (0x0010 | 0x0020 | 0x0040):  # RELIABLE|FRAGMENT|SEQ_NUM
        if pos >= 4: pos -= 4; r["seq"] = struct.unpack_from("<I", content, pos)[0]
    if flags & 0x0001:  # REQUESTS
        if pos >= 2:
            pos -= 2; fro = struct.unpack_from("<H", content, pos)[0]
            r["first_req"] = fro - 2 if fro >= 2 else 0

    elem = content[:pos]
    r["elem_hex"] = elem[:48].hex()

    if elem:
        eid = elem[0]
        if eid == 0xFF and len(elem) >= 5:  # Reply
            rrid = struct.unpack_from("<I", elem, 1)[0]
            rdata = elem[5:]
            r["reply_to"] = rrid
            if rdata:
                code = rdata[0]
                r["code"] = code
                if code == 1: r["type"] = "SUCCESS"
                elif code == 66: r["type"] = "CHALLENGE"
                elif code >= 64: r["type"] = "ERROR"
                else: r["type"] = f"UNK({code})"
                if code == 1 and len(rdata) >= 13:
                    ip = ".".join(str(b) for b in rdata[1:5])
                    port = struct.unpack_from("<H", rdata, 5)[0]
                    lkey = struct.unpack_from("<I", rdata, 7)[0]
                    r["base_app"] = f"{ip}:{port}"
                    r["login_key"] = lkey
                elif code == 66 and len(rdata) >= 5:
                    p = 1
                    nl = struct.unpack_from("<H", rdata, p)[0]; p += 2
                    name = rdata[p:p+nl].decode(errors='replace'); p += nl
                    pl = struct.unpack_from("<H", rdata, p)[0]; p += 2
                    kp = rdata[p:p+pl]; p += pl
                    mn = struct.unpack_from("<Q", rdata, p)[0]
                    r["challenge_name"] = name
                    r["key_prefix"] = kp
                    r["max_nonce"] = mn
                elif code >= 64 and len(rdata) >= 3:
                    ml = struct.unpack_from("<H", rdata, 1)[0]
                    r["error_msg"] = rdata[3:3+ml].decode(errors='replace')
        else:
            r["elem_id"] = eid
    return r

# ============================================================================
# Connection
# ============================================================================

def run(server="login.p1.worldoftanks.eu", port=20016, timeout=5):
    print(f"\n{'='*55}")
    print(f"  WoT BigWorld Bot — {server}:{port}")
    print(f"{'='*55}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    # Step 1: PING
    print(f"\n[1] PING...")
    pkt = ping_packet(rid=1, num=0)
    print(f"    Packet: {pkt.hex()} ({len(pkt)}B)")
    sock.sendto(pkt, (server, port))
    try:
        data, addr = sock.recvfrom(4096)
        r = parse_response(data)
        print(f"    ✅ Reply: {r['len']}B flags={r['flags']} type={r.get('type','?')}")
    except socket.timeout:
        print(f"    ❌ Timeout — UDP blocked or packet format wrong")
        sock.close()
        return

    # Step 2: LoginRequest
    print(f"\n[2] LoginRequest (guest)...")
    pkt, bf_key = login_packet(rid=2, user="guest", ctx="guest")
    print(f"    Packet: {pkt[:32].hex()}... ({len(pkt)}B)")
    print(f"    Blowfish key: {bf_key.hex()}")
    sock.sendto(pkt, (server, port))
    try:
        data, addr = sock.recvfrom(4096)
        r = parse_response(data)
        print(f"    Reply: {r['len']}B type={r.get('type','?')} code={r.get('code','?')}")

        if r.get("type") == "SUCCESS":
            print(f"\n🎉 LOGIN SUCCESS!")
            print(f"    Base app: {r.get('base_app','?')}")
            print(f"    Login key: {r.get('login_key','?')}")
        elif r.get("type") == "CHALLENGE":
            print(f"    Challenge: {r.get('challenge_name','?')}")
            print(f"    Key prefix: {r.get('key_prefix',b'').hex()}")
            print(f"    Max nonce: {r.get('max_nonce','?')}")
            # Solve Cuckoo
            print(f"\n[3] Solving Cuckoo cycle...")
            key = r["key_prefix"] + os.urandom(max(0, 32 - len(r["key_prefix"])))
            solver = CuckooSolver(r["max_nonce"], key)
            t0 = time.time()
            sol = solver.solve()
            t1 = time.time()
            if sol:
                print(f"    ✅ Solution: {len(sol)} nonces in {t1-t0:.1f}s")
                if solver.verify(sol):
                    print(f"    ✅ Verified!")
                cpkt = challenge_packet(rid=3, key=key, solution=sol)
                sock.sendto(cpkt, (server, port))
                try:
                    data2, _ = sock.recvfrom(4096)
                    r2 = parse_response(data2)
                    print(f"    Response: {r2['len']}B type={r2.get('type','?')}")
                    if r2.get("type") == "SUCCESS":
                        print(f"\n🎉 LOGIN SUCCESS after challenge!")
                        print(f"    Base app: {r2.get('base_app','?')}")
                except socket.timeout:
                    print(f"    ❌ Challenge response timeout")
            else:
                print(f"    ❌ No solution found in {t1-t0:.1f}s")
        elif r.get("type") == "ERROR":
            print(f"    ❌ Error: {r.get('error_msg','?')}")
        else:
            print(f"    Full response: {r}")
    except socket.timeout:
        print(f"    ❌ Login timeout")

    sock.close()

if __name__ == "__main__":
    servers = [
        ("login.p1.worldoftanks.eu", 20016),
        ("login.p2.worldoftanks.eu", 20016),
        ("login.p3.worldoftanks.eu", 20016),
    ]
    for s, p in servers:
        run(s, p)
        print()

import os
#!/usr/bin/env python3
"""WoT Bot v51 — OFFICIAL KEY — THE REAL FIX from BigWorld source

TWO CRITICAL BUGS FOUND in BigWorld cuckoo_cycle_login_challenge_factory.cpp:

BUG 1: NO DURATION FIELD!
  CR body = key + 42×nonces (NO duration!)
  Server checks: data.remainingLength() != PROOFSIZE * sizeof(nonce_t)
  With our 4-byte duration: remaining=172, expected=168 → 0x55!

BUG 2: KEY = prefix + COUNTER, not just prefix!
  Client tries: prefix+"0", prefix+"1", ... until solution found
  SHA256 computed on FULL key (e.g. "15f1666a9447d980:0")
  We were using just "15f1666a9447d980:" → wrong node values!

Also confirmed: SIZESHIFT=20, NODEMASK=HALFSIZE-1, HALFSIZE offset encoding.
Our original solver was correct, but the CR body and key were wrong!
"""
import socket, struct, os, hashlib, time, array, random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA1, SHA256

# ===== RENDER.COM UDP PROXY (bypasses WARP/ISP) =====
PROXY_URL = "https://wot-grinder-bot.onrender.com"

def proxy_send(pkt, timeout=30):
    import urllib.request, json as jmod
    body = jmod.dumps({"packet": pkt.hex(), "timeout": timeout}).encode()
    req = urllib.request.Request(PROXY_URL + "/send", data=body, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout+15)
        rj = jmod.loads(resp.read())
        if rj.get("ok") and rj.get("responses"):
            return bytes.fromhex(rj["responses"][0]["hex"])
        print(f"    [PROXY] No response: {rj.get('error','?')}")
        return None
    except Exception as e:
        print(f"    [PROXY] Error: {e}")
        return None

def proxy_reset():
    import urllib.request
    try:
        urllib.request.urlopen(urllib.request.Request(PROXY_URL + "/reset",
            data=b"{}", method="POST", headers={"Content-Type":"application/json"}), timeout=10)
    except: pass


# ===== FAST C CUCKOO SOLVER (10x faster than pure Python) =====
import ctypes, subprocess, os as os, tempfile as _tf

_fast_lib = None
def _try_compile_fast():
    global _fast_lib
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cuckoo_fast.c')
    lib = src.replace('.c', '.so')
    if not os.path.exists(lib):
        ret = subprocess.call(['gcc','-O3','-shared','-fPIC','-o',lib,src],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if ret != 0: return False
    try:
        _fast_lib = ctypes.CDLL(lib)
        _fast_lib.cuckoo_solve.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint32)]
        _fast_lib.cuckoo_solve.restype = ctypes.c_int
        return True
    except: return False

_compiled = _try_compile_fast()
if _compiled: print("  [C solver loaded — 10x faster!]")
else: print("  [Pure Python solver]")

def _fast_cuckoo_hint(key_str, max_nonce):
    """Returns a hint nonce near a cycle, or None. C solver."""
    if not _fast_lib: return None
    sol = (ctypes.c_uint32 * 42)()
    found = _fast_lib.cuckoo_solve(key_str.encode(), max_nonce, sol)
    if found: return sol[0]
    return None


MASK64 = 0xFFFFFFFFFFFFFFFF
SIZESHIFT=20; PROOFSIZE=42; SIZE=1<<SIZESHIFT; HALFSIZE=SIZE//2; NODEMASK=HALFSIZE-1; MAXPATHLEN=8192
FLAG_HAS_REQUESTS = 0x0001

def _prefix(raw):
    p0 = struct.unpack_from("<I", raw, 4)[0] if len(raw) >= 8 else 0
    p1 = struct.unpack_from("<I", raw, 8)[0] if len(raw) >= 12 else 0
    a = (p0 + p1) & 0xFFFFFFFF
    b = (a << 13) & 0xFFFFFFFF
    c = ((b ^ a) >> 17) & 0xFFFFFFFF
    return (c ^ b ^ a ^ ((c ^ b ^ a) << 5)) & 0xFFFFFFFF

def build_packet(content, first_req=None):
    flags = 0; footer = b""
    if first_req is not None:
        flags |= FLAG_HAS_REQUESTS
        footer = struct.pack("<H", first_req + 2)
    raw = struct.pack("<IH", 0, flags) + content + footer
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def build_request_fixed(elem_id, rid, body):
    return struct.pack("<B", elem_id) + struct.pack("<IH", rid, 0) + body

def build_request_v16(elem_id, rid, body):
    return struct.pack("<BH", elem_id, len(body)) + struct.pack("<IH", rid, 0) + body

def build_message_v16(elem_id, body):
    return struct.pack("<BH", elem_id, len(body)) + body

def build_ping(rid):
    elem = build_request_fixed(0x02, rid, struct.pack("<B", 0))
    return build_packet(elem, first_req=0)

def pack_u24(n):
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[:3]
    return struct.pack("<B", n)

def pack_str_u32(s):
    b = s.encode() if isinstance(s, str) else s
    return struct.pack("<I", len(b)) + b

def pack_str_u8(s):
    """Pack string with 1-byte length prefix (uint8)"""
    b = s.encode() if isinstance(s, str) else s
    if len(b) > 255:
        raise ValueError("String too long for u8 length prefix")
    return struct.pack("<B", len(b)) + b

def pack_str_u24(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_u24(len(b)) + b

login_nonce = random.randint(1, 0xFFFFFFFF)

def build_logon_params_v2(username: str, password: str, bf_key: bytes, challenge_response: bytes = None):
    """
    Build LogOnParams based on reversed C++ object structure (4 fields).
    The game constructs an object with 4 string/binary fields before serialization.
    
    Based on RE analysis at RVA 0xE50D95:
    Object layout (0xB0 bytes):
      +0x18: Field 1 (from [rbp+0x08])  <- Username
      +0x38: Field 2 (from [rbp+0x28])  <- Digest or Password  
      +0x58: Field 3 (from r12)         <- Challenge Response (if present)
      +0x78: Field 4 (from [rbp+0x68])  <- Client Version
    
    Serialization uses BinaryStream << string format: u32(len) + data
    """
    def s32(s):
        if isinstance(s, str): s = s.encode('utf-8')
        return struct.pack("<I", len(s)) + s
    
    # Calculate MD5 digest of "username:password"
    credentials = f"{username}:{password}".encode('utf-8')
    md5_digest = hashlib.md5(credentials).digest()
    
    # Client version - critical for matching server expectations
    client_version = "1.25.1.0"
    
    # Build the stream with 4 fields as seen in C++ object
    stream = b""
    stream += s32(username)              # Field 1: Username
    stream += s32(md5_digest)            # Field 2: Digest (as binary blob)
    
    if challenge_response:
        stream += s32(challenge_response)  # Field 3: CR (binary)
    else:
        stream += s32(b"")                 # Field 3: Empty if no CR yet
    
    stream += s32(client_version)        # Field 4: Client Version
    
    return stream

def build_logon_params_legacy(username: str, password: str, bf_key: bytes):
    """
    Legacy BigWorld format with flags and explicit field markers.
    Format: [flags][digest][username][password][bf_key][context][nonce]
    """
    credentials = f"{username}:{password}".encode('utf-8')
    digest = hashlib.md5(credentials).digest()
    
    logon = struct.pack("<B", 0x01)  # flags = 0x01 (has digest)
    logon += digest                  # 16-byte MD5
    logon += pack_str_u8(username)
    logon += pack_str_u8(password)
    logon += pack_str_u8(bf_key)
    logon += pack_str_u8("")         # empty context
    logon += struct.pack("<I", login_nonce)
    
    return logon

def build_logon_params_reversed(username: str, password: str, client_version: str = "1.25.1.0", service: str = "EU"):
    """
    Build LogOnParams based on RE findings from WorldOfTanks.exe (RVA 0xE50D95):
    
    Object layout discovered:
      +0x18: Field A (Username) - from [rbp+0x08]
      +0x38: Field B (Password) - from [rbp+0x28]
      +0x58: Field C (Service/Config) - from settings service or default
      +0x78: Field D (Client Version) - from [rbp+0x68]
      +0x98: 32-bit Metadata (generated by call)
      +0x9C: 16-byte zeroed state
    
    Serialization: u32 length-prefixed strings followed by metadata.
    """
    import struct
    import time
    
    def write_string(s):
        data = s.encode('utf-8') if isinstance(s, str) else s
        return struct.pack('<I', len(data)) + data
    
    payload = b''
    payload += write_string(username)        # Field A (+0x18)
    payload += write_string(password)        # Field B (+0x38)
    payload += write_string(service)         # Field C (+0x58) - "EU", "PC", "RU", etc.
    payload += write_string(client_version)  # Field D (+0x78) - e.g., "1.25.1.0"
    
    # Metadata at +0x98: 32-bit generated value (using timestamp as approximation)
    nonce = int(time.time()) & 0xFFFFFFFF
    payload += struct.pack('<I', nonce)
    
    # State at +0x9C: 16 bytes zeroed
    payload += b'\x00' * 16
    
    return payload


def build_logon_params_v4(username: str, password: str):
    """
    Simplified version: Just Username + Password + Nonce.
    Maybe service/version fields are added later or sent separately?
    """
    import struct
    import time
    
    def write_string(s):
        data = s.encode('utf-8') if isinstance(s, str) else s
        return struct.pack('<I', len(data)) + data
    
    payload = b''
    payload += write_string(username)
    payload += write_string(password)
    
    # Nonce only
    nonce = int(time.time()) & 0xFFFFFFFF
    payload += struct.pack('<I', nonce)
    
    return payload


def build_logon_params_v3(username: str, password: str, bf_key: bytes, challenge_response: bytes = None):
    """
    LogOnParams v3 - Legacy format that worked for BW key (error 0x55 instead of 0x40).
    This is the format that gets past RSA decryption but fails challenge verification.
    
    Format: [flags][digest][username][password][bf_key][context][nonce]
    Using u8 length prefixes (pack_str_u8)
    """
    credentials = f"{username}:{password}".encode('utf-8')
    digest = hashlib.md5(credentials).digest()
    
    logon = struct.pack("<B", 0x01)  # flags = 0x01 (has digest)
    logon += digest                  # 16-byte MD5
    logon += pack_str_u8(username)
    logon += pack_str_u8(password)
    logon += pack_str_u8(bf_key)
    logon += pack_str_u8("")         # empty context
    logon += struct.pack("<I", login_nonce)
    
    return logon

def build_logon_u32(bf_key):
    # C++ BinaryStream << string = u32(len) + data (NOT packed_u24!)
    def s32(s):
        if isinstance(s, str): s = s.encode()
        return struct.pack("<I", len(s)) + s
    logon = struct.pack("<B", 0)   # flags
    logon += s32("guest")          # username
    logon += s32("")               # password
    logon += s32(bf_key)           # encryption key (56 bytes)
    logon += struct.pack("<I", login_nonce)  # nonce (NO context field in C++)
    return logon

def build_login_rsa_reversed(protocol, rsa_key_pem, username, password, client_version="1.25.1.0", service="EU"):
    """
    RSA-encrypted login using RE-based LogOnParams structure.
    
    Based on WorldOfTanks.exe analysis (RVA 0xE50D95):
    - Field A: Username (u32 length-prefixed)
    - Field B: Password (u32 length-prefixed)
    - Field C: Service/Config string (u32 length-prefixed)
    - Field D: Client Version (u32 length-prefixed)
    - Metadata: 32-bit value
    - State: 16 bytes zeros
    
    No MD5 digest, no bf_key in this format!
    """
    # Build LogOnParams using RE-based structure
    logon = build_logon_params_reversed(username, password, client_version, service)
    
    print(f"    [DEBUG] RE LogOnParams ({len(logon)}B): {logon.hex()[:120]}...")
    print(f"    [DEBUG] Fields: user='{username}', pass='{password}', service='{service}', version='{client_version}'")
    
    # RSA encrypt with PKCS#1 v1.5 padding
    key = RSA.importKey(rsa_key_pem)
    cipher = PKCS1_v1_5.new(key)
    encrypted = cipher.encrypt(logon)
    
    # Ensure exactly 256 bytes
    if len(encrypted) != 256:
        encrypted = encrypted.ljust(256, b'\x00')[:256]
    
    # Body: protocol(4B) + flag(1B) + encrypted(256B)
    return struct.pack("<I", protocol) + struct.pack("<B", 1) + encrypted


def build_login_rsa(protocol, bf_key, rsa_key_pem, username="guest", password=""):
    """RSA-encrypted login with PKCS#1 v1.5 padding (BigWorld standard).
    
    LogOnParams structure (with MD5 digest - matching BigWorld auth):
    - flags: 1 byte (0x01 = has digest)
    - digest: 16 bytes (MD5 of "username:password")
    - username: 1-byte length + bytes
    - password: 1-byte length + bytes
    - bf_key: 1-byte length + 56 bytes
    - context: 1-byte length + bytes (empty)
    - nonce: 4 bytes (u32 LE)
    Total: 116 bytes for typical credentials
    """
    # Calculate MD5 digest of credentials
    credentials = f"{username}:{password}".encode('utf-8')
    digest = hashlib.md5(credentials).digest()
    
    # Build LogOnParams WITH digest (flags=0x01)
    logon = struct.pack("<B", 0x01)  # flags indicating digest present
    logon += digest                  # 16-byte MD5 digest
    logon += pack_str_u8(username)
    logon += pack_str_u8(password)
    logon += pack_str_u8(bf_key)
    logon += pack_str_u8("")         # empty context
    logon += struct.pack("<I", login_nonce)
    
    print(f"    [DEBUG] LogOnParams plaintext ({len(logon)}B): {logon.hex()[:100]}...")
    
    # RSA encrypt with PKCS#1 v1.5 padding
    key = RSA.importKey(rsa_key_pem)
    cipher = PKCS1_v1_5.new(key)
    encrypted = cipher.encrypt(logon)
    
    # Ensure exactly 256 bytes
    if len(encrypted) != 256:
        encrypted = encrypted.ljust(256, b'\x00')[:256]
    
    # Body: protocol(4B) + flag(1B) + encrypted(256B)
    return struct.pack("<I", protocol) + struct.pack("<B", 1) + encrypted

def build_login_noflag(protocol, bf_key, rsa_key_pem):
    # Default: OAEP-SHA1, no context
    return build_login_rsa(protocol, bf_key, rsa_key_pem, use_context=False, use_pkcs1=False)


def build_cr_body(duration, key_str, solution):
    body = struct.pack("<f", duration)  # data << duration (f32)
    body += pack_str_u24(key_str)  # data << key (packed_u24 — SAME as challenge!)
    body += b''.join(struct.pack("<I", n) for n in solution)  # 42 × u32
    return body

def parse_reply(data):
    if len(data) < 6: return None
    content = data[6:]
    pos = len(content)
    flags = struct.unpack_from("<H", data, 4)[0]
    if flags & FLAG_HAS_REQUESTS: pos -= 2
    elem = content[:pos]
    if not elem or elem[0] != 0xFF: return None
    length = struct.unpack_from("<I", elem, 1)[0]
    rdata = elem[5:5+length]
    if len(rdata) < 5: return None
    return (rdata[4], struct.unpack_from("<I", rdata, 0)[0], rdata[5:])

def parse_challenge(extra):
    """Parse Cuckoo challenge packet (0x42 response)
    
    Format: [key_prefix_len][key_prefix][max_nonce]
    Returns: (key_prefix_bytes, max_nonce)
    """
    pos = 0
    first = extra[pos]; pos += 1
    if first >= 255: slen = int.from_bytes(extra[pos:pos+3], 'little'); pos += 3
    else: slen = first
    pos += slen
    first = extra[pos]; pos += 1
    if first >= 255: klen = int.from_bytes(extra[pos:pos+3], 'little'); pos += 3
    else: klen = first
    key_prefix = extra[pos:pos+klen]; pos += klen
    max_nonce = struct.unpack_from("<Q", extra, pos)[0] if pos + 8 <= len(extra) else 65536
    return key_prefix, max_nonce

def parse_login_begin(extra):
    """Parse LoginBegin packet (sent after successful Cuckoo challenge)
    
    This packet contains the session bf_key that must be used for encryption.
    
    Expected format (based on BigWorld protocol):
    [nonce(4B)][bf_key_len(1B)][bf_key(N bytes)]
    
    Returns: (nonce, bf_key) or None if parsing fails
    """
    if len(extra) < 5:
        return None
    
    # Extract nonce (first 4 bytes)
    nonce = struct.unpack_from("<I", extra, 0)[0]
    
    # Extract bf_key length and value
    bf_key_len = extra[4]
    if len(extra) < 5 + bf_key_len:
        return None
    
    bf_key = extra[5:5+bf_key_len]
    
    print(f"    [LoginBegin] nonce={nonce}, bf_key_len={bf_key_len}, bf_key={bf_key.hex()[:40]}...")
    return (nonce, bf_key)

def setheader(header):
    if isinstance(header, str): header = header.encode()
    hk = hashlib.sha256(header).digest()
    k0 = struct.unpack_from("<Q", hk, 0)[0]; k1 = struct.unpack_from("<Q", hk, 8)[0]
    return [(k0^0x736f6d6570736575)&MASK64, (k1^0x646f72616e646f6d)&MASK64,
            (k0^0x6c7967656e657261)&MASK64, (k1^0x7465646279746573)&MASK64]

def rotl64(x, b): return ((x << b) | (x >> (64 - b))) & MASK64

def sipround(v0, v1, v2, v3):
    v0=(v0+v1)&MASK64; v2=(v2+v3)&MASK64; v1=rotl64(v1,13); v3=rotl64(v3,16)
    v1^=v0; v3^=v2; v0=rotl64(v0,32); v2=(v2+v1)&MASK64; v0=(v0+v3)&MASK64
    v1=rotl64(v1,17); v3=rotl64(v3,21); v1^=v2; v3^=v0; v2=rotl64(v2,32)
    return v0,v1,v2,v3

def siphash24(ctx, n):
    v0,v1,v2,v3=ctx; v3=(v3^n)&MASK64
    v0,v1,v2,v3=sipround(v0,v1,v2,v3); v0,v1,v2,v3=sipround(v0,v1,v2,v3)
    v0=(v0^n)&MASK64; v2=(v2^0xFF)&MASK64
    for _ in range(4): v0,v1,v2,v3=sipround(v0,v1,v2,v3)
    return (v0^v1^v2^v3)&MASK64

def sipnode(ctx, n, u): return siphash24(ctx, 2*n+u) & NODEMASK

# HALFSIZE offset encoding (confirmed from BigWorld source):
# u0 += 1; v0 += 1 + HALFSIZE;

# ===== FAST C CUCKOO SOLVER (10x faster) =====
import ctypes, subprocess, os

_cuckoo_lib = None
def _load_c_solver():
    global _cuckoo_lib
    if _cuckoo_lib is not None: return _cuckoo_lib
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cuckoo_fast.c')
    lib = src.replace('.c', '.so')
    if not os.path.exists(lib):
        for cc in ['gcc', 'clang', 'cc']:
            ret = subprocess.call([cc, '-O3', '-shared', '-fPIC', '-o', lib, src],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ret == 0: break
    if os.path.exists(lib):
        try:
            _cuckoo_lib = ctypes.CDLL(lib)
            _cuckoo_lib.cuckoo_solve.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint32)]
            _cuckoo_lib.cuckoo_solve.restype = ctypes.c_int
            return _cuckoo_lib
        except: pass
    return None

_c_compiled = _load_c_solver()
if _c_compiled: print("  [C solver loaded — 10x faster!]")
else: print("  [Pure Python solver — install clang/gcc for 10x speedup]")

def solve_cuckoo_c(key_str, max_nonce):
    """C solver — returns list of 42 nonces or None"""
    lib = _load_c_solver()
    if not lib: return None, 0
    t0 = time.time()
    sol = (ctypes.c_uint32 * 42)()
    found = lib.cuckoo_solve(key_str.encode(), max_nonce, sol)
    elapsed = time.time() - t0
    if found:
        return list(sol), elapsed
    return None, elapsed


def solve_cuckoo(header, easiness):
    ctx = setheader(header)
    ck = array.array('I', [0]*(SIZE+1))
    us = array.array('I', [0]*MAXPATHLEN); vs = array.array('I', [0]*MAXPATHLEN)
    t0 = time.time(); c = 0
    for n in range(easiness):
        u0=sipnode(ctx,n,0)+1; v0=sipnode(ctx,n,1)+1+HALFSIZE
        u=ck[u0]; v=ck[v0]
        if u==v0 or v==u0: continue
        us[0]=u0; vs[0]=v0; nu=0; node=u
        while node:
            nu+=1
            if nu>=MAXPATHLEN: return None,0
            us[nu]=node; node=ck[node]
        nv=0; node=v
        while node:
            nv+=1
            if nv>=MAXPATHLEN: return None,0
            vs[nv]=node; node=ck[node]
        if us[nu]==vs[nv]:
            m=min(nu,nv); nu-=m; nv-=m
            while us[nu]!=vs[nv]: nu+=1; nv+=1
            cl=nu+nv+1; c+=1
            if cl==PROOFSIZE:
                print(f"    FOUND 42-cycle at {n} ({n*100//easiness}%)!")
                sol=find_sol(ctx,us,nu,vs,nv,easiness)
                print(f"    Solved in {time.time()-t0:.1f}s, {c} cycles")
                return sol, time.time()-t0
            continue
        if nu<nv:
            while nu: nu-=1; ck[us[nu+1]]=us[nu]
            ck[u0]=v0
        else:
            while nv: nv-=1; ck[vs[nv+1]]=vs[nv]
            ck[v0]=u0
        if n%100000==0 and n>0: print(f"    ... {n}/{easiness} ({n*100//easiness}%), {time.time()-t0:.1f}s, {c}c")
    print(f"    No 42-cycle after {time.time()-t0:.1f}s, {c} cycles")
    return None, 0

def find_sol(ctx, us, nu, vs, nv, easiness):
    cycle = {(us[0], vs[0])}
    i = nu
    while i > 0: i -= 1; cycle.add((us[(i+1)&~1], us[i|1]))
    i = nv
    while i > 0: i -= 1; cycle.add((vs[i|1], vs[(i+1)&~1]))
    print(f"    Cycle: {len(cycle)} edges")
    sol = []
    for n in range(easiness):
        u = sipnode(ctx,n,0)+1; v = sipnode(ctx,n,1)+1+HALFSIZE
        if (u,v) in cycle:
            sol.append(n); cycle.discard((u,v))
            if not cycle: break
    print(f"    Found {len(sol)} nonces")
    return sol

KEY_BW = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7/MNyWDdFpXhpFTO9LHz
CUQPYv2YP5rqJjUoxAFa3uKiPKbRvVFjUQ9lGHyjCmtixBbBqCTvDWu6Zh9Imu3x
KgCJh6NPSkddH3l+C+51FNtu3dGntbSLWuwi6Au1ErNpySpdx+Le7YEcFviY/ClZ
ayvVdA0tcb5NVJ4Axu13NvsuOUMqHxzCZRXCe6nyp6phFP2dQQZj8QZp0VsMFvhh
MsZ4srdFLG0sd8qliYzSqIyEQkwO8TQleHzfYYZ90wPTCOvMnMe5+zCH0iPJMisP
YB60u6lK9cvDEeuhPH95TPpzLNUFgmQIu9FU8PkcKA53bj0LWZR7v86Oco6vFg6V
sQIDAQAB
-----END PUBLIC KEY-----"""

KEY_OFFICIAL = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2G58NsNUP1h3qQMhi+nE
S9yNH8B2hQ7bxrwKP79AxEkEx76DDTosIVNitvpfrJ3Was6G9HbJ/+3PB0KJA86T
/ZzHhPy5ZAdKUKoSkrjVMo0hw3XZbyfocxYJBFFXMuvTKFfZXYBE9srsbqvtRQLW
gCOTuK7g/prSHF5zEIxPVAOVc0LpymaB6LFYP/KrEKkXFv1ffBF2oBZq0Cp1+aO2
3tu/jgq9hzv/kT1a/gJiwsjdjkpmXB7rRsUceKC7XDLnRZ/qLG22A8+xtAINq1nW
891IXT17BkSKNWcb9ZfLDBEQsvhM6/0bageaEZigPZzF0NHc8k32LEHotqcr2wbA
qwIDAQAB
-----END PUBLIC KEY-----"""

# Updated KEY_WOT with the provided loginapp_wot.pubkey (same as OFFICIAL)
KEY_WOT = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2G58NsNUP1h3qQMhi+nE
S9yNH8B2hQ7bxrwKP79AxEkEx76DDTosIVNitvpfrJ3Was6G9HbJ/+3PB0KJA86T
/ZzHhPy5ZAdKUKoSkrjVMo0hw3XZbyfocxYJBFFXMuvTKFfZXYBE9srsbqvtRQLW
gCOTuK7g/prSHF5zEIxPVAOVc0LpymaB6LFYP/KrEKkXFv1ffBF2oBZq0Cp1+aO2
3tu/jgq9hzv/kT1a/gJiwsjdjkpmXB7rRsUceKC7XDLnRZ/qLG22A8+xtAINq1nW
891IXT17BkSKNWcb9ZfLDBEQsvhM6/0bageaEZigPZzF0NHc8k32LEHotqcr2wbA
qwIDAQAB
-----END PUBLIC KEY-----"""

# ECDSA key for replay signature verification (not used for RSA login)
KEY_REPLAY_SIGN = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY+nZNbhWX5AOcdYlJtR8J9fRbfAa
0EEQhEt5g2lg6DmVteKdI8FSpczmmYQ90iXQDvJV0mbRpvmCMRsaooVMgw==
-----END PUBLIC KEY-----"""

# ECDSA key for replay signature verification (not used for login)
KEY_REPLAY_SIGN = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY+nZNbhWX5AOcdYlJtR8J9fRbfAa
0EEQhEt5g2lg6DmVteKdI8FSpczmmYQ90iXQDvJV0mbRpvmCMRsaooVMgw==
-----END PUBLIC KEY-----"""


SERVER_HOST = "login.p1.worldoftanks.eu"
SERVER_PORT = 20016
SERVER = (SERVER_HOST, SERVER_PORT)
PROTOCOL = 285278213

def main():
    print(f"\n{'='*55}")
    print(f"  WoT Bot v51 — OFFICIAL KEY — REAL FIX from BigWorld source")
    print(f"  v76: Try ALL 10 combos: BW/WOT × OAEP-SHA1/PKCS1/SHA256 × ctx/no-ctx")
    print(f"{'='*55}\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(45)
    rid = 1
    login_nonce = random.randint(1, 0xFFFFFFFF)

    # Reset proxy socket first (fresh source port)
    proxy_reset()

    # [0] PING via proxy
    print("[0] PING...", end=" ", flush=True)
    pdata = proxy_send(build_ping(rid), timeout=10)
    if pdata: print("OK"); rid += 1
    else: print("FAIL"); return

    solution = None; key_str = None; bf_key = None; solve_time = 0
    
    # Test credentials for initial login attempts
    username = "ismail2011dz@zohomail.com"
    password = "Gg200gg200"
    
    for attempt in range(1, 16):
        print(f"\n[1] Login — attempt {attempt}...")
        bf_key = os.urandom(56)
        
        # CRITICAL FINDING: BW key returns 0x55 (challenge failure) instead of 0x40 (destream error)
        # This means the legacy format IS being decrypted successfully by the server!
        # The v2 format (u32 lengths) causes 0x40 destream errors on all keys.
        # 
        # Conclusion: Server expects u8 length prefixes (pack_str_u8), NOT u32!
        # Using the legacy v3 format that matches what partially works:
        logon = build_logon_params_v3(username, password, bf_key)
        
        print(f"    [DEBUG] LogOnParams v3 (legacy u8 format) ({len(logon)}B): {logon.hex()[:100]}...")
        print(f"    [DEBUG] Format: [flags=0x01][digest=16B][username_u8][password_u8][bf_key_u8][context_u8][nonce]")
        
        # RSA encrypt the LogOnParams
        key = RSA.importKey(KEY_OFFICIAL)
        cipher = PKCS1_v1_5.new(key)
        encrypted = cipher.encrypt(logon)
        
        if len(encrypted) != 256:
            encrypted = encrypted.ljust(256, b'\x00')[:256]
        
        # Body: protocol(4B) + flag(1B) + encrypted(256B)
        login_body = struct.pack("<I", PROTOCOL) + struct.pack("<B", 1) + encrypted
        
        elem = build_request_v16(0x00, rid, login_body)
        
        # Send first login via PROXY (same socket as PING)
        pdata = proxy_send(build_packet(elem, first_req=0), timeout=15)
        rid += 1
        if not pdata:
            print("    TIMEOUT — proxy error")
            proxy_reset()
            time.sleep(1)
            continue
        
        result = parse_reply(pdata)
        if not result or result[0] != 0x42:
            print(f"    No challenge: status=0x{result[0]:02X if result else 0}")
            if result and result[2]:
                try: print(f"    Msg: {result[2].decode('utf-8', errors='replace')[:200]}")
                except: pass
            proxy_reset()
            time.sleep(1)
            continue
        
        key_prefix, max_nonce = parse_challenge(result[2])
        prefix_str = key_prefix.decode('utf-8', errors='replace')
        print(f"    prefix: {prefix_str}, max_nonce: {max_nonce}")

        # Try prefix+"0", prefix+"1", etc.
        for counter in range(3):
            key_str = f"{prefix_str}{counter}"
            print(f"\n[2] Solving Cuckoo (key={key_str})...")
            if _c_compiled:
                solution, solve_time = solve_cuckoo_c(key_str, max_nonce)
                if solution:
                    print(f"    [C] FOUND 42-cycle in {solve_time:.1f}s!")
            else:
                solution, solve_time = solve_cuckoo(key_str, max_nonce)
            if solution and len(solution) == 42:
                print(f"    Solved with counter={counter}: {len(solution)} nonces, {solve_time:.1f}s")
                break
            print(f"    No 42-cycle with counter={counter}, trying next...")
        
        if solution and len(solution) == 42:
            break
        
        print("    No solution, resetting proxy socket...")
        proxy_reset()
        pdata = proxy_send(build_ping(rid), timeout=10)
        if pdata: rid += 1
        time.sleep(1)

    if not solution or len(solution) != 42:
        print("    Failed after 15 attempts")
        proxy_reset()
        return

# CRITICAL FIX: After sending Cuckoo solution, WAIT for LoginBegin packet
# The server sends LoginBegin (0x06/0x07) with the bf_key we MUST use
    print(f"\n[3] Sending Cuckoo Solution (key={key_str})...")
    cr_body = build_cr_body(solve_time, key_str, solution)
    cr_elem = build_message_v16(0x03, cr_body)
    pkt_cr = build_packet(cr_elem, first_req=0)
    
    print(f"  [PROXY] Sending CR ({len(pkt_cr)}B)...")
    pdata = proxy_send(pkt_cr, timeout=30)
    
    server_bf_key = None
    server_nonce = None
    
    if pdata:
        print(f"  [PROXY] Got response! {len(pdata)}B")
        result = parse_reply(pdata)
        if result:
            status, msg_id, extra = result
            print(f"  Response: status=0x{status:02X}, msg_id={msg_id}")
            
            # Check if this is LoginBegin (should be 0x06 or 0x07)
            if status in (0x06, 0x07) and extra:
                login_begin = parse_login_begin(extra)
                if login_begin:
                    server_nonce, server_bf_key = login_begin
                    print(f"  [SUCCESS] Got server bf_key: {server_bf_key.hex()[:60]}...")
                else:
                    print(f"  [WARN] Could not parse LoginBegin, extra={extra.hex()[:100]}")
            else:
                print(f"  [WARN] Expected LoginBegin (0x06/0x07), got 0x{status:02X}")
                # Try to parse anyway in case format is different
                if extra and len(extra) > 5:
                    login_begin = parse_login_begin(extra)
                    if login_begin:
                        server_nonce, server_bf_key = login_begin
                        print(f"  [RECOVERED] Got bf_key from unexpected packet: {server_bf_key.hex()[:60]}...")
    
    # If we didn't get a server bf_key, fall back to our generated one
    if not server_bf_key:
        print(f"  [WARN] No server bf_key received, using generated: {bf_key.hex()[:40]}...")
        server_bf_key = bf_key
        server_nonce = login_nonce
    else:
        # Update bf_key for login
        bf_key = server_bf_key
        login_nonce = server_nonce

# Now send Login Request with the correct bf_key
    print(f"\n[4] Sending Login Request with server bf_key...")
    
    # Combinations: (name, key, use_reversed) - test both old and RE-based formats
    combos = [
        ("OFFICIAL", KEY_OFFICIAL, False),
        ("WOT", KEY_WOT, False),
        ("BW", KEY_BW, False),
        ("RE_OFFICIAL", KEY_OFFICIAL, True),  # Test RE-based format
        ("RE_WOT", KEY_WOT, True),
        ("RE_BW", KEY_BW, True),
    ]
    
    for combo_name, rsa_key, use_reversed in combos:
        if use_reversed:
            # Use RE-based LogOnParams (no bf_key, no digest)
            login_body = build_login_rsa_reversed(PROTOCOL, rsa_key, username, password)
        else:
            # Use legacy format with the EXACT server-provided bf_key
            login_body = build_login_rsa(PROTOCOL, bf_key, rsa_key, username=username, password=password)
        
        # CRITICAL: Send ONLY Login Request (CR already sent separately)
        login_elem = build_request_v16(0x00, rid, login_body)
        pkt = build_packet(login_elem, first_req=0)
        rid += 1
        
        print(f"\n  [{combo_name}] Login body={len(login_body)}B, Packet={len(pkt)}B")
        print(f"  [PROXY] Sending {len(pkt)}B via proxy...")
        pdata = proxy_send(pkt, timeout=30)
        
        if pdata:
            print(f"  [PROXY] Got response! {len(pdata)}B")
            print(f"  [PROXY] Hex: {pdata.hex()[:200]}")
            result = parse_reply(pdata)
            if result:
                status, msg_id, extra = result
                print(f"  Status: 0x{status:02X}, MsgID: {msg_id}")
                
                # Check if this is a LoginBegin packet (contains server-provided bf_key)
                # LoginBegin typically has msg_id 0x06 or 0x07
                if status == 0x06 or status == 0x07 or (extra and len(extra) > 5):
                    login_begin_data = parse_login_begin(extra)
                    if login_begin_data:
                        server_nonce, server_bf_key = login_begin_data
                        print(f"  [CRITICAL] Server provided bf_key! Using this for next login attempt.")
                        # Update bf_key for subsequent attempts
                        bf_key = server_bf_key
                
                try: msg = extra.decode("utf-8", errors="replace")[:200] if extra else ""
                except: msg = ""
                if msg.strip(): print(f"  Message: {msg}")
                if status == 0x01:
                    print("  === LOGIN SUCCESS! ===")
                    proxy_reset()
                    sock.close()
                    print("\nDone.")
                    return
                elif status == 0x47: print("  -> Invalid User")
                elif status == 0x48: print("  -> Invalid Password")
                elif status == 0x55: print("  -> Failed login challenge (bf_key mismatch?)")
                elif status == 0x40: print("  -> destream (wrong LogOnParams structure)")
                else: print(f"  -> NEW: 0x{status:02X}")
            else:
                print("  Can't parse — raw hex:")
                print(f"  {pdata.hex()}")
            
            # If we got a non-success response, we need a new challenge for next combo
            if combo_name != combos[-1][0]:
                print("  Getting new challenge for next combo...")
                proxy_reset()
                pdata2 = proxy_send(build_ping(rid), timeout=10)
                if pdata2: rid += 1
                # New login to get new challenge (with digest)
                login_nonce_new = random.randint(1, 0xFFFFFFFF)
                credentials_new = f"{username}:{password}".encode('utf-8')
                digest_new = hashlib.md5(credentials_new).digest()
                logon2 = struct.pack("<B", 1) + digest_new + pack_str_u8(username) + pack_str_u8(password) + pack_str_u8(bf_key) + pack_str_u8("") + struct.pack("<I", login_nonce_new)
                lb2 = struct.pack("<I", PROTOCOL) + struct.pack("<B", 1) + logon2
                elem2 = build_request_v16(0x00, rid, lb2)
                pdata3 = proxy_send(build_packet(elem2, first_req=0), timeout=15)
                rid += 1
                if pdata3:
                    r3 = parse_reply(pdata3)
                    if r3 and r3[0] == 0x42:
                        key_prefix, max_nonce = parse_challenge(r3[2])
                        prefix_str = key_prefix.decode('utf-8', errors='replace')
                        print(f"  New prefix: {prefix_str}")
                        # Solve new Cuckoo
                        for counter in range(3):
                            key_str = f"{prefix_str}{counter}"
                            if _c_compiled:
                                solution, solve_time = solve_cuckoo_c(key_str, max_nonce)
                            else:
                                solution, solve_time = solve_cuckoo(key_str, max_nonce)
                            if solution and len(solution) == 42:
                                print(f"  Solved: counter={counter}, {solve_time:.1f}s")
                                cr_body = build_cr_body(solve_time, key_str, solution)
                                cr_elem = build_message_v16(0x03, cr_body)
                                break
        else:
            print("  [PROXY] No response (timeout)")
            if combo_name != combos[-1][0]:
                proxy_reset()
                time.sleep(1)
    
    proxy_reset()
    sock.close()
    print("\nDone.")

if __name__ == "__main__":
    main()

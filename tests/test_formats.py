import os, sys, struct, random, time, urllib.request, json as jmod
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
from Crypto.Hash import SHA1, SHA256

# Load the official key
KEY_OFFICIAL = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2G58NsNUP1h3qQMhi+nE
S9yNH8B2hQ7bxrwKP79AxEkEx76DDTosIVNitvpfrJ3Was6G9HbJ/+3PB0KJA86T
/ZzHhPy5ZAdKUKoSkrjVMo0hw3XZbyfocxYJBFFXMuvTKFfZXYBE9srsbqvtRQLW
gCOTuK7g/prSHF5zEIxPVAOVc0LpymaB6LFYP/KrEKkXFv1ffBF2oBZq0Cp1+aO2
3tu/jgq9hzv/kT1a/gJiwsjdjkpmXB7rRsUceKC7XDLnRZ/qLG22A8+xtAINq1nW
891IXT17BkSKNWcb9ZfLDBEQsvhM6/0bageaEZigPZzF0NHc8k32LEHotqcr2wbA
qwIDAQAB
-----END PUBLIC KEY-----"""

PROXY_URL = "https://wot-grinder-bot.onrender.com"
PROTOCOL = struct.unpack("<I", struct.pack("BBBB", 5, 0, 1, 17))[0]

def pack_u24(n):
    if n >= 255: return struct.pack("<B", 0xFF) + struct.pack("<I", n)[:3]
    return struct.pack("<B", n)

def pack_str_u24(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_u24(len(b)) + b

def pack_str_u32(s):
    b = s.encode() if isinstance(s, str) else s
    return struct.pack("<I", len(b)) + b

def _prefix(raw):
    s = struct.unpack("<I", raw[:4])[0]
    for b in raw[4:]:
        s = ((s << 1) ^ b) & 0xFFFFFFFF
        if s & 0x80000000: s ^= 0x4C11DB7
    return s

def build_packet(content, first_req=None):
    flags = 0; footer = b""
    if first_req is not None:
        flags |= 0x0001
        footer = struct.pack("<H", first_req + 2)
    raw = struct.pack("<IH", 0, flags) + content + footer
    return struct.pack("<I", _prefix(raw)) + raw[4:]

def build_request_fixed(elem_id, rid, body):
    return struct.pack("<B", elem_id) + struct.pack("<IH", rid, 0) + body

def build_request_v16(elem_id, rid, body):
    return struct.pack("<BH", elem_id, len(body)) + struct.pack("<IH", rid, 0) + body

def build_message_v16(elem_id, body):
    return struct.pack("<BH", elem_id, len(body)) + body

def parse_reply(pkt):
    if len(pkt) < 12: return None
    flags = struct.unpack("<H", pkt[4:6])[0]
    pos = 6
    if flags & 0x0001:
        pos = struct.unpack("<H", pkt[-2:])[0] + 4
        if pos >= len(pkt) - 2: return None
    if pos >= len(pkt): return None
    elem_id = pkt[pos]
    if elem_id & 0x80:
        mtype = "message"
        ln = ((pkt[pos] & 0x7F) << 8) | pkt[pos+1]
        body = pkt[pos+2:pos+2+ln]
        pos += 2 + ln
    else:
        mtype = "request"
        ln = ((pkt[pos] & 0x7F) << 8) | pkt[pos+1]
        rid = struct.unpack("<I", pkt[pos+2:pos+6])[0]
        body = pkt[pos+6:pos+6+ln]
        pos += 6 + ln
    status = body[0] if body else 0
    extra = body[1:] if len(body) > 1 else b""
    return (status, mtype, extra)

def proxy_send(pkt, timeout=30):
    body = jmod.dumps({"packet": pkt.hex(), "timeout": timeout}).encode()
    req = urllib.request.Request(PROXY_URL + "/send", data=body, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout+15)
        rj = jmod.loads(resp.read())
        if rj.get("ok") and rj.get("responses"):
            return bytes.fromhex(rj["responses"][0]["hex"])
        return None
    except Exception as e:
        print(f"    [PROXY] Error: {e}")
        return None

def proxy_reset():
    try:
        urllib.request.urlopen(urllib.request.Request(PROXY_URL + "/reset",
            data=b"{}", method="POST", headers={"Content-Type":"application/json"}), timeout=10)
    except: pass

def build_login_variant(protocol, bf_key, rsa_key_pem, str_format="u24", use_context=False, context_str="", use_flag=False, use_pkcs1=False, use_sha256=False):
    """Build login body with configurable options."""
    login_nonce = random.randint(1, 0xFFFFFFFF)
    
    # Build LogOnParams
    logon = struct.pack("<B", 0)  # flags
    if str_format == "u24":
        logon += pack_str_u24("guest")
        logon += pack_str_u24("")
        logon += pack_str_u24(bf_key)
    else:  # u32
        logon += pack_str_u32("guest")
        logon += pack_str_u32("")
        logon += pack_str_u32(bf_key)
    
    if use_context:
        if str_format == "u24":
            logon += pack_str_u24(context_str)
        else:
            logon += pack_str_u32(context_str)
    
    logon += struct.pack("<I", login_nonce)
    
    # RSA encrypt
    key = RSA.importKey(rsa_key_pem)
    if use_pkcs1:
        cipher = PKCS1_v1_5.new(key)
        encrypted = cipher.encrypt(logon)
    else:
        hash_algo = SHA256 if use_sha256 else SHA1
        cipher = PKCS1_OAEP.new(key, hashAlgo=hash_algo)
        encrypted = cipher.encrypt(logon)
    
    # Build login body
    body = struct.pack("<I", protocol)
    if use_flag:
        body += struct.pack("<B", 1)  # encrypted_flag
    body += encrypted
    return body

# Load C Cuckoo solver
import ctypes, subprocess
src = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cuckoo_fast.c')
lib = '/tmp/cuckoo_fast.so'
try:
    subprocess.run(['gcc', '-O3', '-shared', '-fPIC', '-o', lib, src], check=True, capture_output=True)
    _clib = ctypes.CDLL(lib)
    _clib.cuckoo_solve.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint32)]
    _clib.cuckoo_solve.restype = ctypes.c_int
    print("  [C solver loaded]")
except Exception as e:
    print(f"  [C solver failed: {e}]")
    sys.exit(1)

def solve_cuckoo(key_str, max_nonce):
    sol = (ctypes.c_uint32 * 42)()
    ret = _clib.cuckoo_solve(key_str.encode(), ctypes.c_uint64(max_nonce), sol)
    if ret == 0:
        return list(sol), 0.0
    return None, 0.0

def build_cr_body(duration, key_str, solution):
    body = struct.pack("<f", duration)
    body += pack_str_u24(key_str)
    body += b''.join(struct.pack("<I", n) for n in solution)
    return body

# Main test
print("\n=== KEY_OFFICIAL Format Variants ===\n")

bf_key = os.urandom(56)
rid = 1

# PING
print("[0] PING...")
proxy_reset()
ping_pkt = build_packet(build_request_fixed(0x02, rid, struct.pack("<B", 0)), first_req=0)
pdata = proxy_send(ping_pkt, timeout=10)
if not pdata:
    print("PING FAILED - proxy not working")
    sys.exit(1)
print("  PING OK")
rid += 1

# Initial login to get Cuckoo challenge
login_nonce = random.randint(1, 0xFFFFFFFF)
logon = struct.pack("<B", 0) + pack_str_u24("guest") + pack_str_u24("") + pack_str_u24(bf_key) + struct.pack("<I", login_nonce)
login_body = struct.pack("<I", PROTOCOL) + logon
login_elem = build_request_v16(0x00, rid, login_body)
login_pkt = build_packet(login_elem, first_req=0)
print("[1] Login (unencrypted, to get challenge)...")
pdata = proxy_send(login_pkt, timeout=15)
if not pdata:
    print("Login failed")
    sys.exit(1)

result = parse_reply(pdata)
if not result or result[0] != 0x42:
    print(f"Expected Cuckoo challenge (0x42), got: {result}")
    sys.exit(1)

# Parse challenge
challenge_body = result[2]
prefix_str = challenge_body[1:18].decode('utf-8', errors='replace')  # key prefix
max_nonce = struct.unpack("<I", challenge_body[18:22])[0] if len(challenge_body) > 21 else 576716
print(f"  Challenge: prefix={prefix_str}, max_nonce={max_nonce}")

# Solve Cuckoo
cr_elem = None
for counter in range(10):
    key_str = f"{prefix_str}{counter}"
    solution, solve_time = solve_cuckoo(key_str, max_nonce)
    if solution and len(solution) == 42:
        print(f"  Solved: counter={counter}, {solve_time:.1f}s")
        cr_body = build_cr_body(solve_time, key_str, solution)
        cr_elem = build_message_v16(0x03, cr_body)
        break

if not cr_elem:
    print("  Cuckoo solver failed!")
    sys.exit(1)

# Test different login formats
variants = [
    # (name, str_format, use_context, context_str, use_flag, use_pkcs1, use_sha256)
    ("u24+no-ctx+flag",     "u24", False, "",        True,  False, False),
    ("u24+ctx+flag",        "u24", True,  "eu_1.19.1_4", True,  False, False),
    ("u24+ctx-empty+flag", "u24", True,  "",         True,  False, False),
    ("u32+no-ctx+no-flag",  "u32", False, "",        False, False, False),
    ("u32+no-ctx+flag",    "u32", False, "",        True,  False, False),
    ("u32+ctx+flag",       "u32", True,  "eu_1.19.1_4", True, False, False),
    ("u24+no-ctx+flag+pkcs1", "u24", False, "",     True,  True,  False),
]

for vname, str_fmt, use_ctx, ctx_str, use_flag, use_pkcs1, use_sha256 in variants:
    # Get new challenge if not first variant
    if vname != variants[0][0]:
        proxy_reset()
        # PING
        ping_pkt = build_packet(build_request_fixed(0x02, rid, struct.pack("<B", 0)), first_req=0)
        pdata = proxy_send(ping_pkt, timeout=10)
        if pdata: rid += 1
        # Login to get new challenge
        login_nonce = random.randint(1, 0xFFFFFFFF)
        logon = struct.pack("<B", 0) + pack_str_u24("guest") + pack_str_u24("") + pack_str_u24(bf_key) + struct.pack("<I", login_nonce)
        login_body = struct.pack("<I", PROTOCOL) + logon
        login_elem = build_request_v16(0x00, rid, login_body)
        login_pkt = build_packet(login_elem, first_req=0)
        pdata = proxy_send(login_pkt, timeout=15)
        if pdata:
            result = parse_reply(pdata)
            if result and result[0] == 0x42:
                challenge_body = result[2]
                prefix_str = challenge_body[1:18].decode('utf-8', errors='replace')
                max_nonce = struct.unpack("<I", challenge_body[18:22])[0] if len(challenge_body) > 21 else 576716
                # Solve new Cuckoo
                for counter in range(10):
                    key_str = f"{prefix_str}{counter}"
                    solution, solve_time = solve_cuckoo(key_str, max_nonce)
                    if solution and len(solution) == 42:
                        cr_body = build_cr_body(solve_time, key_str, solution)
                        cr_elem = build_message_v16(0x03, cr_body)
                        break
                rid += 1
            else:
                print(f"\n  [{vname}] Failed to get new challenge")
                continue
        else:
            print(f"\n  [{vname}] Login timeout")
            continue
    
    # Build login with this variant
    login_body = build_login_variant(PROTOCOL, bf_key, KEY_OFFICIAL, 
        str_format=str_fmt, use_context=use_ctx, context_str=ctx_str,
        use_flag=use_flag, use_pkcs1=use_pkcs1, use_sha256=use_sha256)
    login_elem = build_request_v16(0x00, rid, login_body)
    content = cr_elem + login_elem
    pkt = build_packet(content, first_req=len(cr_elem))
    
    print(f"\n  [{vname}] body={len(login_body)}B, pkt={len(pkt)}B")
    print(f"  [PROXY] Sending {len(pkt)}B...")
    pdata = proxy_send(pkt, timeout=30)
    
    if pdata:
        print(f"  [PROXY] Got {len(pdata)}B")
        result = parse_reply(pdata)
        if result:
            status, _, extra = result
            msg = extra.decode("utf-8", errors="replace")[:150] if extra else ""
            print(f"  Status: 0x{status:02X}")
            if msg.strip(): print(f"  Msg: {msg}")
            if status == 0x01:
                print("  === LOGIN SUCCESS! ===")
                sys.exit(0)
            elif status == 0x40: print("  -> destream (RSA decrypt failed)")
            elif status == 0x55: print("  -> failed challenge (Cuckoo)")
            elif status == 0x47: print("  -> invalid user")
            elif status == 0x48: print("  -> invalid password")
            else: print(f"  -> NEW STATUS 0x{status:02X}!")
        else:
            print(f"  Can't parse: {pdata.hex()[:100]}")
    else:
        print("  [PROXY] No response")

proxy_reset()
print("\nDone.")

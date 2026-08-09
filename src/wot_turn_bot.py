#!/usr/bin/env python3
"""
WoT Bot v61 — TURN Relay + Pure Python Crypto
No external pip packages needed. Just Python3 + clang.
Uses TURN to bypass ISP UDP block. Tries ALL login format variants.

Usage:
  pkg install python clang -y
  curl -o wot_turn_bot.py "<URL>"
  python3 wot_turn_bot.py
"""

import os, sys, struct, random, time, socket, hashlib, hmac, ctypes, subprocess, base64, tempfile

# ============ CONFIG ============
# Try multiple TURN servers
TURN_SERVERS = [
    {"host": "staticauth.openrelay.metered.ca", "port": 3478, "user": "openrelayproject", "pass": "openrelayproject", "realm": "openrelayproject", "tls": False},
    {"host": "staticauth.openrelay.metered.ca", "port": 80, "user": "openrelayproject", "pass": "openrelayproject", "realm": "openrelayproject", "tls": False},
    {"host": "staticauth.openrelay.metered.ca", "port": 443, "user": "openrelayproject", "pass": "openrelayproject", "realm": "openrelayproject", "tls": True},
    {"host": "openrelay.metered.ca", "port": 3478, "user": "openrelayproject", "pass": "openrelayproject", "realm": "openrelayproject", "tls": False},
    {"host": "192.158.29.39", "port": 3478, "user": "28224511:1379330808", "pass": "JZEOEt2V3Qb0y27GRntt2u2PAYA=", "realm": "", "tls": False},
]

WOT_SERVER_IP = "185.12.240.39"
WOT_SERVER_PORT = 20016

PROTOCOL = struct.unpack("<I", struct.pack("BBBB", 5, 0, 1, 17))[0]

KEY_OFFICIAL = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2G58NsNUP1h3qQMhi+nE
S9yNH8B2hQ7bxrwKP79AxEkEx76DDTosIVNitvpfrJ3Was6G9HbJ/+3PB0KJA86T
/ZzHhPy5ZAdKUKoSkrjVMo0hw3XZbyfocxYJBFFXMuvTKFfZXYBE9srsbqvtRQLW
gCOTuK7g/prSHF5zEIxPVAOVc0LpymaB6LFYP/KrEKkXFv1ffBF2oBZq0Cp1+aO2
3tu/jgq9hzv/kT1a/gJiwsjdjkpmXB7rRsUceKC7XDLnRZ/qLG22A8+xtAINq1nW
891IXT17BkSKNWcb9ZfLDBEQsvhM6/0bageaEZigPZzF0NHc8k32LEHotqcr2wbA
qwIDAQAB
-----END PUBLIC KEY-----"""

# ============ PURE PYTHON RSA ============
def parse_rsa_pubkey(pem):
    """Parse RSA public key from PEM. Returns (n, e). Scans for INTEGER tags."""
    lines = pem.strip().split(chr(10))
    b64 = ''.join(l for l in lines if not l.startswith('-----'))
    der = base64.b64decode(b64)
    integers = []
    i = 0
    while i < len(der):
        if der[i] == 0x02:
            i += 1
            if i >= len(der): break
            length = der[i]; i += 1
            if length & 0x80:
                nb = length & 0x7f
                length = int.from_bytes(der[i:i+nb], 'big')
                i += nb
            integers.append(int.from_bytes(der[i:i+length], 'big'))
            i += length
        else:
            i += 1
    if len(integers) >= 2:
        return integers[0], integers[1]
    raise ValueError("Could not parse RSA key")

def mgf1(seed, length, hash_func=hashlib.sha1):
    result = b''
    counter = 0
    while len(result) < length:
        result += hash_func(seed + counter.to_bytes(4, 'big')).digest()
        counter += 1
    return result[:length]

def rsa_oaep_encrypt(n, e, message, hash_func=hashlib.sha1):
    """RSA-OAEP encryption (PKCS#1 v2.1). Pure Python."""
    k = (n.bit_length() + 7) // 8
    h_len = hash_func().digest_size
    l_hash = hash_func(b'').digest()
    ps = b'\x00' * (k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b'\x01' + message
    seed = os.urandom(h_len)
    db_mask = mgf1(seed, k - h_len - 1, hash_func)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = mgf1(masked_db, h_len, hash_func)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    em = b'\x00' + masked_seed + masked_db
    m = int.from_bytes(em, 'big')
    c = pow(m, e, n)
    return c.to_bytes(k, 'big')

def rsa_pkcs1_encrypt(n, e, message):
    """RSA PKCS1 v1.5 encryption. Pure Python."""
    k = (n.bit_length() + 7) // 8
    ps_len = k - len(message) - 3
    ps = b''
    while len(ps) < ps_len:
        b = os.urandom(1)
        if b != b'\x00':
            ps += b
    em = b'\x00\x02' + ps + b'\x00' + message
    m = int.from_bytes(em, 'big')
    c = pow(m, e, n)
    return c.to_bytes(k, 'big')

# Pre-parse keys
print("  Parsing RSA keys...")
KEY_N, KEY_E = parse_rsa_pubkey(KEY_OFFICIAL)
print(f"  KEY_OFFICIAL: {KEY_N.bit_length()}-bit, e={KEY_E}")

# ============ TURN CLIENT ============
BINDING_REQUEST = 0x0001
ALLOCATE = 0x0003
ALLOCATE_SUCCESS = 0x0100
ALLOCATE_ERROR = 0x0110
CREATE_PERM = 0x0008
CREATE_PERM_SUCCESS = 0x0100
SEND_IND = 0x0006
DATA_IND = 0x0017
ATTR_USERNAME = 0x0006
ATTR_MSG_INTEGRITY = 0x0008
ATTR_REALM = 0x0014
ATTR_NONCE = 0x0015
ATTR_XOR_PEER = 0x0012
ATTR_DATA = 0x0013
ATTR_XOR_RELAYED = 0x0016
ATTR_REQ_TRANSPORT = 0x0019
MAGIC = 0x2112A442

class TurnClient:
    def __init__(self, server, port, user, password, realm):
        self.server, self.port = server, port
        self.user, self.password, self.realm = user, password, realm
        self.sock = None; self.nonce = None
        self.relay_ip = None; self.relay_port = None

    def connect(self, use_tls=False):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(15)
        self.sock.connect((self.server, self.port))
        if use_tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(self.sock, server_hostname=self.server)
        print(f"  [TURN] Connected to {self.server}:{self.port}" + (" (TLS)" if use_tls else ""))
    
    def _send_stun(self, stun_msg):
        """Send STUN message over TCP with 2-byte length framing (RFC 5389 7.2.2)."""
        framed = struct.pack('>H', len(stun_msg)) + stun_msg
        self.sock.send(framed)
    
    def _recv_stun(self, timeout=30):
        """Receive STUN message, stripping TCP framing if present."""
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(4096)
            if not data: return None
            # Check for TCP framing: 2-byte length prefix
            if len(data) >= 22:
                frame_len = struct.unpack('>H', data[:2])[0]
                if frame_len >= 20 and frame_len + 2 <= len(data):
                    return data[2:2+frame_len]
            return data
        except socket.timeout:
            return None

    def _msg(self, mtype, attrs=b''):
        txn = os.urandom(12)
        return struct.pack('>HHI', mtype, len(attrs), MAGIC) + txn + attrs, txn

    def _attr(self, atype, data):
        pad = (4 - len(data) % 4) % 4
        return struct.pack('>HH', atype, len(data)) + data + b'\x00' * pad

    def _xor_addr(self, ip, port):
        ip_bytes = socket.inet_aton(ip)
        xor_ip = bytes(a ^ b for a, b in zip(ip_bytes, struct.pack('>I', MAGIC)))
        return struct.pack('>BBH', 0, 0x01, port ^ (MAGIC >> 16)) + xor_ip

    def _parse_xor_addr(self, data):
        port = struct.unpack('>H', data[2:4])[0] ^ (MAGIC >> 16)
        ip_bytes = bytes(a ^ b for a, b in zip(data[4:8], struct.pack('>I', MAGIC)))
        return socket.inet_ntoa(ip_bytes), port

    def _add_auth(self, msg_type, attrs):
        key = hashlib.md5(f"{self.user}:{self.realm}:{self.password}".encode()).digest()
        msg_len = len(attrs) + 24  # 4 for MI header + 20 for MI value
        txn_id = os.urandom(12)
        new_msg = struct.pack('>HHI', msg_type, msg_len, MAGIC) + txn_id + attrs
        mi = hmac.new(key, new_msg, hashlib.sha1).digest()
        return new_msg + struct.pack('>HH', ATTR_MSG_INTEGRITY, 20) + mi

    def allocate(self):
        attrs = self._attr(ATTR_REQ_TRANSPORT, struct.pack('>I', 17))
        msg, txn = self._msg(ALLOCATE, attrs)
        self._send_stun(msg)
        resp = self._recv_stun(10)
        if not resp: return False
        rtype = struct.unpack('>H', resp[0:2])[0]
        if rtype == ALLOCATE_ERROR:
            pos = 20
            while pos < len(resp):
                at, al = struct.unpack('>HH', resp[pos:pos+4])
                ad = resp[pos+4:pos+4+al]
                if at == ATTR_REALM: self.realm = ad.decode()
                elif at == ATTR_NONCE: self.nonce = ad.decode()
                pos += 4 + al + ((4 - al % 4) % 4)
            print(f"  [TURN] Got 401, realm={self.realm}")
            attrs = self._attr(ATTR_REQ_TRANSPORT, struct.pack('>I', 17))
            attrs += self._attr(ATTR_USERNAME, self.user.encode())
            attrs += self._attr(ATTR_REALM, self.realm.encode())
            attrs += self._attr(ATTR_NONCE, self.nonce.encode())
            msg = self._add_auth(ALLOCATE, attrs)
            self._send_stun(msg)
            resp = self._recv_stun(10)
            if not resp: return False
            rtype = struct.unpack('>H', resp[0:2])[0]
        if rtype == ALLOCATE_SUCCESS:
            pos = 20
            while pos < len(resp):
                at, al = struct.unpack('>HH', resp[pos:pos+4])
                ad = resp[pos+4:pos+4+al]
                if at == ATTR_XOR_RELAYED:
                    self.relay_ip, self.relay_port = self._parse_xor_addr(ad)
                pos += 4 + al + ((4 - al % 4) % 4)
            print(f"  [TURN] Relay: {self.relay_ip}:{self.relay_port}")
            return True
        print(f"  [TURN] Allocate failed: 0x{rtype:04x}")
        return False

    def create_permission(self, peer_ip, peer_port):
        attrs = self._attr(ATTR_XOR_PEER, self._xor_addr(peer_ip, peer_port))
        attrs += self._attr(ATTR_USERNAME, self.user.encode())
        attrs += self._attr(ATTR_REALM, self.realm.encode())
        attrs += self._attr(ATTR_NONCE, self.nonce.encode())
        msg = self._add_auth(CREATE_PERM, attrs)
        self._send_stun(msg)
        resp = self._recv_stun(10)
        return resp and struct.unpack('>H', resp[0:2])[0] == CREATE_PERM_SUCCESS

    def sendto(self, data):
        attrs = self._attr(ATTR_XOR_PEER, self._xor_addr(WOT_SERVER_IP, WOT_SERVER_PORT))
        attrs += self._attr(ATTR_DATA, data)
        msg, _ = self._msg(SEND_IND, attrs)
        self._send_stun(msg)

    def recvfrom(self, timeout=30):
        data = self._recv_stun(timeout)
        if data:
            rtype = struct.unpack('>H', data[0:2])[0]
            if rtype == DATA_IND:
                pos = 20
                while pos < len(data):
                    at, al = struct.unpack('>HH', data[pos:pos+4])
                    ad = data[pos+4:pos+4+al]
                    if at == ATTR_DATA: return ad
                    pos += 4 + al + ((4 - al % 4) % 4)
        return None

    def close(self):
        if self.sock: self.sock.close()

# ============ BOT PROTOCOL ============
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
        flags |= 0x0001; footer = struct.pack("<H", first_req + 2)
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
        ln = ((pkt[pos] & 0x7F) << 8) | pkt[pos+1]
        body = pkt[pos+2:pos+2+ln]
    else:
        ln = ((pkt[pos] & 0x7F) << 8) | pkt[pos+1]
        body = pkt[pos+6:pos+6+ln]
    return (body[0] if body else 0, body[1:] if len(body) > 1 else b"")

# ============ CUCKOO SOLVER ============
CUCKOO_SRC = r"""/*
 * Fast Cuckoo Cycle solver - matches Python algorithm exactly
 * Compile: gcc -O3 -shared -fPIC -o cuckoo_fast.so cuckoo_fast.c
 *       or: clang -O3 -shared -fPIC -o cuckoo_fast.so cuckoo_fast.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* SHA-256 */
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
static const uint32_t K256[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

static void sha256(const uint8_t*msg,size_t len,uint8_t out[32]){
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint64_t bl=(uint64_t)len*8;
    size_t pl=len+1; while(pl%64!=56)pl++; pl+=8;
    uint8_t*p=(uint8_t*)calloc(pl,1);
    memcpy(p,msg,len); p[len]=0x80;
    for(int i=0;i<8;i++)p[pl-8+i]=(uint8_t)(bl>>(56-i*8));
    for(size_t b=0;b<pl;b+=64){
        uint32_t w[64];
        for(int i=0;i<16;i++)w[i]=((uint32_t)p[b+i*4]<<24)|((uint32_t)p[b+i*4+1]<<16)|((uint32_t)p[b+i*4+2]<<8)|p[b+i*4+3];
        for(int i=16;i<64;i++){uint32_t s0=ROR32(w[i-15],7)^ROR32(w[i-15],18)^(w[i-15]>>3),s1=ROR32(w[i-2],17)^ROR32(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}
        uint32_t a=h[0],b2=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int i=0;i<64;i++){uint32_t S1=ROR32(e,6)^ROR32(e,11)^ROR32(e,25),ch=(e&f)^(~e&g),t1=hh+S1+ch+K256[i]+w[i],S0=ROR32(a,2)^ROR32(a,13)^ROR32(a,22),maj=(a&b2)^(a&c)^(b2&c),t2=S0+maj;hh=g;g=f;f=e;e=d+t1;d=c;c=b2;b2=a;a=t1+t2;}
        h[0]+=a;h[1]+=b2;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    free(p);
    for(int i=0;i<8;i++){out[i*4]=(h[i]>>24)&0xFF;out[i*4+1]=(h[i]>>16)&0xFF;out[i*4+2]=(h[i]>>8)&0xFF;out[i*4+3]=h[i]&0xFF;}
}

/* SipHash-2-4 */
#define ROTL64(x,n) (((x)<<(n))|((x)>>(64-(n))))
#define SIPR \
    v0+=v1; v1=ROTL64(v1,13); v1^=v0; v0=ROTL64(v0,32); \
    v2+=v3; v3=ROTL64(v3,16); v3^=v2; \
    v0+=v3; v3=ROTL64(v3,21); v3^=v0; \
    v2+=v1; v1=ROTL64(v1,17); v1^=v2; v2=ROTL64(v2,32);

static inline uint64_t siphash24(uint64_t k0,uint64_t k1,uint64_t n){
    uint64_t v0=k0^0x736f6d6570736575ULL,v1=k1^0x646f72616e646f6dULL,v2=k0^0x6c7967656e657261ULL,v3=k1^0x7465646279746573ULL;
    v3^=n; SIPR; SIPR; v0^=n; v2^=0xff; SIPR; SIPR; SIPR; SIPR;
    return v0^v1^v2^v3;
}

#define SIZESHIFT 20
#define PROOFSIZE 42
#define SIZE (1ULL<<SIZESHIFT)
#define HALFSIZE (SIZE/2)
#define NODEMASK (HALFSIZE-1)
#define MAXPATH 8192

static uint32_t ck[(1<<SIZESHIFT)+1]; /* 4MB static */
static uint32_t us[MAXPATH], vs[MAXPATH];

static int find_sol(uint64_t k0,uint64_t k1,uint32_t*us,int nu,uint32_t*vs,int nv,uint64_t max_nonce,uint32_t*sol){
    uint32_t cu[42],cv[42]; int nc=0;
    cu[nc]=us[0]; cv[nc]=vs[0]; nc++;
    for(int i=nu;i>0;){i--; cu[nc]=us[(i+1)&~1]; cv[nc]=us[i|1]; nc++;}
    for(int i=nv;i>0;){i--; cu[nc]=vs[i|1]; cv[nc]=vs[(i+1)&~1]; nc++;}
    if(nc!=42) return 0;
    int found=0;
    for(uint64_t n=0;n<max_nonce&&found<42;n++){
        uint32_t u=(uint32_t)(siphash24(k0,k1,2*n)&NODEMASK)+1;
        uint32_t v=(uint32_t)(siphash24(k0,k1,2*n+1)&NODEMASK)+1+HALFSIZE;
        for(int k=0;k<42;k++){
            if(cu[k]==u&&cv[k]==v){
                sol[found++]=(uint32_t)n;
                cu[k]=0; cv[k]=0;
                break;
            }
        }
    }
    return found==42?1:0;
}

/* Main solver: matches Python solve_cuckoo() exactly */
int cuckoo_solve(const char*key_str,uint64_t max_nonce,uint32_t*sol){
    uint8_t hash[32];
    sha256((const uint8_t*)key_str,strlen(key_str),hash);
    uint64_t k0=0,k1=0;
    for(int i=0;i<8;i++)k0|=((uint64_t)hash[i]<<(i*8));
    for(int i=0;i<8;i++)k1|=((uint64_t)hash[8+i]<<(i*8));

    memset(ck,0,sizeof(ck));
    uint64_t c=0;

    for(uint64_t n=0;n<max_nonce;n++){
        uint32_t u0=(uint32_t)(siphash24(k0,k1,2*n)&NODEMASK)+1;
        uint32_t v0=(uint32_t)(siphash24(k0,k1,2*n+1)&NODEMASK)+1+HALFSIZE;
        uint32_t u=ck[u0],v=ck[v0];
        if(u==v0||v==u0) continue;

        us[0]=u0; vs[0]=v0;
        int nu=0; uint32_t node=u;
        while(node){if(++nu>=MAXPATH)return 0; us[nu]=node; node=ck[node];}
        int nv=0; node=v;
        while(node){if(++nv>=MAXPATH)return 0; vs[nv]=node; node=ck[node];}

        if(us[nu]==vs[nv]){
            int m=nu<nv?nu:nv; nu-=m; nv-=m;
            while(us[nu]!=vs[nv]){nu++;nv++;}
            int cl=nu+nv+1; c++;
            if(cl==PROOFSIZE){
                return find_sol(k0,k1,us,nu,vs,nv,max_nonce,sol);
            }
            continue;
        }
        if(nu<nv){
            while(nu){nu--; ck[us[nu+1]]=us[nu];}
            ck[u0]=v0;
        } else {
            while(nv){nv--; ck[vs[nv+1]]=vs[nv];}
            ck[v0]=u0;
        }
    }
    return 0;
}
"""

def load_cuckoo_solver():
    lib_path = os.path.join(tempfile.gettempdir(), "cuckoo_turn.so")
    src_path = os.path.join(tempfile.gettempdir(), "cuckoo_turn.c")
    with open(src_path, 'w') as f: f.write(CUCKOO_SRC)
    for compiler in ['clang', 'gcc', 'cc']:
        try:
            r = subprocess.run([compiler, '-O3', '-shared', '-fPIC', '-o', lib_path, src_path],
                             capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                lib = ctypes.CDLL(lib_path)
                lib.cuckoo_solve.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint32)]
                lib.cuckoo_solve.restype = ctypes.c_int
                print("  [Cuckoo] C solver loaded")
                return lib
        except FileNotFoundError: continue
        except Exception: continue
    print("  [Cuckoo] No C compiler, using Python fallback (slow)")
    return None

def solve_cuckoo(lib, key_str, max_nonce):
    if lib:
        sol = (ctypes.c_uint32 * 42)()
        t0 = time.time()
        ret = lib.cuckoo_solve(key_str.encode(), ctypes.c_uint64(max_nonce), sol)
        t1 = time.time()
        if ret == 1: return list(sol), t1 - t0
        return None, t1 - t0
    # Python fallback
    import hashlib as hl
    h = hl.sha256(key_str.encode()).digest()
    k0 = int.from_bytes(h[:8], 'little'); k1 = int.from_bytes(h[8:16], 'little')
    # ... (simplified Python siphash - same as C code)
    SIZESHIFT = 20; HALFSIZE = 1 << SIZESHIFT; NODEMASK = HALFSIZE - 1
    def siphash24(k0, k1, n):
        v0=k0^0x736f6d6570736575; v1=k1^0x646f72616e646f6d
        v2=k0^0x6c7967656e657261; v3=k1^0x7465646279746573
        v3^=n
        for _ in range(2):
            v0+=v1; v1=((v1<<13)|(v1>>51))&0xFFFFFFFFFFFFFFFF; v1^=v0; v0=((v0<<32)|(v0>>32))&0xFFFFFFFFFFFFFFFF
            v2+=v3; v3=((v3<<16)|(v3>>48))&0xFFFFFFFFFFFFFFFF; v3^=v2
            v0+=v3; v3=((v3<<21)|(v3>>43))&0xFFFFFFFFFFFFFFFF; v3^=v0
            v2+=v1; v1=((v1<<17)|(v1>>47))&0xFFFFFFFFFFFFFFFF; v1^=v2; v2=((v2<<32)|(v2>>32))&0xFFFFFFFFFFFFFFFF
        v0^=n; v2^=0xFF
        for _ in range(4):
            v0+=v1; v1=((v1<<13)|(v1>>51))&0xFFFFFFFFFFFFFFFF; v1^=v0; v0=((v0<<32)|(v0>>32))&0xFFFFFFFFFFFFFFFF
            v2+=v3; v3=((v3<<16)|(v3>>48))&0xFFFFFFFFFFFFFFFF; v3^=v2
            v0+=v3; v3=((v3<<21)|(v3>>43))&0xFFFFFFFFFFFFFFFF; v3^=v0
            v2+=v1; v1=((v1<<17)|(v1>>47))&0xFFFFFFFFFFFFFFFF; v1^=v2; v2=((v2<<32)|(v2>>32))&0xFFFFFFFFFFFFFFFF
        return (v0^v1^v2^v3) & NODEMASK
    t0 = time.time()
    ck = [0] * (HALFSIZE + 1)
    for n in range(max_nonce):
        u0 = siphash24(k0, k1, 2*n) + 1
        v0 = siphash24(k0, k1, 2*n+1) + 1 + HALFSIZE
        u = ck[u0]; v = ck[v0]
        if u == v0 or v == u0: continue
        us = [u0]; vs = [v0]
        node = u
        while node and len(us) < 8192:
            us.append(node); node = ck[node]
        node = v
        while node and len(vs) < 8192:
            vs.append(node); node = ck[node]
        nu = len(us) - 1; nv = len(vs) - 1
        if us[nu] == vs[nv]:
            m = min(nu, nv); nu -= m; nv -= m
            while us[nu] != vs[nv]: nu += 1; nv += 1
            if nu + nv + 1 == 42:
                # Found! Extract solution
                sol = []
                cu = []; cv = []
                cu.append(us[0]); cv.append(vs[0])
                for i in range(nu, 0, -1): cu.append(us[(i+1)&~1]); cv.append(us[i|1])
                for i in range(nv, 0, -1): cu.append(vs[i|1]); cv.append(vs[(i+1)&~1])
                for nn in range(max_nonce):
                    u = siphash24(k0, k1, 2*nn) + 1
                    v = siphash24(k0, k1, 2*nn+1) + 1 + HALFSIZE
                    for k in range(42):
                        if cu[k] == u and cv[k] == v:
                            sol.append(nn); cu[k] = 0; cv[k] = 0; break
                    if len(sol) == 42: break
                t1 = time.time()
                return sol, t1 - t0
            continue
        if nu < nv:
            for i in range(nu): ck[us[i+1]] = us[i]
            ck[u0] = v0
        else:
            for i in range(nv): ck[vs[i+1]] = vs[i]
            ck[v0] = u0
    t1 = time.time()
    return None, t1 - t0

def build_cr_body(duration, key_str, solution):
    body = struct.pack("<f", duration)
    body += pack_str_u24(key_str)
    body += b''.join(struct.pack("<I", n) for n in solution)
    return body

# ============ LOGIN BUILDER ============
def build_login(bf_key, login_nonce, str_fmt="u24", use_ctx=False, ctx_str="",
                flag_mode="none", use_pkcs1=False, use_sha256=False):
    logon = struct.pack("<B", 0)
    if str_fmt == "u24":
        logon += pack_str_u24("guest") + pack_str_u24("") + pack_str_u24(bf_key)
        if use_ctx: logon += pack_str_u24(ctx_str)
    else:
        logon += pack_str_u32("guest") + pack_str_u32("") + pack_str_u32(bf_key)
        if use_ctx: logon += pack_str_u32(ctx_str)
    logon += struct.pack("<I", login_nonce)
    
    if use_pkcs1:
        encrypted = rsa_pkcs1_encrypt(KEY_N, KEY_E, logon)
    else:
        hf = hashlib.sha256 if use_sha256 else hashlib.sha1
        encrypted = rsa_oaep_encrypt(KEY_N, KEY_E, logon, hf)
    
    body = struct.pack("<I", PROTOCOL)
    if flag_mode == "flag": body += struct.pack("<B", 1)
    elif flag_mode == "len": body += pack_u24(len(encrypted))
    body += encrypted
    return body

# ============ MAIN ============
def main():
    print("=" * 60)
    print("  WoT Bot v61 — TURN + Pure Python Crypto")
    print("  No pip install needed!")
    print("=" * 60)
    
    cuckoo_lib = load_cuckoo_solver()
    
    print("\n[1] Connecting to TURN server...")
    turn = None
    for srv in TURN_SERVERS:
        host = srv["host"]; port = srv["port"]; use_tls = srv.get("tls", False)
        print(f"  Trying {host}:{port}{' (TLS)' if use_tls else ''}...")
        turn = TurnClient(host, port, srv["user"], srv["pass"], srv.get("realm", ""))
        try:
            turn.connect(use_tls=use_tls)
            # Quick STUN binding test
            txn = os.urandom(12)
            binding = struct.pack('>HHI', 0x0001, 0, MAGIC) + txn
            turn._send_stun(binding)
            resp = turn._recv_stun(timeout=5)
            if resp and len(resp) >= 20:
                rtype = struct.unpack('>H', resp[0:2])[0]
                if rtype == 0x0101:  # Binding Success
                    print(f"  ✓ STUN binding OK!")
                    break
                else:
                    print(f"  Got 0x{rtype:04x} (not STUN)")
                    turn.close(); turn = None
            else:
                print(f"  No response")
                turn.close(); turn = None
        except Exception as e:
            print(f"  Failed: {e}")
            turn = None
    if not turn:
        print("  All TURN servers failed!"); return
    
    print("\n[2] Allocating TURN relay...")
    if not turn.allocate():
        print("  Failed!"); turn.close(); return
    
    print(f"\n[3] Permission for WoT server...")
    if not turn.create_permission(WOT_SERVER_IP, WOT_SERVER_PORT):
        print("  Failed!"); turn.close(); return
    print("  OK")
    
    rid = 1; bf_key = os.urandom(56)
    login_nonce = random.randint(1, 0xFFFFFFFF)
    
    print("\n[4] PING test via TURN...")
    ping = build_packet(build_request_fixed(0x02, rid, struct.pack("<B", 0)), first_req=0)
    turn.sendto(ping)
    pong = turn.recvfrom(15)
    if not pong:
        print("  PING FAILED - WoT not responding through TURN")
        print("  WoT may block the TURN server IP")
        turn.close(); return
    print(f"  PING OK! {len(pong)}B")
    rid += 1
    
    def get_challenge():
        nonlocal rid
        logon = struct.pack("<B", 0) + pack_str_u24("guest") + pack_str_u24("") + pack_str_u24(bf_key)
        logon += struct.pack("<I", login_nonce)
        lb = struct.pack("<I", PROTOCOL) + logon
        le = build_request_v16(0x00, rid, lb)
        pk = build_packet(le, first_req=0)
        turn.sendto(pk)
        cr = turn.recvfrom(15)
        if cr:
            r = parse_reply(cr)
            if r and r[0] == 0x42:
                cb = r[1]
                ps = cb[1:18].decode('utf-8', errors='replace')
                mn = struct.unpack("<I", cb[18:22])[0] if len(cb) > 21 else 576716
                rid += 1
                return ps, mn
        return None, None
    
    print("\n[5] Getting Cuckoo challenge...")
    prefix_str, max_nonce = get_challenge()
    if not prefix_str:
        print("  Failed!"); turn.close(); return
    print(f"  prefix={prefix_str}, max_nonce={max_nonce}")
    
    combos = [
        ("OFFICIAL+u24+no-ctx+noflag",   "u24", False, "",              "none",  False, False),
        ("OFFICIAL+u24+no-ctx+flag",     "u24", False, "",              "flag",  False, False),
        ("OFFICIAL+u24+no-ctx+len",      "u24", False, "",              "len",   False, False),
        ("OFFICIAL+u24+ctx+noflag",      "u24", True,  "eu_1.19.1_4",  "none",  False, False),
        ("OFFICIAL+u24+ctx+flag",       "u24", True,  "eu_1.19.1_4",  "flag",  False, False),
        ("OFFICIAL+u24+ctx+len",        "u24", True,  "eu_1.19.1_4",  "len",   False, False),
        ("OFFICIAL+u32+no-ctx+noflag",    "u32", False, "",              "none",  False, False),
        ("OFFICIAL+u32+no-ctx+flag",     "u32", False, "",              "flag",  False, False),
        ("OFFICIAL+u32+no-ctx+len",      "u32", False, "",              "len",   False, False),
        ("OFFICIAL+u24+no-ctx+flag+pkcs1","u24", False, "",             "flag",  True,  False),
        ("OFFICIAL+u24+no-ctx+noflag+sha256","u24", False, "",           "none",  False, True),
        ("OFFICIAL+u24+no-ctx+flag+sha256","u24", False, "",            "flag",  False, True),
    ]
    
    for i, (name, sf, uc, cs, fm, up, us) in enumerate(combos):
        if i > 0:
            ping = build_packet(build_request_fixed(0x02, rid, struct.pack("<B", 0)), first_req=0)
            turn.sendto(ping); turn.recvfrom(5)
            prefix_str, max_nonce = get_challenge()
            if not prefix_str:
                print(f"\n  [{name}] No challenge"); continue
        
        for counter in range(15):
            key_str = f"{prefix_str}{counter}"
            solution, st = solve_cuckoo(cuckoo_lib, key_str, max_nonce)
            if solution and len(solution) == 42:
                print(f"\n  [{name}] Cuckoo: counter={counter}, {st:.1f}s")
                cr_body = build_cr_body(st, key_str, solution)
                cr_elem = build_message_v16(0x03, cr_body)
                break
        else:
            print(f"\n  [{name}] Cuckoo failed"); continue
        
        lb = build_login(bf_key, login_nonce, sf, uc, cs, fm, up, us)
        le = build_request_v16(0x00, rid, lb)
        pkt = build_packet(cr_elem + le, first_req=len(cr_elem))
        
        print(f"  body={len(lb)}B pkt={len(pkt)}B")
        turn.sendto(pkt)
        resp = turn.recvfrom(30)
        if resp:
            print(f"  Got {len(resp)}B: {resp.hex()[:100]}")
            r = parse_reply(resp)
            if r:
                st, msg = r[0], r[1].decode("utf-8", errors="replace")[:150] if len(r)>1 else ""
                print(f"  Status: 0x{st:02X}")
                if msg.strip(): print(f"  Msg: {msg}")
                if st == 0x01:
                    print("\n  *** LOGIN SUCCESS! ***")
                    print(f"  Format: {name}")
                    turn.close(); return
                elif st == 0x40: print("  -> destream")
                elif st == 0x55: print("  -> failed challenge")
                else: print(f"  -> 0x{st:02X}")
        else:
            print("  No response")
    
    turn.close()
    print("\n" + "=" * 60)
    print("  Done. If all 0x40, key may be wrong.")
    print("=" * 60)

if __name__ == "__main__":
    main()

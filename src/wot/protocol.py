#!/usr/bin/env python3
"""WoT Protocol Classes - Clean packet encoding/decoding"""
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
import struct


@dataclass(frozen=True)
class ProtocolConfig:
    """Centralized protocol constants"""
    server_host: str = "login.p1.worldoftanks.eu"
    server_port: int = 20016
    protocol_version: int = 285278213  # 17.1.0 (5)
    proof_size: int = 42
    size_shift: int = 20
    client_version: str = "1.25.1.0"
    service: str = "EU"


@dataclass
class PacketHeader:
    """BigWorld packet header"""
    prefix: int = 0
    flags: int = 0
    
    FLAG_HAS_REQUESTS = 0x0001
    
    def encode(self) -> bytes:
        return struct.pack("<IH", self.prefix, self.flags)
    
    @classmethod
    def decode(cls, data: bytes) -> Tuple['PacketHeader', bytes]:
        if len(data) < 6:
            raise ValueError("Packet too short for header")
        prefix = struct.unpack_from("<I", data, 0)[0]
        flags = struct.unpack_from("<H", data, 4)[0]
        return cls(prefix=prefix, flags=flags), data[6:]


@dataclass
class Element:
    """BigWorld request/response element"""
    element_id: int
    request_id: int = 0
    payload: bytes = b""
    
    def encode(self) -> bytes:
        """Encode as: elem_id(1B) + request_id(4B) + pad(2B) + payload"""
        return struct.pack("<B", self.element_id) + \
               struct.pack("<IH", self.request_id, 0) + \
               self.payload
    
    @classmethod
    def decode(cls, data: bytes) -> Tuple['Element', bytes]:
        if len(data) < 7:
            raise ValueError("Data too short for element")
        elem_id = data[0]
        request_id = struct.unpack_from("<I", data, 1)[0]
        # Skip 2 bytes padding
        payload = data[7:]
        return cls(element_id=elem_id, request_id=request_id, payload=payload), b""


@dataclass
class ChallengeResponse:
    """Cuckoo cycle challenge response"""
    key_prefix: bytes
    solution: List[int]  # 42 nonces
    
    def encode(self) -> bytes:
        """Encode CR body: key(u24-prefixed) + 42×u32 nonces"""
        # Pack key with u24 length prefix
        key_len = len(self.key_prefix)
        if key_len >= 255:
            key_data = struct.pack("<B", 0xFF) + struct.pack("<I", key_len)[:3] + self.key_prefix
        else:
            key_data = struct.pack("<B", key_len) + self.key_prefix
        
        # Pack 42 nonces as u32 LE
        nonce_data = b''.join(struct.pack("<I", n) for n in self.solution)
        return key_data + nonce_data
    
    def validate(self) -> bool:
        """Validate solution has correct size"""
        return len(self.solution) == 42


@dataclass
class LogOnParams:
    """Login credentials container"""
    username: str
    password: str
    bf_key: bytes = b""
    challenge_response: Optional[bytes] = None
    context: str = ""
    nonce: int = field(default_factory=lambda: __import__('random').randint(1, 0xFFFFFFFF))
    client_version: str = "1.25.1.0"
    service: str = "EU"
    
    def encode_legacy(self) -> bytes:
        """
        Legacy BigWorld format with MD5 digest.
        Format: [flags][digest][username_u8][password_u8][bf_key_u8][context_u8][nonce]
        """
        import hashlib
        
        credentials = f"{self.username}:{self.password}".encode('utf-8')
        digest = hashlib.md5(credentials).digest()
        
        logon = struct.pack("<B", 0x01)  # flags = has digest
        logon += digest                  # 16-byte MD5
        logon += self._pack_str_u8(self.username)
        logon += self._pack_str_u8(self.password)
        logon += self._pack_str_u8(self.bf_key)
        logon += self._pack_str_u8(self.context)
        logon += struct.pack("<I", self.nonce)
        
        return logon
    
    def encode_reversed(self) -> bytes:
        """
        RE-based format from WorldOfTanks.exe analysis.
        Format: username[u32] + password[u32] + service[u32] + version[u32] + metadata[u32] + state[16]
        """
        import time
        
        def write_string(s: str) -> bytes:
            data = s.encode('utf-8')
            return struct.pack('<I', len(data)) + data
        
        payload = b''
        payload += write_string(self.username)
        payload += write_string(self.password)
        payload += write_string(self.service)
        payload += write_string(self.client_version)
        
        # Metadata: timestamp-based nonce
        nonce = int(time.time()) & 0xFFFFFFFF
        payload += struct.pack('<I', nonce)
        
        # State: 16 zeroed bytes
        payload += b'\x00' * 16
        
        return payload
    
    @staticmethod
    def _pack_str_u8(s: str) -> bytes:
        """Pack string with 1-byte length prefix"""
        b = s.encode('utf-8') if isinstance(s, str) else s
        if len(b) > 255:
            raise ValueError("String too long for u8 length prefix")
        return struct.pack("<B", len(b)) + b
    
    @staticmethod
    def _pack_str_u32(s: str) -> bytes:
        """Pack string with 4-byte length prefix"""
        b = s.encode('utf-8') if isinstance(s, str) else s
        return struct.pack("<I", len(b)) + b


@dataclass
class LoginRequest:
    """RSA-encrypted login request"""
    protocol: int
    encrypted_payload: bytes
    
    def encode(self) -> bytes:
        """Encode: protocol(4B) + flag(1B) + encrypted(256B)"""
        return struct.pack("<I", self.protocol) + struct.pack("<B", 1) + self.encrypted_payload


@dataclass
class PingRequest:
    """Simple ping request"""
    request_id: int = 0
    
    def encode(self) -> bytes:
        elem = struct.pack("<B", 0x02) + struct.pack("<IH", self.request_id, 0) + struct.pack("<B", 0)
        return build_packet(elem, first_req=0)


def build_packet(content: bytes, first_req: Optional[int] = None) -> bytes:
    """Build complete packet with prefix and optional request footer"""
    flags = 0
    footer = b""
    
    if first_req is not None:
        flags |= PacketHeader.FLAG_HAS_REQUESTS
        footer = struct.pack("<H", first_req + 2)
    
    raw = struct.pack("<IH", 0, flags) + content + footer
    prefix = _compute_prefix(raw)
    return struct.pack("<I", prefix) + raw[4:]


def _compute_prefix(raw: bytes) -> int:
    """Compute packet prefix checksum"""
    p0 = struct.unpack_from("<I", raw, 4)[0] if len(raw) >= 8 else 0
    p1 = struct.unpack_from("<I", raw, 8)[0] if len(raw) >= 12 else 0
    a = (p0 + p1) & 0xFFFFFFFF
    b = (a << 13) & 0xFFFFFFFF
    c = ((b ^ a) >> 17) & 0xFFFFFFFF
    return (c ^ b ^ a ^ ((c ^ b ^ a) << 5)) & 0xFFFFFFFF


def parse_reply(data: bytes) -> Optional[Tuple[int, int, bytes]]:
    """Parse server reply: (element_id, request_id, response_data)"""
    if len(data) < 6:
        return None
    
    content = data[6:]
    pos = len(content)
    flags = struct.unpack_from("<H", data, 4)[0]
    
    if flags & PacketHeader.FLAG_HAS_REQUESTS:
        pos -= 2
    
    elem = content[:pos]
    if not elem or elem[0] != 0xFF:
        return None
    
    length = struct.unpack_from("<I", elem, 1)[0]
    rdata = elem[5:5+length]
    
    if len(rdata) < 5:
        return None
    
    return (rdata[4], struct.unpack_from("<I", rdata, 0)[0], rdata[5:])

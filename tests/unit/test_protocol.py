#!/usr/bin/env python3
"""Unit tests for WoT protocol packet encoding/decoding"""
import pytest
import struct
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.wot.protocol import (
    ProtocolConfig,
    PacketHeader,
    Element,
    ChallengeResponse,
    LogOnParams,
    build_packet,
    parse_reply
)


class TestProtocolConfig:
    """Test protocol configuration constants"""
    
    def test_default_values(self):
        config = ProtocolConfig()
        assert config.server_host == "login.p1.worldoftanks.eu"
        assert config.server_port == 20016
        assert config.proof_size == 42
        assert config.size_shift == 20
    
    def test_immutability(self):
        config = ProtocolConfig()
        with pytest.raises(Exception):  # frozen=True
            config.server_port = 9999


class TestPacketHeader:
    """Test packet header encoding/decoding"""
    
    def test_encode_basic(self):
        header = PacketHeader(prefix=0x12345678, flags=0x0001)
        encoded = header.encode()
        assert len(encoded) == 6
        assert encoded[:4] == struct.pack("<I", 0x12345678)
        assert encoded[4:6] == struct.pack("<H", 0x0001)
    
    def test_decode_basic(self):
        data = struct.pack("<IH", 0xABCDEF00, 0x0001) + b"payload"
        header, remaining = PacketHeader.decode(data)
        assert header.prefix == 0xABCDEF00
        assert header.flags == 0x0001
        assert remaining == b"payload"
    
    def test_decode_short(self):
        with pytest.raises(ValueError):
            PacketHeader.decode(b"short")
    
    def test_flag_has_requests(self):
        assert PacketHeader.FLAG_HAS_REQUESTS == 0x0001


class TestElement:
    """Test request/response element encoding"""
    
    def test_encode_basic(self):
        elem = Element(element_id=0x02, request_id=1, payload=b"\x00")
        encoded = elem.encode()
        assert encoded[0] == 0x02
        assert struct.unpack_from("<I", encoded, 1)[0] == 1
    
    def test_decode_basic(self):
        data = struct.pack("<B", 0xFF) + struct.pack("<IH", 99, 0) + b"data"
        elem, remaining = Element.decode(data)
        assert elem.element_id == 0xFF
        assert elem.request_id == 99
    
    def test_validate_solution(self):
        cr = ChallengeResponse(
            key_prefix=b"test_key",
            solution=list(range(42))
        )
        assert cr.validate() is True
        
        # Invalid solution size
        cr.solution = list(range(41))
        assert cr.validate() is False


class TestLogOnParams:
    """Test login credential encoding"""
    
    def test_encode_legacy_format(self):
        params = LogOnParams(
            username="testuser",
            password="testpass",
            bf_key=b"key" * 18 + b"12",  # 56 bytes
            context=""
        )
        encoded = params.encode_legacy()
        
        # Should start with flags byte 0x01 (has digest)
        assert encoded[0] == 0x01
        
        # Next 16 bytes should be MD5 digest
        import hashlib
        expected_digest = hashlib.md5(b"testuser:testpass").digest()
        assert encoded[1:17] == expected_digest
    
    def test_encode_reversed_format(self):
        params = LogOnParams(
            username="testuser",
            password="testpass",
            client_version="1.25.1.0",
            service="EU"
        )
        encoded = params.encode_reversed()
        
        # Should contain username, password, service, version as u32-prefixed strings
        assert b"testuser" in encoded
        assert b"testpass" in encoded
        assert b"EU" in encoded
        assert b"1.25.1.0" in encoded
        
        # Should end with 16 zeroed state bytes
        assert encoded[-16:] == b'\x00' * 16
    
    def test_mask_username(self):
        from src.wot.auth import mask_username
        assert mask_username("john@example.com") == "joh***"
        assert mask_username("ab") == "***"
        assert mask_username("abc") == "***"


class TestChallengeResponse:
    """Test Cuckoo challenge response encoding"""
    
    def test_encode_solution(self):
        solution = list(range(42))  # Nonces 0-41
        cr = ChallengeResponse(
            key_prefix=b"test_key_123",
            solution=solution
        )
        encoded = cr.encode()
        
        # Key length prefix + key + 42 * 4 bytes
        expected_len = 1 + len(b"test_key_123") + (42 * 4)
        assert len(encoded) == expected_len
        
        # Verify nonces are packed as u32 LE
        offset = 1 + len(b"test_key_123")
        for i in range(42):
            nonce = struct.unpack_from("<I", encoded, offset + i*4)[0]
            assert nonce == i
    
    def test_validate_empty(self):
        cr = ChallengeResponse(key_prefix=b"key", solution=[])
        assert cr.validate() is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

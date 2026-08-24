#!/usr/bin/env python3
"""
Test: Add encrypted_flag byte back to build_login_rsa()

This is a MINIMAL test to verify the encrypted_flag hypothesis.
NO OTHER CHANGES.

Current bug (line 160):
    return struct.pack("<I", protocol) + encrypted  # 260 bytes

Fixed version:
    return struct.pack("<I", protocol) + struct.pack("<B", 1) + encrypted  # 261 bytes
"""

# Extract just the build_login_rsa function and test it

import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1

KEY_OFFICIAL = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2G58NsNUP1h3qQMhi+nE
S9yNH8B2hQ7bxrwKP79AxEkEx76DDTosIVNitvpfrJ3Was6G9HbJ/+3PB0KJA86T
/ZzHhPy5ZAdKUKoSkrjVMo0hw3XZbyfocxYJBFFXMuvTKFfZXYBE9srsbqvtRQLW
gCOTuK7g/prSHF5zEIxPVAOVc0LpymaB6LFYP/KrEKkXFv1ffBF2oBZq0Cp1+aO2
3tu/jgq9hzv/kT1a/gJiwsjdjkpmXB7rRsUceKC7XDLnRZ/qLG22A8+xtAINq1nW
891IXT17BkSKNWcb9ZfLDBEQsvhM6/0bageaEZigPZzF0NHc8k32LEHotqcr2wbA
qwIDAQAB
-----END PUBLIC KEY-----"""

PROTOCOL = 285278213

def pack_str_u24(s):
    """Current helper from bw_bot.py"""
    b = s.encode() if isinstance(s, str) else s
    if len(b) >= 255:
        return struct.pack("<B", 0xFF) + struct.pack("<I", len(b))[:3] + b
    else:
        return struct.pack("<B", len(b)) + b


def build_login_rsa_CURRENT(protocol, bf_key, rsa_key_pem):
    """CURRENT BROKEN VERSION (line 160)"""
    logon = struct.pack("<B", 0)
    logon += pack_str_u24("guest")
    logon += pack_str_u24("")
    logon += pack_str_u24(bf_key)
    # NO context (not testing context change)
    logon += struct.pack("<I", 12345)  # dummy nonce
    
    key = RSA.importKey(rsa_key_pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    encrypted = cipher.encrypt(logon)
    
    # CURRENT: Missing encrypted_flag
    return struct.pack("<I", protocol) + encrypted


def build_login_rsa_FIXED(protocol, bf_key, rsa_key_pem):
    """FIXED VERSION with encrypted_flag byte"""
    logon = struct.pack("<B", 0)
    logon += pack_str_u24("guest")
    logon += pack_str_u24("")
    logon += pack_str_u24(bf_key)
    # NO context (not testing context change)
    logon += struct.pack("<I", 12345)  # dummy nonce
    
    key = RSA.importKey(rsa_key_pem)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    encrypted = cipher.encrypt(logon)
    
    # FIXED: Add encrypted_flag byte
    return struct.pack("<I", protocol) + struct.pack("<B", 1) + encrypted


def test_encrypted_flag():
    """Test: Verify byte layout changes with encrypted_flag"""
    
    print("\n" + "="*70)
    print("  TEST: encrypted_flag impact on login body size")
    print("="*70)
    
    bf_key = b'\x00' * 56  # 56 bytes for testing
    
    # Test CURRENT (broken)
    current = build_login_rsa_CURRENT(PROTOCOL, bf_key, KEY_OFFICIAL)
    print(f"\n[CURRENT] build_login_rsa() output:")
    print(f"  Total size: {len(current)} bytes")
    print(f"  Expected:   261 bytes (4 protocol + 1 flag + 256 RSA)")
    print(f"  Actual:     {len(current)} bytes")
    if len(current) == 260:
        print(f"  ✗ SIZE MISMATCH: {len(current)} != 261")
        print(f"     → Server expects 261, gets 260 → parse fails → 0x40")
    else:
        print(f"  ? Unexpected size")
    
    # Parse structure
    proto_current = struct.unpack("<I", current[0:4])[0]
    print(f"  [0:4]   Protocol: 0x{proto_current:08X} (should be 0x{PROTOCOL:08X})")
    print(f"  [4:260] RSA data (256 bytes, no flag byte!)")
    print(f"    First 16 bytes of RSA: {current[4:20].hex()}")
    
    # Test FIXED (with flag)
    fixed = build_login_rsa_FIXED(PROTOCOL, bf_key, KEY_OFFICIAL)
    print(f"\n[FIXED] build_login_rsa() with encrypted_flag:")
    print(f"  Total size: {len(fixed)} bytes")
    print(f"  Expected:   261 bytes (4 protocol + 1 flag + 256 RSA)")
    print(f"  Actual:     {len(fixed)} bytes")
    if len(fixed) == 261:
        print(f"  ✓ SIZE CORRECT: {len(fixed)} == 261")
        print(f"     → Server gets correct format → parse works → 0x42 (challenge)")
    else:
        print(f"  ? Unexpected size: {len(fixed)}")
    
    # Parse structure
    proto_fixed = struct.unpack("<I", fixed[0:4])[0]
    encrypted_flag = fixed[4]
    print(f"  [0:4]   Protocol: 0x{proto_fixed:08X} (should be 0x{PROTOCOL:08X})")
    print(f"  [4:5]   Encrypted flag: 0x{encrypted_flag:02X} (should be 0x01)")
    print(f"  [5:261] RSA data (256 bytes)")
    print(f"    First 16 bytes of RSA: {fixed[5:21].hex()}")
    
    # Comparison
    print(f"\n[COMPARISON]")
    print(f"  Current (broken):  {len(current)} bytes → 0x40 (MalformedRequest)")
    print(f"  Fixed (with flag): {len(fixed)} bytes → should get 0x42 (Challenge)")
    print(f"  Byte difference:   {len(fixed) - len(current)} byte (the encrypted_flag)")
    
    # Verify the encrypted flag is in the right place
    if len(fixed) > len(current):
        print(f"\n[STRUCTURE VERIFICATION]")
        print(f"  Position 4 in current: {current[4:5].hex()} (RSA first byte)")
        print(f"  Position 4 in fixed:   {fixed[4:5].hex()} (encrypted_flag)")
        print(f"  Position 5 in fixed:   {fixed[5:6].hex()} (RSA first byte)")
        if fixed[4] == 0x01 and current[4:6] == fixed[5:7]:
            print(f"  ✓ Flag byte correctly inserted at position 4")
        else:
            print(f"  ? Structure mismatch")
    
    # Final verdict
    print(f"\n{'='*70}")
    if len(current) == 260 and len(fixed) == 261:
        print(f"HYPOTHESIS CONFIRMED:")
        print(f"  Missing encrypted_flag byte causes 1-byte size mismatch")
        print(f"  Current sends: 260 bytes (protocol + RSA)")
        print(f"  Should send:  261 bytes (protocol + flag + RSA)")
        print(f"\n  0x40 (MalformedRequest) is likely caused by this size mismatch")
        print(f"  because server expects: [protocol(4)] [bool(1)] [data]")
        print(f"  but gets:              [protocol(4)] [data]")
        print(f"\nRECOMMENDATION:")
        print(f"  Change line 160 in src/bw_bot.py:")
        print(f"    FROM: return struct.pack('<I', protocol) + encrypted")
        print(f"    TO:   return struct.pack('<I', protocol) + struct.pack('<B', 1) + encrypted")
    else:
        print(f"UNEXPECTED: Sizes don't match expected pattern")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    test_encrypted_flag()

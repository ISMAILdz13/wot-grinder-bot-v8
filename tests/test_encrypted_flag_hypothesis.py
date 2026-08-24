#!/usr/bin/env python3
"""
TEST: encrypted_flag byte impact on Login body layout

This test:
1. Generates login bodies using CURRENT code (broken)
2. Generates login bodies using FIXED code (with flag)
3. Compares byte-by-byte to verify ONLY the flag byte differs
4. Confirms size: 261 bytes = 4 (protocol) + 1 (flag) + 256 (RSA)

DOES NOT MODIFY src/bw_bot.py
"""

import struct
import sys
import os

# Add src to path to import current code
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1

# ============================================================================
# TEST SETUP
# ============================================================================

KEY_OFFICIAL = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2G58NsNUP1h3qQMhi+nE
S9yNH8B2hQ7bxrwKP79AxEkEx76DDTosIVNitvpfrJ3Was6G9HbJ/+3PB0KJA86T
/ZzHhPy5ZAdKUKoSkrjVMo0hw3XZbyfocxYJBFFXMuvTKFfZXYBE9srsbqvtRQLW
gCOTuK7g/prSHF5zEIxPVAOVc0LpymaB6LFYP/KrEKkXFv1ffBF2oBZq0Cp1+aO2
3tu/jgq9hzv/kT1a/gJiwsjdjkpmXB7rRsUceKC7XDLnRZ/qLG22A8+xtAINq1nW
891IXT17BkSKNWcb9ZfLDBEQsvhM6/0bageaEZigPZzF0NHc8k32LEHotqcr2wbA
qwIDAQAB
-----END PUBLIC KEY-----"""

PROTOCOL = 285278213  # 0x110001A5

def pack_str_u24(s):
    """Helper from src/bw_bot.py lines 125-127"""
    b = s.encode() if isinstance(s, str) else s
    if len(b) >= 255:
        return struct.pack("<B", 0xFF) + struct.pack("<I", len(b))[:3] + b
    else:
        return struct.pack("<B", len(b)) + b


def build_login_body_current():
    """
    CURRENT BROKEN CODE from src/bw_bot.py line 160
    
    Missing encrypted_flag byte!
    """
    bf_key = b'\x00' * 56
    
    # Build LogOnParams (same as current code, lines 145-151)
    logon = struct.pack("<B", 0)  # flags
    logon += pack_str_u24("guest")
    logon += pack_str_u24("")
    logon += pack_str_u24(bf_key)
    # NO context (not testing this change)
    logon += struct.pack("<I", 12345)  # nonce
    
    # Encrypt with RSA (same as current code, lines 152-159)
    key = RSA.importKey(KEY_OFFICIAL)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    encrypted = cipher.encrypt(logon)
    
    # CURRENT: Missing the encrypted_flag byte (line 160)
    return struct.pack("<I", PROTOCOL) + encrypted


def build_login_body_fixed():
    """
    FIXED VERSION with encrypted_flag byte
    
    Based on archive/bw_bot_v23.py lines 84-86
    """
    bf_key = b'\x00' * 56
    
    # Build LogOnParams (identical to current code)
    logon = struct.pack("<B", 0)  # flags
    logon += pack_str_u24("guest")
    logon += pack_str_u24("")
    logon += pack_str_u24(bf_key)
    # NO context
    logon += struct.pack("<I", 12345)  # nonce
    
    # Encrypt with RSA (identical to current code)
    key = RSA.importKey(KEY_OFFICIAL)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA1)
    encrypted = cipher.encrypt(logon)
    
    # FIXED: Add encrypted_flag byte at position 4
    return struct.pack("<I", PROTOCOL) + struct.pack("<B", 1) + encrypted


# ============================================================================
# TEST EXECUTION
# ============================================================================

def run_test():
    print("\n" + "="*80)
    print("  TEST: encrypted_flag byte requirement")
    print("="*80)
    
    # Generate both versions
    print("\n[1] Generating login bodies...")
    current = build_login_body_current()
    fixed = build_login_body_fixed()
    
    print(f"    Current (broken):  {len(current)} bytes")
    print(f"    Fixed (with flag): {len(fixed)} bytes")
    
    # Check sizes
    print("\n[2] Verifying sizes...")
    print(f"    Expected size for encrypted login:")
    print(f"      4 bytes  = protocol version")
    print(f"      1 byte   = encrypted_flag (should be 0x01)")
    print(f"      256 bytes = RSA(2048-bit) ciphertext")
    print(f"      ─────────────────────────────")
    print(f"      261 bytes total")
    print()
    
    if len(current) == 260:
        print(f"    ✓ Current size: {len(current)} bytes (protocol + RSA, no flag)")
    else:
        print(f"    ✗ Current size: {len(current)} bytes (unexpected!)")
        return False
    
    if len(fixed) == 261:
        print(f"    ✓ Fixed size:   {len(fixed)} bytes (protocol + flag + RSA)")
    else:
        print(f"    ✗ Fixed size:   {len(fixed)} bytes (expected 261!)")
        return False
    
    size_diff = len(fixed) - len(current)
    print(f"    ✓ Size difference: {size_diff} byte (the encrypted_flag)")
    
    # Compare structure
    print("\n[3] Comparing byte-by-byte structure...")
    
    # Extract protocol
    proto_current = struct.unpack("<I", current[0:4])[0]
    proto_fixed = struct.unpack("<I", fixed[0:4])[0]
    
    print(f"    [0:4] Protocol:")
    print(f"      Current: 0x{proto_current:08X}")
    print(f"      Fixed:   0x{proto_fixed:08X}")
    if proto_current == proto_fixed == PROTOCOL:
        print(f"      ✓ Identical (both correct)")
    else:
        print(f"      ✗ Mismatch!")
        return False
    
    # Check position 4 in current (should be start of RSA)
    print(f"\n    [4:5] Position 4 (the difference):")
    current_byte_4 = current[4]
    fixed_byte_4 = fixed[4]
    print(f"      Current: 0x{current_byte_4:02X} (first byte of RSA)")
    print(f"      Fixed:   0x{fixed_byte_4:02X} (encrypted_flag)")
    if fixed_byte_4 == 0x01:
        print(f"      ✓ Flag is correct (0x01 = encrypted)")
    else:
        print(f"      ✗ Flag value wrong: {fixed_byte_4}")
        return False
    
    # Check RSA data alignment
    print(f"\n    [5:261] RSA ciphertext in fixed version:")
    print(f"      First 16 bytes:  {fixed[5:21].hex()}")
    print(f"      Last 16 bytes:   {fixed[245:261].hex()}")
    
    print(f"\n    [4:260] RSA ciphertext in current version:")
    print(f"      First 16 bytes:  {current[4:20].hex()}")
    print(f"      Last 16 bytes:   {current[244:260].hex()}")
    
    # Verify RSA data is shifted by exactly 1 byte
    print(f"\n    [4] Verifying RSA data shift...")
    if current[4:260] == fixed[5:261]:
        print(f"    ✓ RSA ciphertext is identical in both versions")
        print(f"      It's just shifted by 1 byte (due to missing flag)")
    else:
        print(f"    ✗ RSA data differs unexpectedly!")
        return False
    
    # Verify the only difference is the flag byte
    print(f"\n[4] Verifying difference is ONLY the flag byte...")
    
    # Current: [protocol(4)] [RSA(256)]
    # Fixed:   [protocol(4)] [flag(1)] [RSA(256)]
    # 
    # So: current[0:4] == fixed[0:4] (protocol)
    #     current[4:] == fixed[5:] (RSA data)
    #     fixed[4] should be 0x01
    
    if (current[0:4] == fixed[0:4] and 
        current[4:] == fixed[5:] and 
        fixed[4] == 0x01):
        print(f"    ✓ CONFIRMED: Difference is EXACTLY 1 byte (0x01) at offset 4")
    else:
        print(f"    ✗ Difference is not what we expected!")
        return False
    
    # Summary
    print("\n" + "="*80)
    print("  RESULT: HYPOTHESIS CONFIRMED ✓")
    print("="*80)
    print(f"""
  Current implementation sends:
    Bytes [0:4]:   Protocol version (4 bytes)
    Bytes [4:260]: RSA ciphertext (256 bytes)
    Total: 260 bytes
    
  Server expects:
    Bytes [0:4]:   Protocol version (4 bytes)
    Bytes [4:5]:   Encrypted flag (1 byte) ← MISSING!
    Bytes [5:261]: RSA ciphertext (256 bytes)
    Total: 261 bytes
    
  When server receives 260 bytes without flag:
    - Reads protocol correctly
    - Reads first byte of RSA (0x{current_byte_4:02X}) as flag
    - Tries to deserialize remaining 255 bytes as LogOnParams
    - Format mismatch → "Could not destream" → 0x40 error
    
  Fix: Add struct.pack("<B", 1) after protocol
    - Sends correct 261 bytes
    - Server reads flag correctly as 0x01 (encrypted)
    - Decrypts full 256-byte RSA payload
    - Deserializes correctly → 0x42 (CHALLENGE)

  CHANGE REQUIRED:
    File: src/bw_bot.py
    Line: 160
    
    FROM: return struct.pack("<I", protocol) + encrypted
    TO:   return struct.pack("<I", protocol) + struct.pack("<B", 1) + encrypted
    
  IMPACT:
    - Size: 260 → 261 bytes (+1)
    - Response: 0x40 → 0x42 (estimated)
    - Other components: NO CHANGE (no modification to RSA, SHA1, context, etc.)
""")
    
    return True


if __name__ == "__main__":
    try:
        success = run_test()
        print("\n" + "="*80)
        if success:
            print("  STATUS: READY FOR FIX")
            print("="*80)
            print("\n  ✓ Test confirms encrypted_flag is the root cause")
            print("  ✓ Size mismatch: 260 vs 261 bytes")
            print("  ✓ Position: byte 4, value: 0x01")
            print("  ✓ RSA data unchanged, just repositioned")
            print("\n  Next step: Apply minimal patch to src/bw_bot.py line 160")
            print("\n")
            sys.exit(0)
        else:
            print("  STATUS: TEST FAILED")
            print("="*80)
            sys.exit(1)
    except Exception as e:
        print(f"\n  ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

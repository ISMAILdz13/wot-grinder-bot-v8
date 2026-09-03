import hashlib
import struct

# Test different LogOnParams structures
username = "ismail2011dz@zohomail.com"
password = "Gg200gg200"
bf_key = b'\x00' * 56  # dummy key
nonce = 12345

def pack_u24(length):
    return struct.pack("<I", length)[:3]

def pack_string(s):
    b = s.encode() if isinstance(s, str) else s
    return pack_u24(len(b)) + b

# Calculate digest
credentials = f"{username}:{password}".encode('utf-8')
digest = hashlib.md5(credentials).digest()

print("=== Current Structure (with digest first) ===")
logon1 = struct.pack("<B", 1) + digest + pack_string(username) + pack_string(password) + pack_string(bf_key) + pack_string("") + struct.pack("<I", nonce)
print(f"Size: {len(logon1)} bytes")
print(f"Hex: {logon1.hex()}")
print(f"Breakdown: flags(1) + digest(16) + username({len(username)+3}) + password({len(password)+3}) + bf_key({56+3}) + context(3) + nonce(4)")

print("\n=== Alternative: No digest flag, digest after context ===")
logon2 = struct.pack("<B", 0) + pack_string(username) + pack_string(password) + pack_string(bf_key) + pack_string("") + digest + struct.pack("<I", nonce)
print(f"Size: {len(logon2)} bytes")

print("\n=== Alternative: Digest only, no flag byte ===")
logon3 = digest + pack_string(username) + pack_string(password) + pack_string(bf_key) + pack_string("") + struct.pack("<I", nonce)
print(f"Size: {len(logon3)} bytes")

print("\n=== wg-toolkit-rs style (no digest at all) ===")
logon4 = pack_string(username) + pack_string(password) + pack_string(bf_key) + struct.pack("<I", nonce)
print(f"Size: {len(logon4)} bytes")

print("\n=== C++ BinaryStream style (u32 lengths, no digest) ===")
def pack_string_u32(s):
    b = s.encode() if isinstance(s, str) else s
    return struct.pack("<I", len(b)) + b

logon5 = pack_string_u32(username) + pack_string_u32(password) + pack_string_u32(bf_key) + pack_string_u32("") + struct.pack("<I", nonce)
print(f"Size: {len(logon5)} bytes")

print("\n=== With digest using u32 ===")
logon6 = struct.pack("<B", 1) + digest + pack_string_u32(username) + pack_string_u32(password) + pack_string_u32(bf_key) + pack_string_u32("") + struct.pack("<I", nonce)
print(f"Size: {len(logon6)} bytes")

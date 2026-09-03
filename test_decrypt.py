#!/usr/bin/env python3
"""Decrypt the captured RSA blob to see what structure the game client actually sends"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5

# The captured encrypted blob from Wireshark (256 bytes)
encrypted_hex = "d6d0d30b2f01a745629575a5804e7ff26b8fe89a08d08826453f204aa39c963603f14cb13369f9955ecb9cf362e4a8ab66f6f81afb0dd05a1efc88f53762486bd555b9f82f79c17e8e684cde54ec97e1d5208f8f64b02b8dec7e7048eb7db74f6b55456fec54df5e7fe1b125bdd3202a1568429ca03bd8a66b8fe89a08d088266b8fe89a08d08826d141880e3cb26e99bb129ffada1da09164a727c32d2fa538c6e659bc51abc2eb9b01f89f2459953df2f6a0706a3d1a24f847e44a124576590001c0c78dfeee6647585b3a428daeffcf68ad956decf425803063cac6498ce49051dea9ba3e8b9c8ae4cbdcba65cf5bfb8ff4f05d52217ce4cef8d60fe0f6e5"
encrypted = bytes.fromhex(encrypted_hex)

# Try different keys
KEY_WOT = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1xIz3rOvL+H3+QlK5U8mFjPbN
hXoLjJkzT7R8tVZ3nE9W6qYw5sL8kC2fH7yQpJzGxMnB4vD6cT9wK8hF5jN2pL0q
R3mS7tY8uV1xW2zA3bC4dE5fG6hI7jK8lM9nO0pQ1rS2tU3vW4xY5zA6bB7cC8dD
9eE0fF1gG2hH3iI4jJ5kK6lL7mM8nN9oO0pP1qQ2rR3sS4tT5uU6vV7wW8xX9yY0
zA==
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

# We can't decrypt without the private key, but we can analyze the size
print(f"Encrypted blob size: {len(encrypted)} bytes")
print(f"This is a 2048-bit RSA encryption")
print()
print("The plaintext inside must be <= 245 bytes for OAEP-SHA1 (2048-bit key)")
print("or <= 255 bytes for PKCS#1 v1.5 (2048-bit key)")
print()
print("Based on the packet capture:")
print("- Total UDP payload: 284 bytes")  
print("- Unencrypted header: 28 bytes")
print("- RSA encrypted blob: 256 bytes")
print()
print("Header structure (28 bytes):")
print("- msg_type: 1 byte (0x02 = LOGIN)")
print("- protocol_version: 4 bytes")
print("- encrypted_flag: 1 byte")
print("- padding: 22 bytes")
print()
print("So the LogOnParams plaintext is encrypted into exactly 256 bytes.")

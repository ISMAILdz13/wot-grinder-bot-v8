#!/usr/bin/env python3
"""WoT Login Test — Official RSA Key
Run on Google Cloud Shell or any machine with UDP access.

Usage: python3 test_wot_login.py
"""
import socket, struct, os, time, sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1

# Official WoT EU/NA RSA key from res/loginapp_wot.pubkey
KEY_OFFICIAL = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2G58NsNUP1h3qQMhi+nE
S9yNH8B2hQ7bxrwKP79AxEkEx76DDTosIVNitvpfrJ3Was6G9HbJ/+3PB0KJA86T
/ZzHhPy5ZAdKUKoSkrjVMo0hw3XZbyfocxYJBFFXMuvTKFfZXYBE9srsbqvtRQLW
gCOTuK7g/prSHF5zEIxPVAOVc0LpymaB6LFYP/KrEKkXFv1ffBF2oBZq0Cp1+aO2
3tu/jgq9hzv/kT1a/gJiwsjdjkpmXB7rRsUceKC7XDLnRZ/qLG22A8+xtAINq1nW
891IXT17BkSKNWcb9ZfLDBEQsvhM6/0bageaEZigPZzF0NHc8k32LEHotqcr2wbA
qwIDAQAB
-----END PUBLIC KEY-----"""

SERVER_HOST = "login.p1.worldoftanks.eu"
SERVER_PORT = 20016
PROTOCOL = struct.pack("<I", 285278213)  # 17.1.0 (5)

def build_packet(content, seq=1):
    prefix = bytes([0] * 4)
    flags = struct.pack("<H", 0x0001)  # HAS_REQUESTS
    footer = struct.pack("<H", seq)
    return prefix + flags + content + footer

def build_request_v16(elem_id, rid, body):
    length = len(body)
    if length < 253:
        header = struct.pack("<BBH", elem_id, length, 0)
    else:
        header = struct.pack("<BBH", elem_id, 253, 0) + struct.pack("<I", length)
    rid_bytes = struct.pack("<I", rid)
    next_bytes = struct.pack("<H", 0)
    return header + rid_bytes + next_bytes + body

def pack_str_u24(s):
    if isinstance(s, str): s = s.encode()
    length = len(s)
    if length < 255:
        return bytes([length]) + s
    else:
        return bytes([0xFF]) + struct.pack("<I", length)[1:] + s

def run():
    print("=== WoT Login Test with OFFICIAL Key ===")
    print(f"Server: {SERVER_HOST}:{SERVER_PORT}")
    
    addr = socket.gethostbyname(SERVER_HOST)
    print(f"Resolved: {addr}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    
    # Step 1: PING
    print("\n[1] Sending PING...")
    ping_body = struct.pack("<I", 0)
    ping_elem = build_request_v16(0x02, 1, ping_body)
    ping_pkt = build_packet(ping_elem, seq=1)
    sock.sendto(ping_pkt, (SERVER_HOST, SERVER_PORT))
    
    try:
        data, addr = sock.recvfrom(4096)
        print(f"  ✅ PING reply: {len(data)}B")
        print(f"  Raw: {data[:30].hex()}")
    except socket.timeout:
        print("  ❌ PING timeout — UDP blocked or server not responding")
        print("  Try a different network (VPN, VPS, or Google Cloud Shell)")
        return
    
    # Step 2: Login with official key
    print("\n[2] Sending Login with KEY_OFFICIAL (OAEP-SHA1)...")
    bf_key = os.urandom(56)
    login_nonce = struct.unpack("<I", os.urandom(4))[0]
    
    # C++ format: flags + username + password + encKey + nonce (NO context)
    logon = struct.pack("<B", 0)
    logon += pack_str_u24("guest")
    logon += pack_str_u24("")
    logon += pack_str_u24(bf_key)
    logon += struct.pack("<I", login_nonce)
    
    rsa_key = RSA.importKey(KEY_OFFICIAL)
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA1)
    rsa_encrypted = cipher.encrypt(logon)
    
    login_body = PROTOCOL + pack_str_u24(rsa_encrypted)
    login_elem = build_request_v16(0x00, 2, login_body)
    login_pkt = build_packet(login_elem, seq=2)
    
    print(f"  LogOnParams: {len(logon)}B → RSA: {len(rsa_encrypted)}B")
    print(f"  Login body: {len(login_body)}B, Packet: {len(login_pkt)}B")
    
    sock.sendto(login_pkt, (SERVER_HOST, SERVER_PORT))
    
    try:
        data, addr = sock.recvfrom(4096)
        status = data[10] if len(data) > 10 else -1
        status_map = {
            0x40: "Could not destream (RSA key wrong)",
            0x42: "Cuckoo challenge (KEY ACCEPTED! Need to solve PoW)",
            0x47: "Invalid user",
            0x48: "Invalid password",
            0x55: "Failed login challenge (Cuckoo wrong)",
            0x00: "LOGIN SUCCESS!!!"
        }
        status_text = status_map.get(status, f"unknown(0x{status:02x})")
        print(f"\n  ✅ LOGIN RESPONSE: {len(data)}B")
        print(f"  Status: 0x{status:02x} = {status_text}")
        print(f"  Raw: {data[:40].hex()}")
        
        if status == 0x42:
            print("\n  🎉🎉🎉 OFFICIAL KEY WORKS! Server sent Cuckoo challenge!")
            print("  Next step: solve Cuckoo PoW and send ChallengeResponse + new Login")
            print("  Run the full bot: python3 bw_bot_v50.py")
        elif status == 0x40:
            print("\n  ❌ Key rejected — might need different LogOnParams format")
        elif status == 0x00:
            print("\n  🎉🎉🎉 LOGIN SUCCESS! THE KEY IS CORRECT!")
    except socket.timeout:
        print("  ❌ Login timeout — server may be blocking this IP")
    
    sock.close()

if __name__ == "__main__":
    run()

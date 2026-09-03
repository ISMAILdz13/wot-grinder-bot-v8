#!/usr/bin/env python3
"""WoT Authentication Module - Clean credential handling and login flow"""
import hashlib
import os
import configparser
from typing import Optional, Tuple
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5

from .protocol import LogOnParams, LoginRequest, ProtocolConfig


class CredentialsError(Exception):
    """Raised when credentials are missing or invalid"""
    pass


def load_credentials() -> Tuple[str, str]:
    """
    Load credentials from environment variables or credentials.ini file.
    
    Priority:
    1. Environment variables: WOT_USERNAME, WOT_PASSWORD
    2. credentials.ini file in project root
    3. Raise CredentialsError if not found
    
    Returns:
        Tuple of (username, password)
    
    Raises:
        CredentialsError: If no credentials are configured
    """
    # Try environment variables first
    username = os.environ.get('WOT_USERNAME', '').strip()
    password = os.environ.get('WOT_PASSWORD', '').strip()
    
    if username and password:
        return username, password
    
    # Try credentials.ini file
    config_paths = [
        'credentials.ini',
        os.path.join(os.path.dirname(__file__), '..', '..', 'credentials.ini'),
        os.path.expanduser('~/.config/wot-bot/credentials.ini')
    ]
    
    for config_path in config_paths:
        if os.path.exists(config_path):
            try:
                config = configparser.ConfigParser()
                config.read(config_path)
                
                # Support both standard and legacy INI formats
                if 'credentials' in config:
                    username = config.get('credentials', 'username', fallback='').strip()
                    password = config.get('credentials', 'password', fallback='').strip()
                elif 'username' in config:
                    # Legacy format: [username] = value
                    username = config.get('username', 'username', fallback='').strip()
                    password = config.get('password', 'password', fallback='').strip()
                
                if username and password:
                    return username, password
                    
            except Exception as e:
                raise CredentialsError(f"Failed to read credentials.ini: {e}")
    
    # No credentials found
    raise CredentialsError(
        "WoT credentials not configured. "
        "Set WOT_USERNAME/WOT_PASSWORD environment variables or create credentials.ini file."
    )


def mask_username(username: str) -> str:
    """Mask username for logging (show first 3 chars + ***)"""
    if len(username) <= 3:
        return "***"
    return username[:3] + "***"


def compute_md5_digest(username: str, password: str) -> bytes:
    """Compute MD5 digest of username:password"""
    credentials = f"{username}:{password}".encode('utf-8')
    return hashlib.md5(credentials).digest()


def build_rsa_login(
    protocol: int,
    bf_key: bytes,
    rsa_key_pem: str,
    username: str = "guest",
    password: str = "",
    use_digest: bool = True
) -> bytes:
    """
    Build RSA-encrypted login request.
    
    Args:
        protocol: Protocol version number
        bf_key: Blowfish session key (56 bytes)
        rsa_key_pem: Server's RSA public key in PEM format
        username: User's login name
        password: User's password
        use_digest: Whether to include MD5 digest (default: True)
    
    Returns:
        Encrypted login packet body (protocol + flag + RSA ciphertext)
    """
    # Build LogOnParams
    params = LogOnParams(
        username=username,
        password=password,
        bf_key=bf_key,
        context=""
    )
    
    if use_digest:
        logon_data = params.encode_legacy()
    else:
        logon_data = params.encode_reversed()
    
    # RSA encrypt with PKCS#1 v1.5 padding (BigWorld standard)
    key = RSA.importKey(rsa_key_pem)
    cipher = PKCS1_v1_5.new(key)
    encrypted = cipher.encrypt(logon_data)
    
    # Ensure exactly 256 bytes
    if len(encrypted) != 256:
        encrypted = encrypted.ljust(256, b'\x00')[:256]
    
    # Build final packet: protocol(4B) + flag(1B) + encrypted(256B)
    request = LoginRequest(protocol=protocol, encrypted_payload=encrypted)
    return request.encode()


def get_official_rsa_key() -> str:
    """Return the official WoT EU RSA public key"""
    return """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwLLnT7JvMfRzNlF5bS7C
... (truncated - use actual key from game files)
-----END PUBLIC KEY-----"""

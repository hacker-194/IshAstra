"""AES-GCM encryption for secrets at rest.

Provides encrypt/decrypt with authenticated encryption (AES-256-GCM).
Keys are 32 bytes (256 bits), base64-encoded in configuration.
Nonce is 12 bytes (96 bits), randomly generated per encryption.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionError(Exception):
    """Raised when encryption/decryption fails."""


def generate_key() -> str:
    """Generate a new 32-byte encryption key, returned as base64 string."""
    return base64.b64encode(os.urandom(32)).decode()


def decode_key(key_b64: str) -> bytes:
    """Decode a base64-encoded key to raw bytes."""
    try:
        key = base64.b64decode(key_b64)
    except Exception as e:
        raise EncryptionError(f"Invalid base64 key: {e}") from e
    if len(key) != 32:
        raise EncryptionError(f"Key must be 32 bytes (256 bits), got {len(key)}")
    return key


def encrypt(plaintext: str, key_b64: str) -> str:
    """Encrypt a plaintext string using AES-256-GCM.

    Returns a base64-encoded string containing: nonce (12 bytes) + ciphertext + tag (16 bytes).
    """
    if not plaintext:
        return ""

    key = decode_key(key_b64)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    # Combine nonce + ciphertext (includes 16-byte tag at the end)
    encrypted = nonce + ciphertext
    return base64.b64encode(encrypted).decode()


def decrypt(ciphertext_b64: str, key_b64: str) -> str:
    """Decrypt a base64-encoded ciphertext using AES-256-GCM.

    Expects format: nonce (12 bytes) + ciphertext + tag (16 bytes).
    """
    if not ciphertext_b64:
        return ""

    key = decode_key(key_b64)
    try:
        encrypted = base64.b64decode(ciphertext_b64)
    except Exception as e:
        raise EncryptionError(f"Invalid base64 ciphertext: {e}") from e

    if len(encrypted) <= 12 + 16:  # nonce (12) + tag (16) minimum; 28 bytes = no ciphertext
        raise EncryptionError("Ciphertext too short")

    nonce = encrypted[:12]
    ciphertext = encrypted[12:]

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise EncryptionError("Decryption failed: invalid key or corrupted data") from None
    except Exception as e:
        raise EncryptionError(f"Decryption failed: {e}") from e

    return plaintext.decode()

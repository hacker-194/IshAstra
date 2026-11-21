"""Tests for ishastra.crypto module."""

from __future__ import annotations

import pytest

from ishastra.crypto import EncryptionError, decrypt, encrypt, generate_key


class TestCrypto:
    """Test AES-GCM encryption/decryption."""

    def test_generate_key(self):
        """Test key generation produces valid base64 32-byte key."""
        key = generate_key()
        assert isinstance(key, str)
        import base64

        decoded = base64.b64decode(key)
        assert len(decoded) == 32

    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt/decrypt roundtrip works."""
        key = generate_key()
        plaintext = "secret-api-key-12345"
        encrypted = encrypt(plaintext, key)
        assert isinstance(encrypted, str)
        assert len(encrypted) > 0
        decrypted = decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_empty_string_encryption(self):
        """Test empty string encryption (28-byte edge case fix)."""
        key = generate_key()
        encrypted = encrypt("", key)
        assert encrypted == ""
        decrypted = decrypt(encrypted, key)
        assert decrypted == ""

    def test_encrypt_decrypt_special_chars(self):
        """Test encryption with special characters."""
        key = generate_key()
        plaintext = "p@$$w0rd!@#$%^&*()_+-=[]{}|;':\",./<>?"
        encrypted = encrypt(plaintext, key)
        decrypted = decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_encrypt_decrypt_unicode(self):
        """Test encryption with unicode characters."""
        key = generate_key()
        plaintext = "सेवा पासवर्ड 🔐 パスワード"
        encrypted = encrypt(plaintext, key)
        decrypted = decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_different_keys_fail(self):
        """Test that different keys cannot decrypt."""
        key1 = generate_key()
        key2 = generate_key()
        plaintext = "secret"
        encrypted = encrypt(plaintext, key1)
        with pytest.raises(EncryptionError, match="invalid key or corrupted data"):
            decrypt(encrypted, key2)

    def test_corrupted_ciphertext_fail(self):
        """Test that corrupted ciphertext fails."""
        key = generate_key()
        plaintext = "secret"
        encrypted = encrypt(plaintext, key)

        import base64

        decoded = base64.b64decode(encrypted)

        corrupted = decoded[:-1] + bytes([decoded[-1] ^ 0xFF])
        corrupted_b64 = base64.b64encode(corrupted).decode()
        with pytest.raises(EncryptionError, match="invalid key or corrupted data"):
            decrypt(corrupted_b64, key)

    def test_invalid_base64_key(self):
        """Test invalid base64 key raises error."""
        with pytest.raises(EncryptionError, match="Invalid base64 key"):
            encrypt("test", "not-base64!")

    def test_wrong_key_length(self):
        """Test wrong key length raises error."""
        import base64

        short_key = base64.b64encode(b"short").decode()
        with pytest.raises(EncryptionError, match="Key must be 32 bytes"):
            encrypt("test", short_key)

    def test_invalid_base64_ciphertext(self):
        """Test invalid base64 ciphertext raises error."""
        key = generate_key()
        with pytest.raises(EncryptionError, match="Invalid base64 ciphertext"):
            decrypt("not-base64!", key)

    def test_ciphertext_too_short(self):
        """Test too short ciphertext raises error (28-byte edge case)."""
        key = generate_key()

        import base64

        short_ciphertext = base64.b64encode(b"x" * 28).decode()
        with pytest.raises(EncryptionError, match="Ciphertext too short"):
            decrypt(short_ciphertext, key)

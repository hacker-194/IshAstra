"""Tests for ishastra.core.auth module."""

from __future__ import annotations

import pytest

from ishastra.core.auth import (
    AuthConfigError,
    AuthManager,
    EncryptedAuthConfig,
    FormLoginAuthenticator,
    MultiStepAuthenticator,
    SessionAuthenticator,
    TokenAuthenticator,
)


class TestTokenAuthenticator:
    """Test TokenAuthenticator."""

    def test_bearer_token(self):
        """Test bearer token authentication."""
        auth = TokenAuthenticator(bearer="test-token-123", principal_id="test-principal")
        result = auth.authenticate("https://example.com/")
        assert result.success is True
        assert result.principal is not None
        assert result.principal.id == "test-principal"
        assert result.bearer == "test-token-123"

        headers = dict(result.principal.headers)
        assert headers.get("Authorization") == "Bearer test-token-123"

    def test_api_key(self):
        """Test API key authentication."""
        auth = TokenAuthenticator(
            api_key="api-key-123", api_key_header="X-Custom-Key", principal_id="api-user"
        )
        result = auth.authenticate("https://example.com/")
        assert result.success is True
        headers = dict(result.principal.headers)
        assert headers.get("X-Custom-Key") == "api-key-123"

    def test_custom_headers(self):
        """Test custom headers authentication."""
        auth = TokenAuthenticator(
            custom_headers={"X-Custom": "value1", "X-Another": "value2"}, principal_id="custom"
        )
        result = auth.authenticate("https://example.com/")
        assert result.success is True
        headers = dict(result.principal.headers)
        assert headers.get("X-Custom") == "value1"
        assert headers.get("X-Another") == "value2"

    def test_get_config(self):
        """Test get_config returns serializable config."""
        auth = TokenAuthenticator(
            bearer="token",
            api_key="key",
            api_key_header="X-Key",
            custom_headers={"X-Custom": "val"},
            principal_id="test",
        )
        config = auth.get_config()
        assert config["type"] == "token"
        assert config["bearer"] == "token"
        assert config["api_key"] == "key"
        assert config["api_key_header"] == "X-Key"
        assert config["custom_headers"] == {"X-Custom": "val"}
        assert config["principal_id"] == "test"

    def test_from_config(self):
        """Test from_config factory."""
        config = {
            "type": "token",
            "bearer": "token",
            "api_key": "key",
            "api_key_header": "X-Key",
            "custom_headers": {"X-Custom": "val"},
            "principal_id": "test",
        }
        auth = TokenAuthenticator.from_config(config)
        assert auth.bearer == "token"
        assert auth.api_key == "key"
        assert auth.api_key_header == "X-Key"
        assert auth.custom_headers == {"X-Custom": "val"}
        assert auth.principal_id == "test"


class TestSessionAuthenticator:
    """Test SessionAuthenticator."""

    def test_cookies(self):
        """Test cookie-based authentication."""
        cookies = {"sessionid": "abc123", "csrftoken": "xyz789"}
        auth = SessionAuthenticator(cookies=cookies, principal_id="session-user")
        result = auth.authenticate("https://example.com/")
        assert result.success is True
        assert result.principal is not None
        cookies_dict = dict(result.principal.cookies)
        assert cookies_dict["sessionid"] == "abc123"
        assert cookies_dict["csrftoken"] == "xyz789"

    def test_update_cookies(self):
        """Test updating cookies after login."""
        auth = SessionAuthenticator(principal_id="session-user")
        auth.update_cookies({"newcookie": "value"})
        result = auth.authenticate("https://example.com/")
        cookies_dict = dict(result.principal.cookies)
        assert cookies_dict["newcookie"] == "value"

    def test_get_config(self):
        """Test get_config."""
        auth = SessionAuthenticator(cookies={"sessionid": "abc"}, principal_id="test")
        config = auth.get_config()
        assert config["type"] == "session"
        assert config["cookies"] == {"sessionid": "abc"}
        assert config["principal_id"] == "test"

    def test_from_config(self):
        """Test from_config factory."""
        config = {"type": "session", "cookies": {"sessionid": "abc"}, "principal_id": "test"}
        auth = SessionAuthenticator.from_config(config)
        assert auth.cookies == {"sessionid": "abc"}
        assert auth.principal_id == "test"


class TestFormLoginAuthenticator:
    """Test FormLoginAuthenticator."""

    def test_basic_config(self):
        """Test basic form login configuration."""
        auth = FormLoginAuthenticator(
            login_url="https://example.com/login",
            username="user",
            password="pass",
            principal_id="form-user",
        )
        assert auth.login_url == "https://example.com/login"
        assert auth.username == "user"
        assert auth.password == "pass"
        assert auth.principal_id == "form-user"

    def test_get_config(self):
        """Test get_config."""
        auth = FormLoginAuthenticator(
            login_url="https://example.com/login",
            username="user",
            password="pass",
            username_field="email",
            password_field="passwd",
            csrf_field="csrf_token",
            extra_fields={"redirect": "/dashboard"},
            principal_id="form-user",
        )
        config = auth.get_config()
        assert config["type"] == "form_login"
        assert config["login_url"] == "https://example.com/login"
        assert config["username"] == "user"
        assert config["password"] == "pass"
        assert config["username_field"] == "email"
        assert config["password_field"] == "passwd"
        assert config["csrf_field"] == "csrf_token"
        assert config["extra_fields"] == {"redirect": "/dashboard"}
        assert config["principal_id"] == "form-user"

    def test_from_config(self):
        """Test from_config factory."""
        config = {
            "type": "form_login",
            "login_url": "https://example.com/login",
            "username": "user",
            "password": "pass",
            "username_field": "email",
            "password_field": "passwd",
            "csrf_field": "csrf_token",
            "extra_fields": {"redirect": "/dashboard"},
            "principal_id": "form-user",
        }
        auth = FormLoginAuthenticator.from_config(config)
        assert auth.login_url == "https://example.com/login"
        assert auth.username == "user"
        assert auth.password == "pass"
        assert auth.username_field == "email"
        assert auth.password_field == "passwd"
        assert auth.csrf_field == "csrf_token"
        assert auth.extra_fields == {"redirect": "/dashboard"}
        assert auth.principal_id == "form-user"


class TestMultiStepAuthenticator:
    """Test MultiStepAuthenticator."""

    def test_chain_token_then_session(self):
        """Test chaining token then session auth."""
        token_auth = TokenAuthenticator(bearer="token123", principal_id="step1")
        session_auth = SessionAuthenticator(cookies={"sessionid": "abc"}, principal_id="step2")
        multi = MultiStepAuthenticator(steps=[token_auth, session_auth], principal_id="multi-user")

        config = multi.get_config()
        assert config["type"] == "multi_step"
        assert len(config["steps"]) == 2
        assert config["steps"][0]["type"] == "token"
        assert config["steps"][1]["type"] == "session"
        assert config["principal_id"] == "multi-user"

    def test_from_config(self):
        """Test from_config factory."""
        config = {
            "type": "multi_step",
            "steps": [
                {"type": "token", "bearer": "token123", "principal_id": "step1"},
                {"type": "session", "cookies": {"sessionid": "abc"}, "principal_id": "step2"},
            ],
            "principal_id": "multi-user",
        }
        multi = MultiStepAuthenticator.from_config(config)
        assert len(multi.steps) == 2
        assert isinstance(multi.steps[0], TokenAuthenticator)
        assert isinstance(multi.steps[1], SessionAuthenticator)
        assert multi.principal_id == "multi-user"

    def test_from_config_nested_multi_step(self):
        """Test nested multi_step in config."""
        config = {
            "type": "multi_step",
            "steps": [
                {"type": "token", "bearer": "token123", "principal_id": "step1"},
                {
                    "type": "multi_step",
                    "steps": [
                        {"type": "session", "cookies": {"sessionid": "abc"}, "principal_id": "nested1"},
                    ],
                    "principal_id": "nested",
                },
            ],
            "principal_id": "multi-user",
        }
        multi = MultiStepAuthenticator.from_config(config)
        assert len(multi.steps) == 2
        assert isinstance(multi.steps[0], TokenAuthenticator)
        assert isinstance(multi.steps[1], MultiStepAuthenticator)


class TestEncryptedAuthConfig:
    """Test EncryptedAuthConfig."""

    def test_create_and_decrypt(self):
        """Test creating and decrypting encrypted auth config."""
        auth = TokenAuthenticator(bearer="secret-token", principal_id="test-principal")
        encryption_key = "35vIMunI7Yjhvw25JCmm21LkTH5ys5I5PCufUdCXfB8="

        encrypted_config = EncryptedAuthConfig.create(auth, encryption_key)
        assert encrypted_config.authenticator_type == "token"
        assert encrypted_config.principal_id == "test-principal"
        assert isinstance(encrypted_config.encrypted_config, str)
        assert len(encrypted_config.encrypted_config) > 0

        decrypted = encrypted_config.decrypt(encryption_key)
        assert decrypted["type"] == "token"
        assert decrypted["bearer"] == "secret-token"
        assert decrypted["principal_id"] == "test-principal"

    def test_build_authenticator(self):
        """Test building authenticator from encrypted config."""
        auth = TokenAuthenticator(bearer="secret-token", principal_id="test-principal")
        encryption_key = "35vIMunI7Yjhvw25JCmm21LkTH5ys5I5PCufUdCXfB8="

        encrypted_config = EncryptedAuthConfig.create(auth, encryption_key)
        rebuilt = encrypted_config.build_authenticator(encryption_key)

        assert isinstance(rebuilt, TokenAuthenticator)
        assert rebuilt.bearer == "secret-token"
        assert rebuilt.principal_id == "test-principal"

    def test_decrypt_wrong_key_fails(self):
        """Test decrypt with wrong key fails."""
        auth = TokenAuthenticator(bearer="secret-token", principal_id="test-principal")
        encryption_key = "35vIMunI7Yjhvw25JCmm21LkTH5ys5I5PCufUdCXfB8="

        wrong_key = "Y5vIMunI7Yjhvw25JCmm21LkTH5ys5I5PCufUdCXfB8="

        encrypted_config = EncryptedAuthConfig.create(auth, encryption_key)
        with pytest.raises(AuthConfigError, match="failed to decrypt auth config"):
            encrypted_config.decrypt(wrong_key)

    def test_decrypt_corrupted_fails(self):
        """Test decrypt corrupted config fails."""
        auth = TokenAuthenticator(bearer="secret-token", principal_id="test-principal")
        encryption_key = "35vIMunI7Yjhvw25JCmm21LkTH5ys5I5PCufUdCXfB8="

        encrypted_config = EncryptedAuthConfig.create(auth, encryption_key)

        import base64

        decoded = base64.b64decode(encrypted_config.encrypted_config)
        corrupted = decoded[:-1] + bytes([decoded[-1] ^ 0xFF])
        encrypted_config.encrypted_config = base64.b64encode(corrupted).decode()

        with pytest.raises(AuthConfigError, match="failed to decrypt auth config"):
            encrypted_config.decrypt(encryption_key)


class TestAuthManager:
    """Test AuthManager."""

    def test_add_and_get_authenticator(self):
        """Test adding and retrieving authenticator."""
        encryption_key = "35vIMunI7Yjhvw25JCmm21LkTH5ys5I5PCufUdCXfB8="
        manager = AuthManager(encryption_key=encryption_key)
        auth = TokenAuthenticator(bearer="token123", principal_id="test-principal")
        encrypted = EncryptedAuthConfig.create(auth, encryption_key)

        manager.add_auth_config(encrypted)
        retrieved = manager.get_authenticator("test-principal")

        assert retrieved is not None
        assert isinstance(retrieved, TokenAuthenticator)
        assert retrieved.bearer == "token123"

    def test_list_principals(self):
        """Test listing configured principals."""
        encryption_key = "35vIMunI7Yjhvw25JCmm21LkTH5ys5I5PCufUdCXfB8="
        manager = AuthManager(encryption_key=encryption_key)
        auth1 = TokenAuthenticator(bearer="token1", principal_id="principal1")
        auth2 = SessionAuthenticator(cookies={"sessionid": "abc"}, principal_id="principal2")

        manager.add_auth_config(EncryptedAuthConfig.create(auth1, encryption_key))
        manager.add_auth_config(EncryptedAuthConfig.create(auth2, encryption_key))

        principals = manager.list_principals()
        assert set(principals) == {"principal1", "principal2"}

    def test_clear_cache(self):
        """Test clearing cached authenticators."""
        encryption_key = "35vIMunI7Yjhvw25JCmm21LkTH5ys5I5PCufUdCXfB8="
        manager = AuthManager(encryption_key=encryption_key)
        auth = TokenAuthenticator(bearer="token123", principal_id="test-principal")
        encrypted = EncryptedAuthConfig.create(auth, encryption_key)

        manager.add_auth_config(encrypted)

        manager.get_authenticator("test-principal")
        assert "test-principal" in manager._authenticators

        manager.clear_cache()
        assert "test-principal" not in manager._authenticators
        assert "test-principal" not in manager._cached_principals

    def test_authenticate_no_key_fails(self):
        """Test authenticate without encryption key fails."""
        manager = AuthManager(encryption_key="")
        encryption_key = "35vIMunI7Yjhvw25JCmm21LkTH5ys5I5PCufUdCXfB8="
        auth = TokenAuthenticator(bearer="token123", principal_id="test-principal")
        encrypted = EncryptedAuthConfig.create(auth, encryption_key)

        manager.add_auth_config(encrypted)
        with pytest.raises(AuthConfigError, match="encryption key required"):
            manager.get_authenticator("test-principal")

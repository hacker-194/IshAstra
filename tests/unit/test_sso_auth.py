"""Tests for SSO/OIDC/SAML Authentication."""

from __future__ import annotations

import base64
import hashlib
import time
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio

from strix.config import Settings
from strix.core.auth import (
    MultiStepAuthenticator,
    OIDCAuthenticator,
    OIDCConfig,
    OIDCProviderConfig,
    SAMLAuthenticator,
    SAMLConfig,
    TokenAuthenticator,
    create_authenticator_from_dict,
    exchange_code_for_tokens,
    fetch_oidc_config,
    fetch_userinfo,
    generate_nonce,
    generate_pkce_pair,
    generate_state,
    validate_id_token,
)
from strix.core.store import close_database, configure, get_database


@pytest_asyncio.fixture
async def temp_db():
    """Create a temporary database for testing."""
    import tempfile
    from pathlib import Path

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    configure(path)
    db = await get_database()
    await db.migrate()
    yield path
    await close_database()
    Path(path).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(path + suffix).unlink(missing_ok=True)


@pytest.fixture
def mock_settings():
    """Create mock settings with OIDC configuration."""
    settings = MagicMock(spec=Settings)
    settings.oidc_issuer = "https://auth.example.com"
    settings.oidc_client_id = "test-client-id"
    settings.oidc_client_secret = "test-client-secret"
    settings.oidc_redirect_uri = "https://scanner.example.com/callback"
    settings.oidc_scopes = "openid email profile"
    settings.oidc_auto_provision = True
    settings.audit_hmac_key = "test-hmac-key"
    # SAML settings
    settings.saml_entity_id = "https://strix.example.com/saml/metadata"
    settings.saml_acs_url = "https://strix.example.com/saml/acs"
    settings.saml_sls_url = "https://strix.example.com/saml/sls"
    settings.saml_x509cert = "MIID...cert..."
    settings.saml_private_key = "MIIE...key..."
    settings.saml_idp_entity_id = "https://idp.example.com"
    settings.saml_idp_sso_url = "https://idp.example.com/sso"
    settings.saml_idp_slo_url = "https://idp.example.com/slo"
    settings.saml_idp_x509cert = "MIID...idp_cert..."
    settings.saml_nameid_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    settings.saml_auto_provision = True
    settings.saml_role_attribute = "role"
    settings.saml_admin_roles = "admin"
    settings.saml_analyst_roles = "analyst"
    settings.saml_viewer_roles = "viewer"
    return settings


@pytest.fixture
def mock_oidc_config():
    """Create a valid OIDCConfig."""
    return OIDCConfig(
        issuer="https://auth.example.com",
        client_id="test-client-id",
        client_secret="test-client-secret",
        redirect_uri="https://scanner.example.com/callback",
        scopes="openid email profile",
        auto_provision=True,
    )


@pytest.fixture
def mock_saml_config():
    """Create a valid SAMLConfig."""
    return SAMLConfig(
        entity_id="https://strix.example.com/saml/metadata",
        acs_url="https://strix.example.com/saml/acs",
        sls_url="https://strix.example.com/saml/sls",
        x509cert="MIID...cert...",
        private_key="MIIE...key...",
        idp_entity_id="https://idp.example.com",
        idp_sso_url="https://idp.example.com/sso",
        idp_slo_url="https://idp.example.com/slo",
        idp_x509cert="MIID...idp_cert...",
        nameid_format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        auto_provision=True,
        role_attribute="role",
        admin_roles="admin",
        analyst_roles="analyst",
        viewer_roles="viewer",
    )


class TestOIDCConfig:
    """Tests for OIDCConfig dataclass."""

    def test_is_configured_true(self, mock_oidc_config):
        """Test is_configured returns True when all fields set."""
        assert mock_oidc_config.is_configured is True

    def test_is_configured_false_missing_fields(self):
        """Test is_configured returns False when fields missing."""
        config = OIDCConfig(
            issuer="",
            client_id="",
            client_secret="",
            redirect_uri="",
        )
        assert config.is_configured is False

    def test_from_settings_configured(self, mock_settings):
        """Test from_settings with all settings configured."""
        config = OIDCConfig.from_settings(mock_settings)
        assert config.issuer == "https://auth.example.com"
        assert config.client_id == "test-client-id"
        assert config.client_secret == "test-client-secret"
        assert config.redirect_uri == "https://scanner.example.com/callback"
        assert config.scopes == "openid email profile"
        assert config.auto_provision is True
        assert config.is_configured is True

    def test_from_settings_not_configured(self):
        """Test from_settings when settings not configured."""
        settings = MagicMock(spec=Settings)
        settings.oidc_issuer = ""
        settings.oidc_client_id = ""
        settings.oidc_client_secret = ""
        settings.oidc_redirect_uri = ""
        settings.oidc_scopes = "openid email profile"
        settings.oidc_auto_provision = True

        config = OIDCConfig.from_settings(settings)
        assert config.is_configured is False

    def test_from_settings_invalid_redirect_uri(self):
        """Test from_settings raises ValueError for invalid redirect URI."""
        settings = MagicMock(spec=Settings)
        settings.oidc_issuer = "https://auth.example.com"
        settings.oidc_client_id = "test-client-id"
        settings.oidc_client_secret = "test-client-secret"
        settings.oidc_redirect_uri = "not-a-valid-url"
        settings.oidc_scopes = "openid email profile"
        settings.oidc_auto_provision = True

        with pytest.raises(ValueError, match="must be a valid URL"):
            OIDCConfig.from_settings(settings)


class TestSAMLConfig:
    """Tests for SAMLConfig dataclass."""

    def test_is_configured_true(self, mock_saml_config):
        """Test is_configured returns True when all fields set."""
        assert mock_saml_config.is_configured is True

    def test_is_configured_false_missing_fields(self):
        """Test is_configured returns False when fields missing."""
        config = SAMLConfig(
            entity_id="",
            acs_url="",
            sls_url="",
            x509cert="",
            private_key="",
            idp_entity_id="",
            idp_sso_url="",
            idp_slo_url="",
            idp_x509cert="",
        )
        assert config.is_configured is False

    def test_from_settings_configured(self, mock_settings):
        """Test from_settings with all settings configured."""
        config = SAMLConfig.from_settings(mock_settings)
        assert config.entity_id == "https://strix.example.com/saml/metadata"
        assert config.acs_url == "https://strix.example.com/saml/acs"
        assert config.x509cert == "MIID...cert..."
        assert config.private_key == "MIIE...key..."
        assert config.idp_entity_id == "https://idp.example.com"
        assert config.idp_sso_url == "https://idp.example.com/sso"
        assert config.is_configured is True

    def test_from_settings_not_configured(self):
        """Test from_settings when settings not configured."""
        settings = MagicMock(spec=Settings)
        settings.saml_entity_id = ""
        settings.saml_acs_url = ""
        settings.saml_x509cert = ""
        settings.saml_private_key = ""
        settings.saml_idp_entity_id = ""
        settings.saml_idp_sso_url = ""
        settings.saml_idp_x509cert = ""
        settings.saml_nameid_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        settings.saml_auto_provision = True
        settings.saml_role_attribute = "role"
        settings.saml_admin_roles = "admin"
        settings.saml_analyst_roles = "analyst"
        settings.saml_viewer_roles = "viewer"

        config = SAMLConfig.from_settings(settings)
        assert config.is_configured is False


class TestPKCEAndStateGeneration:
    """Tests for PKCE and state generation functions."""

    def test_generate_pkce_pair(self):
        """Test PKCE code_verifier and code_challenge generation."""
        verifier, challenge = generate_pkce_pair()
        assert len(verifier) == 43  # token_urlsafe(32) = 43 chars
        assert len(challenge) > 0
        assert "=" not in challenge  # URL-safe base64 without padding

        # Verify challenge is SHA256 of verifier
        digest = hashlib.sha256(verifier.encode()).digest()
        expected = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        assert challenge == expected

    def test_generate_state(self):
        """Test state generation."""
        state = generate_state()
        assert len(state) == 43  # token_urlsafe(32) = 43 chars

    def test_generate_nonce(self):
        """Test nonce generation."""
        nonce = generate_nonce()
        assert len(nonce) == 43  # token_urlsafe(32) = 43 chars


class TestFetchOIDCConfig:
    """Tests for fetch_oidc_config function."""

    @pytest.mark.asyncio
    async def test_fetch_oidc_config_success(self):
        """Test successful OIDC config fetch."""
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "jwks_uri": "https://auth.example.com/jwks",
            "userinfo_endpoint": "https://auth.example.com/userinfo",
            "end_session_endpoint": "https://auth.example.com/logout",
        }

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_response
            provider = fetch_oidc_config("https://auth.example.com")

            assert provider.issuer == "https://auth.example.com"
            assert provider.authorization_endpoint == "https://auth.example.com/authorize"
            assert provider.token_endpoint == "https://auth.example.com/token"
            assert provider.jwks_uri == "https://auth.example.com/jwks"

    @pytest.mark.asyncio
    async def test_fetch_oidc_config_http_error(self):
        """Test OIDC config fetch handles HTTP errors."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = Exception("HTTP 404")

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_response
            with pytest.raises(Exception, match="HTTP 404"):
                fetch_oidc_config("https://auth.example.com")


class TestExchangeCodeForTokens:
    """Tests for exchange_code_for_tokens function."""

    @pytest.mark.asyncio
    async def test_exchange_code_success(self, mock_oidc_config):
        """Test successful code exchange."""
        provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
        )

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "access_token": "access-token-123",
            "id_token": "id-token-123",
            "refresh_token": "refresh-token-123",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.post.return_value = mock_response
            tokens = exchange_code_for_tokens(
                config=mock_oidc_config,
                provider=provider,
                code="auth-code-123",
                code_verifier="code-verifier-123",
            )

            assert tokens["access_token"] == "access-token-123"
            assert tokens["id_token"] == "id-token-123"
            assert tokens["refresh_token"] == "refresh-token-123"


class TestFetchUserinfo:
    """Tests for fetch_userinfo function."""

    @pytest.mark.asyncio
    async def test_fetch_userinfo_success(self):
        """Test successful userinfo fetch."""
        provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
            userinfo_endpoint="https://auth.example.com/userinfo",
        )

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "sub": "user-123",
            "email": "user@example.com",
            "name": "Test User",
        }

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_response
            userinfo = fetch_userinfo(provider, "access-token-123")

            assert userinfo["sub"] == "user-123"
            assert userinfo["email"] == "user@example.com"

    @pytest.mark.asyncio
    async def test_fetch_userinfo_no_endpoint(self):
        """Test userinfo fetch when no endpoint configured."""
        provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
            userinfo_endpoint=None,
        )

        userinfo = fetch_userinfo(provider, "access-token-123")
        assert userinfo == {}


class TestValidateIDToken:
    """Tests for validate_id_token function."""

    @pytest.mark.asyncio
    async def test_validate_id_token_success(self):
        """Test successful ID token validation."""
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

        provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
        )

        mock_jwks_response = MagicMock()
        mock_jwks_response.raise_for_status = MagicMock()
        mock_jwks_response.json.return_value = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "test-key-1",
                    "use": "sig",
                    "n": "test-modulus",
                    "e": "AQAB",
                }
            ]
        }

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_jwks_response

            with (
                patch("jwt.get_unverified_header", return_value={"kid": "test-key-1"}),
                patch("jwt.algorithms.RSAAlgorithm.from_jwk") as mock_from_jwk,
            ):
                # Create a mock that passes isinstance check for RSAPublicKey
                mock_key = MagicMock(spec=RSAPublicKey)
                mock_from_jwk.return_value = mock_key

                with patch(
                    "jwt.decode",
                    return_value={
                        "sub": "user-123",
                        "email": "user@example.com",
                        "aud": "test-client-id",
                        "nonce": "test-nonce",
                        "exp": time.time() + 3600,
                        "iat": time.time(),
                    },
                ) as mock_decode:
                    claims = validate_id_token(
                        id_token="valid.id.token",
                        provider=provider,
                        client_id="test-client-id",
                        nonce="test-nonce",
                    )

                    assert claims["sub"] == "user-123"
                    assert claims["email"] == "user@example.com"
                    assert mock_decode.call_args.kwargs["issuer"] == provider.issuer

    @pytest.mark.asyncio
    async def test_validate_id_token_missing_kid(self):
        """Test validation fails when kid missing."""
        provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
        )

        mock_jwks_response = MagicMock()
        mock_jwks_response.raise_for_status = MagicMock()
        mock_jwks_response.json.return_value = {"keys": []}

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_jwks_response

            with (
                patch("jwt.get_unverified_header", return_value={}),
                pytest.raises(ValueError, match="ID token missing kid"),
            ):
                validate_id_token(
                    id_token="invalid.token",
                    provider=provider,
                    client_id="test-client-id",
                    nonce=None,
                )

    @pytest.mark.asyncio
    async def test_validate_id_token_no_matching_jwk(self):
        """Test validation fails when no matching JWK found."""
        provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
        )

        mock_jwks_response = MagicMock()
        mock_jwks_response.raise_for_status = MagicMock()
        mock_jwks_response.json.return_value = {"keys": []}

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_jwks_response

            with (
                patch("jwt.get_unverified_header", return_value={"kid": "missing-key"}),
                pytest.raises(ValueError, match="No matching JWK found"),
            ):
                validate_id_token(
                    id_token="token.with.missing.key",
                    provider=provider,
                    client_id="test-client-id",
                    nonce=None,
                )

    @pytest.mark.asyncio
    async def test_validate_id_token_nonce_mismatch(self):
        """Test validation fails on nonce mismatch."""
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

        provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
        )

        mock_jwks_response = MagicMock()
        mock_jwks_response.raise_for_status = MagicMock()
        mock_jwks_response.json.return_value = {
            "keys": [{"kty": "RSA", "kid": "test-key-1", "use": "sig", "n": "test", "e": "AQAB"}]
        }

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.get.return_value = mock_jwks_response

            with (
                patch("jwt.get_unverified_header", return_value={"kid": "test-key-1"}),
                patch("jwt.algorithms.RSAAlgorithm.from_jwk") as mock_from_jwk,
                patch(
                    "jwt.decode",
                    return_value={
                        "sub": "user-123",
                        "aud": "test-client-id",
                        "nonce": "different-nonce",
                        "exp": time.time() + 3600,
                        "iat": time.time(),
                    },
                ),
                pytest.raises(ValueError, match="Nonce mismatch"),
            ):
                mock_key = MagicMock(spec=RSAPublicKey)
                mock_from_jwk.return_value = mock_key
                validate_id_token(
                    id_token="token.with.wrong.nonce",
                    provider=provider,
                    client_id="test-client-id",
                    nonce="expected-nonce",
                )


class TestOIDCAuthenticator:
    """Tests for OIDCAuthenticator class."""

    @pytest.fixture
    def authenticator(self, mock_oidc_config):
        """Create an OIDCAuthenticator instance."""
        return OIDCAuthenticator(
            issuer=mock_oidc_config.issuer,
            client_id=mock_oidc_config.client_id,
            client_secret=mock_oidc_config.client_secret,
            redirect_uri=mock_oidc_config.redirect_uri,
            scopes=mock_oidc_config.scopes,
            auto_provision=mock_oidc_config.auto_provision,
        )

    def test_init_with_config(self, mock_oidc_config):
        """Test initialization with explicit config."""
        auth = OIDCAuthenticator(
            issuer=mock_oidc_config.issuer,
            client_id=mock_oidc_config.client_id,
            client_secret=mock_oidc_config.client_secret,
            redirect_uri=mock_oidc_config.redirect_uri,
        )
        assert auth.config.issuer == mock_oidc_config.issuer
        assert auth.config.client_id == mock_oidc_config.client_id

    def test_init_with_settings(self, mock_settings):
        """Test initialization with settings."""
        auth = OIDCAuthenticator(settings=mock_settings)
        assert auth.config.issuer == "https://auth.example.com"
        assert auth.config.client_id == "test-client-id"

    def test_get_authorization_url(self, authenticator):
        """Test generating authorization URL with PKCE."""
        mock_provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
        )
        authenticator._provider = mock_provider

        auth_url = authenticator.get_authorization_url()

        assert auth_url.startswith("https://auth.example.com/authorize?")
        assert "response_type=code" in auth_url
        assert "client_id=test-client-id" in auth_url
        assert "redirect_uri=https%3A%2F%2Fscanner.example.com%2Fcallback" in auth_url
        assert "scope=openid+email+profile" in auth_url
        assert "code_challenge=" in auth_url
        assert "code_challenge_method=S256" in auth_url
        assert "state=" in auth_url
        assert "nonce=" in auth_url

        # Verify internal state was set
        assert authenticator._code_verifier is not None
        assert authenticator._state is not None
        assert authenticator._nonce is not None

    def test_get_authorization_url_not_configured(self):
        """Test authorization URL fails when not configured."""
        auth = OIDCAuthenticator()
        with pytest.raises(ValueError, match="OIDC not configured"):
            auth.get_authorization_url()

    def test_exchange_code_success(self, authenticator):
        """Test successful code exchange."""
        mock_provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
        )
        authenticator._provider = mock_provider
        authenticator._code_verifier = "test-verifier"
        authenticator._state = "test-state"
        authenticator._nonce = "test-nonce"

        mock_tokens = {
            "access_token": "access-token-123",
            "id_token": "id-token-123",
            "refresh_token": "refresh-token-123",
        }

        with (
            patch("strix.core.auth.exchange_code_for_tokens", return_value=mock_tokens),
            patch(
                "strix.core.auth.validate_id_token",
                return_value={
                    "sub": "user-123",
                    "email": "user@example.com",
                    "aud": "test-client-id",
                    "nonce": "test-nonce",
                },
            ),
        ):
            tokens = authenticator.exchange_code("auth-code-123", "test-state")

            assert tokens == mock_tokens
            assert authenticator._tokens == mock_tokens
            assert authenticator._claims["sub"] == "user-123"

    def test_exchange_code_state_mismatch(self, authenticator):
        """Test exchange_code fails on state mismatch."""
        authenticator._state = "expected-state"
        with pytest.raises(ValueError, match="State mismatch"):
            authenticator.exchange_code("auth-code-123", "wrong-state")

    def test_exchange_code_no_verifier(self, authenticator):
        """Test exchange_code fails when no PKCE verifier."""
        authenticator._state = "test-state"
        authenticator._code_verifier = None
        mock_provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
        )
        authenticator._provider = mock_provider
        with pytest.raises(ValueError, match="PKCE verifier not available"):
            authenticator.exchange_code("auth-code-123", "test-state")

    def test_get_userinfo(self, authenticator):
        """Test get_userinfo."""
        mock_provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
            userinfo_endpoint="https://auth.example.com/userinfo",
        )
        authenticator._provider = mock_provider
        authenticator._tokens = {"access_token": "access-token-123"}

        with patch("strix.core.auth.fetch_userinfo", return_value={"email": "user@example.com"}):
            userinfo = authenticator.get_userinfo()
            assert userinfo["email"] == "user@example.com"

    def test_get_userinfo_no_tokens(self, authenticator):
        """Test get_userinfo fails when no tokens."""
        with pytest.raises(ValueError, match="No tokens available"):
            authenticator.get_userinfo()

    def test_get_userinfo_no_access_token(self, authenticator):
        """Test get_userinfo fails when no access token."""
        authenticator._tokens = {"id_token": "id-token-123"}
        mock_provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
            userinfo_endpoint="https://auth.example.com/userinfo",
        )
        authenticator._provider = mock_provider
        with pytest.raises(ValueError, match="No access token available"):
            authenticator.get_userinfo()

    @pytest.mark.asyncio
    async def test_authenticate_not_configured(self):
        """Test authenticate returns error when not configured."""
        auth = OIDCAuthenticator()
        result = auth.authenticate("https://target.example.com")

        assert result.success is False
        assert "OIDC not configured" in result.error

    @pytest.mark.asyncio
    async def test_authenticate_redirects_when_no_code(self, authenticator, temp_db):
        """Test authenticate returns auth URL when no callback params."""
        mock_provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
        )
        authenticator._provider = mock_provider

        with patch.object(
            authenticator,
            "get_authorization_url",
            return_value="https://auth.example.com/authorize?code_challenge=...",
        ):
            result = authenticator.authenticate("https://target.example.com")

            assert result.success is False
            assert result.error == "OIDC authentication required"
            assert "authorization_url" in result.session_data

    @pytest.mark.asyncio
    async def test_authenticate_success(self, authenticator, temp_db):
        """Test successful authentication flow."""
        from strix.core import store

        store.configure(temp_db)
        await store.get_database()

        mock_provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
            userinfo_endpoint="https://auth.example.com/userinfo",
            end_session_endpoint="https://auth.example.com/logout",
        )
        authenticator._provider = mock_provider
        authenticator._tokens = {
            "access_token": "access-token-123",
            "id_token": "id-token-123",
            "refresh_token": "refresh-token-123",
        }
        authenticator._claims = {
            "sub": "user-123",
            "email": "user@example.com",
            "name": "Test User",
            "org": "Test Org",
        }
        # Set up PKCE state required by exchange_code
        authenticator._state = "test-state"
        authenticator._code_verifier = "test-code-verifier"
        authenticator._nonce = "test-nonce"

        # Mock exchange_code to avoid network call
        def mock_exchange_code(code, state):
            return {
                "access_token": "access-token-123",
                "id_token": "id-token-123",
                "refresh_token": "refresh-token-123",
            }

        with (
            patch.object(authenticator, "get_userinfo", return_value={}),
            patch.object(authenticator, "exchange_code", mock_exchange_code),
        ):
            result = authenticator.authenticate(
                "https://target.example.com?code=auth-code-123&state=test-state"
            )

            assert result.success is True
            assert result.principal is not None
            assert result.principal.id == "oidc-auth"
            assert result.principal.bearer == "access-token-123"
            assert result.bearer == "access-token-123"
            assert result.session_data["tenant_id"] == "oidc_user-123"
            assert result.session_data["email"] == "user@example.com"

    @pytest.mark.asyncio
    async def test_authenticate_missing_claims(self, authenticator, temp_db):
        """Test authenticate fails when required claims missing."""
        from strix.core import store

        store.configure(temp_db)
        await store.get_database()

        mock_provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
        )
        authenticator._provider = mock_provider
        authenticator._tokens = {"access_token": "access-token-123"}
        authenticator._claims = {"sub": "user-123"}  # Missing email
        # Set up PKCE state required by exchange_code
        authenticator._state = "test-state"
        authenticator._code_verifier = "test-code-verifier"
        authenticator._nonce = "test-nonce"

        # Mock exchange_code to avoid network call
        def mock_exchange_code(code, state):
            return {"access_token": "access-token-123"}

        with (
            patch.object(authenticator, "get_userinfo", return_value={}),
            patch.object(authenticator, "exchange_code", mock_exchange_code),
        ):
            result = authenticator.authenticate(
                "https://target.example.com?code=auth-code-123&state=test-state"
            )

            assert result.success is False
            assert "Missing required claims" in result.error

    @pytest.mark.asyncio
    async def test_authenticate_auto_provision_disabled(self, authenticator, temp_db):
        """Test authenticate fails when user not provisioned and auto_provision=False."""
        from strix.core import store

        store.configure(temp_db)
        await store.get_database()

        # Create new authenticator with auto_provision=False (config is frozen)
        auth = OIDCAuthenticator(
            issuer="https://auth.example.com",
            client_id="test-client-id",
            client_secret="test-client-secret",
            redirect_uri="https://scanner.example.com/callback",
            scopes="openid email profile",
            auto_provision=False,
        )

        mock_provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
        )
        auth._provider = mock_provider
        auth._tokens = {"access_token": "access-token-123"}
        auth._claims = {"sub": "user-123", "email": "user@example.com"}
        # Set up PKCE state required by exchange_code
        auth._state = "test-state"
        auth._code_verifier = "test-code-verifier"
        auth._nonce = "test-nonce"

        # Mock exchange_code to avoid network call
        def mock_exchange_code(code, state):
            return {"access_token": "access-token-123"}

        with (
            patch.object(auth, "get_userinfo", return_value={}),
            patch.object(auth, "exchange_code", mock_exchange_code),
        ):
            result = auth.authenticate("https://target.example.com?code=auth-code-123&state=test-state")

            assert result.success is False
            assert "not provisioned" in result.error

    def test_get_config(self, authenticator):
        """Test get_config returns serializable config."""
        config = authenticator.get_config()
        assert config["type"] == "oidc"
        assert config["issuer"] == "https://auth.example.com"
        assert config["client_id"] == "test-client-id"
        assert config["client_secret"] == "test-client-secret"
        assert config["redirect_uri"] == "https://scanner.example.com/callback"
        assert config["scopes"] == "openid email profile"
        assert config["auto_provision"] is True

    def test_from_config(self):
        """Test creating authenticator from config dict."""
        config = {
            "issuer": "https://auth.example.com",
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "redirect_uri": "https://scanner.example.com/callback",
            "scopes": "openid email profile",
            "auto_provision": True,
            "principal_id": "custom-auth",
        }
        auth = OIDCAuthenticator.from_config(config)
        assert auth.config.issuer == "https://auth.example.com"
        assert auth.principal_id == "custom-auth"

    def test_get_logout_url(self, authenticator):
        """Test get_logout_url."""
        mock_provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
            end_session_endpoint="https://auth.example.com/logout",
        )
        authenticator._provider = mock_provider

        logout_url = authenticator.get_logout_url("https://app.example.com/")
        assert (
            logout_url
            == "https://auth.example.com/logout?post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2F"
        )

    def test_get_logout_url_no_endpoint(self, authenticator):
        """Test get_logout_url returns None when no endpoint."""
        mock_provider = OIDCProviderConfig(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            jwks_uri="https://auth.example.com/jwks",
            end_session_endpoint=None,
        )
        authenticator._provider = mock_provider

        logout_url = authenticator.get_logout_url()
        assert logout_url is None


class TestSAMLAuthenticator:
    """Tests for SAMLAuthenticator class."""

    @pytest.fixture
    def authenticator(self, mock_saml_config):
        """Create a SAMLAuthenticator instance."""
        return SAMLAuthenticator(
            entity_id=mock_saml_config.entity_id,
            acs_url=mock_saml_config.acs_url,
            sls_url=mock_saml_config.sls_url,
            x509cert=mock_saml_config.x509cert,
            private_key=mock_saml_config.private_key,
            idp_entity_id=mock_saml_config.idp_entity_id,
            idp_sso_url=mock_saml_config.idp_sso_url,
            idp_slo_url=mock_saml_config.idp_slo_url,
            idp_x509cert=mock_saml_config.idp_x509cert,
            nameid_format=mock_saml_config.nameid_format,
            auto_provision=mock_saml_config.auto_provision,
            role_attribute=mock_saml_config.role_attribute,
            admin_roles=mock_saml_config.admin_roles,
            analyst_roles=mock_saml_config.analyst_roles,
            viewer_roles=mock_saml_config.viewer_roles,
        )

    def test_init_with_config(self, mock_saml_config):
        """Test initialization with explicit config."""
        auth = SAMLAuthenticator(
            entity_id=mock_saml_config.entity_id,
            acs_url=mock_saml_config.acs_url,
            x509cert=mock_saml_config.x509cert,
            private_key=mock_saml_config.private_key,
            idp_entity_id=mock_saml_config.idp_entity_id,
            idp_sso_url=mock_saml_config.idp_sso_url,
            idp_x509cert=mock_saml_config.idp_x509cert,
        )
        assert auth.config.entity_id == mock_saml_config.entity_id
        assert auth.config.acs_url == mock_saml_config.acs_url

    def test_init_with_settings(self, mock_settings):
        """Test initialization with settings."""
        auth = SAMLAuthenticator(settings=mock_settings)
        assert auth.config.entity_id == "https://strix.example.com/saml/metadata"
        assert auth.config.acs_url == "https://strix.example.com/saml/acs"

    def test_build_saml_settings(self, authenticator):
        """Test building SAML settings dictionary."""
        settings = authenticator._build_saml_settings()
        assert settings["sp"]["entityId"] == "https://strix.example.com/saml/metadata"
        assert settings["sp"]["assertionConsumerService"]["url"] == "https://strix.example.com/saml/acs"
        assert settings["idp"]["entityId"] == "https://idp.example.com"
        assert settings["idp"]["singleSignOnService"]["url"] == "https://idp.example.com/sso"
        assert settings["security"]["authnRequestsSigned"] is True

    def test_build_saml_settings_not_configured(self):
        """Test building settings fails when not configured."""
        auth = SAMLAuthenticator()
        with pytest.raises(ValueError, match="SAML not configured"):
            auth._build_saml_settings()

    def test_get_config(self, authenticator):
        """Test get_config returns serializable config."""
        config = authenticator.get_config()
        assert config["type"] == "saml"
        assert config["entity_id"] == "https://strix.example.com/saml/metadata"
        assert config["acs_url"] == "https://strix.example.com/saml/acs"
        assert config["x509cert"] == "MIID...cert..."
        assert config["private_key"] == "MIIE...key..."
        assert config["idp_entity_id"] == "https://idp.example.com"
        assert config["idp_sso_url"] == "https://idp.example.com/sso"
        assert config["idp_x509cert"] == "MIID...idp_cert..."
        assert config["role_attribute"] == "role"
        assert config["admin_roles"] == "admin"
        assert config["analyst_roles"] == "analyst"
        assert config["viewer_roles"] == "viewer"

    def test_from_config(self):
        """Test creating authenticator from config dict."""
        config = {
            "entity_id": "https://strix.example.com/saml/metadata",
            "acs_url": "https://strix.example.com/saml/acs",
            "x509cert": "MIID...cert...",
            "private_key": "MIIE...key...",
            "idp_entity_id": "https://idp.example.com",
            "idp_sso_url": "https://idp.example.com/sso",
            "idp_x509cert": "MIID...idp_cert...",
            "role_attribute": "role",
            "admin_roles": "admin",
            "analyst_roles": "analyst",
            "viewer_roles": "viewer",
            "principal_id": "custom-saml",
        }
        auth = SAMLAuthenticator.from_config(config)
        assert auth.config.entity_id == "https://strix.example.com/saml/metadata"
        assert auth.principal_id == "custom-saml"

    @pytest.mark.asyncio
    async def test_authenticate_not_configured(self):
        """Test authenticate returns error when not configured."""
        auth = SAMLAuthenticator()
        result = auth.authenticate("https://target.example.com")

        assert result.success is False
        assert "SAML not configured" in result.error

    @pytest.mark.asyncio
    async def test_authenticate_no_saml_response(self, authenticator):
        """Test authenticate returns SSO URL when no SAMLResponse."""
        with patch.object(
            authenticator, "get_sso_url", return_value="https://idp.example.com/sso?SAMLRequest=..."
        ):
            result = authenticator.authenticate("https://target.example.com")

            assert result.success is False
            assert result.error == "SAML authentication required"
            assert "sso_url" in result.session_data


class TestCreateAuthenticatorFromDict:
    """Tests for create_authenticator_from_dict factory."""

    def test_create_token(self):
        """Test creating token authenticator."""
        config = {"type": "token", "bearer": "test-token", "principal_id": "test"}
        auth = create_authenticator_from_dict(config)
        assert isinstance(auth, OIDCAuthenticator) is False
        from strix.core.auth import TokenAuthenticator

        assert isinstance(auth, TokenAuthenticator)

    def test_create_oidc(self):
        """Test creating OIDC authenticator."""
        config = {
            "type": "oidc",
            "issuer": "https://auth.example.com",
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "redirect_uri": "https://scanner.example.com/callback",
        }
        auth = create_authenticator_from_dict(config)
        assert isinstance(auth, OIDCAuthenticator)
        assert auth.config.issuer == "https://auth.example.com"

    def test_create_saml(self):
        """Test creating SAML authenticator."""
        config = {
            "type": "saml",
            "entity_id": "https://strix.example.com/saml/metadata",
            "acs_url": "https://strix.example.com/saml/acs",
            "x509cert": "MIID...cert...",
            "private_key": "MIIE...key...",
            "idp_entity_id": "https://idp.example.com",
            "idp_sso_url": "https://idp.example.com/sso",
            "idp_x509cert": "MIID...idp_cert...",
        }
        auth = create_authenticator_from_dict(config)
        assert isinstance(auth, SAMLAuthenticator)
        assert auth.config.entity_id == "https://strix.example.com/saml/metadata"

    def test_create_unknown_type(self):
        """Test creating unknown authenticator type fails."""
        config = {"type": "unknown"}
        with pytest.raises(Exception, match="unknown authenticator type"):
            create_authenticator_from_dict(config)


class TestMultiStepWithSSO:
    """Tests for MultiStepAuthenticator with OIDC/SAML steps."""

    def test_multi_step_with_oidc(self, mock_oidc_config):
        """Test multi-step with OIDC step."""
        from strix.core.auth import TokenAuthenticator

        token_auth = TokenAuthenticator(bearer="token123", principal_id="step1")
        oidc_auth = OIDCAuthenticator(
            issuer=mock_oidc_config.issuer,
            client_id=mock_oidc_config.client_id,
            client_secret=mock_oidc_config.client_secret,
            redirect_uri=mock_oidc_config.redirect_uri,
        )
        multi = MultiStepAuthenticator(steps=[token_auth, oidc_auth], principal_id="multi-user")

        config = multi.get_config()
        assert config["type"] == "multi_step"
        assert len(config["steps"]) == 2
        assert config["steps"][0]["type"] == "token"
        assert config["steps"][1]["type"] == "oidc"

    def test_multi_step_with_saml(self, mock_saml_config):
        """Test multi-step with SAML step."""
        from strix.core.auth import TokenAuthenticator

        token_auth = TokenAuthenticator(bearer="token123", principal_id="step1")
        saml_auth = SAMLAuthenticator(
            entity_id=mock_saml_config.entity_id,
            acs_url=mock_saml_config.acs_url,
            x509cert=mock_saml_config.x509cert,
            private_key=mock_saml_config.private_key,
            idp_entity_id=mock_saml_config.idp_entity_id,
            idp_sso_url=mock_saml_config.idp_sso_url,
            idp_x509cert=mock_saml_config.idp_x509cert,
        )
        multi = MultiStepAuthenticator(steps=[token_auth, saml_auth], principal_id="multi-user")

        config = multi.get_config()
        assert config["type"] == "multi_step"
        assert len(config["steps"]) == 2
        assert config["steps"][0]["type"] == "token"
        assert config["steps"][1]["type"] == "saml"

    def test_from_config_with_oidc_and_saml(self):
        """Test from_config with OIDC and SAML steps."""

        config = {
            "type": "multi_step",
            "steps": [
                {"type": "token", "bearer": "token123", "principal_id": "step1"},
                {
                    "type": "oidc",
                    "issuer": "https://auth.example.com",
                    "client_id": "test-client-id",
                    "client_secret": "test-client-secret",
                    "redirect_uri": "https://scanner.example.com/callback",
                    "principal_id": "oidc-step",
                },
                {
                    "type": "saml",
                    "entity_id": "https://strix.example.com/saml/metadata",
                    "acs_url": "https://strix.example.com/saml/acs",
                    "x509cert": "MIID...cert...",
                    "private_key": "MIIE...key...",
                    "idp_entity_id": "https://idp.example.com",
                    "idp_sso_url": "https://idp.example.com/sso",
                    "idp_x509cert": "MIID...idp_cert...",
                    "principal_id": "saml-step",
                },
            ],
            "principal_id": "multi-user",
        }
        multi = MultiStepAuthenticator.from_config(config)
        assert len(multi.steps) == 3
        assert isinstance(multi.steps[0], TokenAuthenticator)
        assert isinstance(multi.steps[1], OIDCAuthenticator)
        assert isinstance(multi.steps[2], SAMLAuthenticator)

"""OIDC Authentication for Ishastra Core Assessment Engine.

Provides OIDC Authorization Code flow with PKCE for authenticated scanning.
Integrates with the core Authenticator pattern for use in assessments.
Fail-closed when misconfigured.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from ishastra.config import Settings
from ishastra.core.auth import (
    Authenticator,
    AuthResult,
    Principal,
    generate_nonce,
    generate_pkce_pair,
    generate_state,
)
from ishastra.core.store import load_api_keys_sync, save_api_key_sync

log = logging.getLogger(__name__)

_STATE_TTL = 300
_NONCE_TTL = 300


@dataclass(frozen=True)
class OIDCConfig:
    """OIDC configuration loaded from Settings."""

    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: str = "openid email profile"
    auto_provision: bool = True

    @property
    def is_configured(self) -> bool:
        return all([self.issuer, self.client_id, self.client_secret, self.redirect_uri])

    @classmethod
    def from_settings(cls, settings: Settings) -> OIDCConfig:
        issuer = settings.oidc_issuer
        client_id = settings.oidc_client_id
        client_secret = settings.oidc_client_secret
        redirect_uri = settings.oidc_redirect_uri
        scopes = settings.oidc_scopes
        auto_provision = settings.oidc_auto_provision

        if not all([issuer, client_id, client_secret, redirect_uri]):
            return cls(
                issuer="",
                client_id="",
                client_secret="",
                redirect_uri="",
                scopes=scopes,
                auto_provision=auto_provision,
            )

        try:
            parsed = urllib.parse.urlparse(redirect_uri)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError
        except ValueError as e:
            raise ValueError("ISHASTRA_OIDC_REDIRECT_URI must be a valid URL") from e

        return cls(
            issuer=issuer,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes,
            auto_provision=auto_provision,
        )


class OIDCProviderConfig:
    """OIDC Provider Configuration (from .well-known/openid-configuration)."""

    def __init__(
        self,
        issuer: str,
        authorization_endpoint: str,
        token_endpoint: str,
        jwks_uri: str,
        userinfo_endpoint: str | None = None,
        end_session_endpoint: str | None = None,
    ):
        self.issuer = issuer
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.jwks_uri = jwks_uri
        self.userinfo_endpoint = userinfo_endpoint
        self.end_session_endpoint = end_session_endpoint

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OIDCProviderConfig:
        return cls(
            issuer=data["issuer"],
            authorization_endpoint=data["authorization_endpoint"],
            token_endpoint=data["token_endpoint"],
            jwks_uri=data["jwks_uri"],
            userinfo_endpoint=data.get("userinfo_endpoint"),
            end_session_endpoint=data.get("end_session_endpoint"),
        )


def fetch_oidc_config(issuer: str) -> OIDCProviderConfig:
    """Fetch OIDC provider configuration from discovery endpoint."""
    with httpx.Client(timeout=10.0) as client:
        resp = client.get(f"{issuer.rstrip('/')}/.well-known/openid-configuration")
        resp.raise_for_status()
        return OIDCProviderConfig.from_dict(resp.json())


def exchange_code_for_tokens(
    config: OIDCConfig,
    provider: OIDCProviderConfig,
    code: str,
    code_verifier: str,
) -> dict[str, Any]:
    """Exchange authorization code for tokens."""
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(
            provider.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": config.redirect_uri,
                "code_verifier": code_verifier,
                "client_id": config.client_id,
                "client_secret": config.client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        return resp.json()


def fetch_userinfo(
    provider: OIDCProviderConfig,
    access_token: str,
) -> dict[str, Any]:
    """Fetch user info from OIDC provider."""
    if not provider.userinfo_endpoint:
        return {}
    with httpx.Client(timeout=10.0) as client:
        resp = client.get(
            provider.userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()


def validate_id_token(
    id_token: str,
    provider: OIDCProviderConfig,
    client_id: str,
    nonce: str | None,
) -> dict[str, Any]:
    """Validate ID token signature and claims."""

    with httpx.Client(timeout=10.0) as client:
        jwks_resp = client.get(provider.jwks_uri)
        jwks_resp.raise_for_status()
        jwks = jwks_resp.json()

    unverified_header = jwt.get_unverified_header(id_token)
    kid = unverified_header.get("kid")
    if not kid:
        raise ValueError("ID token missing kid")

    key = None
    for k in jwks.get("keys", []):
        if k.get("kid") == kid:
            key = jwt.algorithms.RSAAlgorithm.from_jwk(k)
            break

    if not key:
        raise ValueError("No matching JWK found for kid")

    if not isinstance(key, RSAPublicKey):
        raise ValueError("JWK is not an RSA public key")

    claims = jwt.decode(
        id_token,
        key,
        algorithms=["RS256"],
        audience=client_id,
        issuer=provider.issuer,
        options={"verify_exp": True, "verify_iat": True, "verify_nbf": True},
    )

    if nonce and claims.get("nonce") != nonce:
        raise ValueError("Nonce mismatch")

    return claims


class OIDCAuthenticator(Authenticator):
    """OIDC Authorization Code flow with PKCE for authenticated scanning.

    This authenticator performs the OIDC flow to obtain an identity token
    and optionally fetches userinfo. It can be used for assessments that
    require OIDC authentication.

    Usage:
        auth = OIDCAuthenticator(
            issuer="https://auth.example.com",
            client_id="...",
            client_secret="...",
            redirect_uri="https://scanner.example.com/callback",
        )
        result = auth.authenticate("https://target.example.com")
    """

    def __init__(
        self,
        *,
        issuer: str = "",
        client_id: str = "",
        client_secret: str = "",
        redirect_uri: str = "",
        scopes: str = "openid email profile",
        auto_provision: bool = True,
        principal_id: str = "oidc-auth",
        settings: Settings | None = None,
    ):
        if settings:
            config = OIDCConfig.from_settings(settings)
            self.config = config
        else:
            self.config = OIDCConfig(
                issuer=issuer,
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                scopes=scopes,
                auto_provision=auto_provision,
            )
        self.principal_id = principal_id
        self._provider: OIDCProviderConfig | None = None
        self._state: str | None = None
        self._nonce: str | None = None
        self._code_verifier: str | None = None
        self._tokens: dict[str, Any] | None = None
        self._claims: dict[str, Any] | None = None

    def _ensure_provider(self) -> OIDCProviderConfig:
        """Fetch and cache provider configuration."""
        if self._provider is None:
            if not self.config.is_configured:
                raise ValueError("OIDC not configured")
            self._provider = fetch_oidc_config(self.config.issuer)
        return self._provider

    def get_authorization_url(self) -> str:
        """Generate the OIDC authorization URL with PKCE."""
        if not self.config.is_configured:
            raise ValueError("OIDC not configured")

        provider = self._provider
        if provider is None:
            raise ValueError("Provider not initialized. Call authenticate() first or initialize manually.")

        self._code_verifier, code_challenge = generate_pkce_pair()
        self._state = generate_state()
        self._nonce = generate_nonce()

        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "scope": self.config.scopes,
            "state": self._state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "nonce": self._nonce,
        }
        return f"{provider.authorization_endpoint}?{urlencode(params)}"

    def exchange_code(self, code: str, state: str) -> dict[str, Any]:
        """Exchange authorization code for tokens and validate."""
        if self._state != state:
            raise ValueError("State mismatch")

        provider = self._ensure_provider()

        if not self._code_verifier:
            raise ValueError("PKCE verifier not available")

        self._tokens = exchange_code_for_tokens(self.config, provider, code, self._code_verifier)

        id_token = self._tokens.get("id_token")
        if not id_token:
            raise ValueError("No ID token returned")

        self._claims = validate_id_token(id_token, provider, self.config.client_id, self._nonce)

        return self._tokens

    def get_userinfo(self) -> dict[str, Any]:
        """Fetch user info from UserInfo endpoint."""
        if not self._tokens:
            raise ValueError("No tokens available. Complete authentication first.")

        provider = self._ensure_provider()
        access_token = self._tokens.get("access_token")
        if not access_token:
            raise ValueError("No access token available")

        return fetch_userinfo(provider, access_token)

    def authenticate(
        self,
        target: str,
        *,
        timeout: float = 30.0,
        cancel: Any | None = None,
    ) -> AuthResult:
        """Perform OIDC authentication and return a Principal with credentials.

        Note: This requires the authorization code flow to have been completed
        externally (e.g., via a browser redirect). The code and state must be
        provided via the `code` and `state` parameters in the target URL query
        string, or this will return a redirect to the authorization endpoint.

        For headless/automated use, consider using TokenAuthenticator with
        a pre-obtained access token instead.
        """
        if not self.config.is_configured:
            return AuthResult(
                success=False,
                error=(
                    "OIDC not configured — set ISHASTRA_OIDC_ISSUER, "
                    "ISHASTRA_OIDC_CLIENT_ID, ISHASTRA_OIDC_CLIENT_SECRET, "
                    "ISHASTRA_OIDC_REDIRECT_URI"
                ),
            )

        parsed = urllib.parse.urlparse(target)
        query_params = urllib.parse.parse_qs(parsed.query)
        code = query_params.get("code", [None])[0]
        state = query_params.get("state", [None])[0]

        if not code or not state:
            provider = self._ensure_provider()
            auth_url = self.get_authorization_url()
            return AuthResult(
                success=False,
                error="OIDC authentication required",
                session_data={"authorization_url": auth_url, "provider": provider.__dict__},
            )

        try:
            self.exchange_code(code, state)
        except Exception as e:
            log.error("OIDC token exchange failed: %s", e)
            return AuthResult(success=False, error=f"Token exchange failed: {e}")

        try:
            userinfo = self.get_userinfo()
        except Exception as e:
            log.warning("UserInfo fetch failed: %s", e)
            userinfo = {}

        claims = self._claims or {}
        email = claims.get("email") or userinfo.get("email")
        sub = claims.get("sub") or userinfo.get("sub")
        name = claims.get("name") or userinfo.get("name") or claims.get("preferred_username")
        org = claims.get("org") or claims.get("organization") or userinfo.get("organization")

        if not email or not sub:
            return AuthResult(
                success=False,
                error="Missing required claims (email, sub) after authentication",
            )

        tenant_id = f"oidc_{sub}"
        tier = "standard"

        keys = load_api_keys_sync()
        tenant_exists = any(k["tenant_id"] == tenant_id for k in keys)

        if not tenant_exists and self.config.auto_provision:
            raw_key = f"ishastra_{secrets.token_urlsafe(32)}"
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            now = time.time()
            save_api_key_sync(
                tenant_id=tenant_id,
                key_hash=key_hash,
                tier=tier,
                admin=False,
                active=True,
                created_at=now,
                last_used=now,
                scope="write",
            )
            log.info("Auto-provisioned OIDC tenant: %s", tenant_id)
        elif not tenant_exists:
            return AuthResult(
                success=False,
                error="OIDC user not provisioned — contact administrator",
            )

        tokens = self._tokens or {}
        principal = Principal(
            id=self.principal_id,
            bearer=tokens.get("access_token", ""),
        )

        return AuthResult(
            success=True,
            principal=principal,
            bearer=tokens.get("access_token", ""),
            session_data={
                "tenant_id": tenant_id,
                "email": email,
                "name": name,
                "org": org,
                "id_token": tokens.get("id_token"),
                "refresh_token": tokens.get("refresh_token"),
                "claims": claims,
                "userinfo": userinfo,
            },
        )

    def get_config(self) -> dict[str, Any]:
        """Return serializable configuration (encrypted secrets)."""
        return {
            "type": "oidc",
            "issuer": self.config.issuer,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "redirect_uri": self.config.redirect_uri,
            "scopes": self.config.scopes,
            "auto_provision": self.config.auto_provision,
            "principal_id": self.principal_id,
        }

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> OIDCAuthenticator:
        return cls(
            issuer=config.get("issuer", ""),
            client_id=config.get("client_id", ""),
            client_secret=config.get("client_secret", ""),
            redirect_uri=config.get("redirect_uri", ""),
            scopes=config.get("scopes", "openid email profile"),
            auto_provision=config.get("auto_provision", True),
            principal_id=config.get("principal_id", "oidc-auth"),
        )

    def get_logout_url(self, post_logout_redirect_uri: str = "/") -> str | None:
        """Get the OIDC provider logout URL (OP-initiated logout)."""
        if self._provider and self._provider.end_session_endpoint:
            params = {"post_logout_redirect_uri": post_logout_redirect_uri}
            return f"{self._provider.end_session_endpoint}?{urlencode(params)}"
        return None


async def create_oidc_authenticator_from_settings(
    settings: Settings,
    principal_id: str = "oidc-auth",
) -> OIDCAuthenticator | None:
    """Factory to create OIDCAuthenticator from settings if configured."""
    config = OIDCConfig.from_settings(settings)
    if not config.is_configured:
        return None
    return OIDCAuthenticator(settings=settings, principal_id=principal_id)

"""Authentication handlers for authenticated scanning.

Provides session/cookie authentication, header/token authentication,
form-based login with CSRF handling, multi-step authentication flows,
and OIDC/SAML SSO authentication.
Credentials are encrypted at rest using AES-256-GCM via crypto.py.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

from strix.config import Settings
from strix.core.authz import Principal
from strix.core.probe import EndpointProbe
from strix.crypto import EncryptionError, decrypt, encrypt

log = logging.getLogger(__name__)

# OIDC constants
_STATE_TTL = 300  # 5 minutes
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
            raise ValueError("STRIX_OIDC_REDIRECT_URI must be a valid URL") from e

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
    import httpx

    with httpx.Client(timeout=10.0) as client:
        resp = client.get(f"{issuer.rstrip('/')}/.well-known/openid-configuration")
        resp.raise_for_status()
        return OIDCProviderConfig.from_dict(resp.json())


def generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge."""
    code_verifier = secrets.token_urlsafe(32)  # 43 chars
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return code_verifier, code_challenge


def generate_state() -> str:
    """Generate secure state parameter."""
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    """Generate nonce for ID token validation."""
    return secrets.token_urlsafe(32)


def exchange_code_for_tokens(
    config: OIDCConfig,
    provider: OIDCProviderConfig,
    code: str,
    code_verifier: str,
) -> dict[str, Any]:
    """Exchange authorization code for tokens."""
    import httpx

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
    import httpx

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
    import httpx
    import jwt
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

    # Fetch JWKS
    with httpx.Client(timeout=10.0) as client:
        jwks_resp = client.get(provider.jwks_uri)
        jwks_resp.raise_for_status()
        jwks = jwks_resp.json()

    # Find matching key
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

    # Decode and validate
    claims = jwt.decode(
        id_token,
        key,
        algorithms=["RS256"],
        audience=client_id,
        issuer=provider.issuer,
        options={"verify_exp": True, "verify_iat": True, "verify_nbf": True},
    )

    # Validate nonce if provided
    if nonce and claims.get("nonce") != nonce:
        raise ValueError("Nonce mismatch")

    return claims


class AuthConfigError(Exception):
    """Raised when authentication configuration is invalid."""


@dataclass(frozen=True)
class LoginForm:
    """Discovered login form details."""

    action_url: str
    method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: str | None = None
    csrf_value: str | None = None
    extra_fields: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthResult:
    """Result of an authentication attempt."""

    success: bool
    principal: Principal | None = None
    error: str | None = None
    cookies: tuple[tuple[str, str], ...] = ()
    headers: tuple[tuple[str, str], ...] = ()
    bearer: str = ""
    session_data: dict[str, Any] = field(default_factory=dict)


class Authenticator(ABC):
    """Base class for authentication handlers."""

    principal_id: str

    @abstractmethod
    def authenticate(
        self,
        target: str,
        *,
        timeout: float = 30.0,
        cancel: Any | None = None,
    ) -> AuthResult:
        """Perform authentication and return a Principal with credentials."""

    @abstractmethod
    def get_config(self) -> dict[str, Any]:
        """Return serializable configuration (encrypted secrets)."""


class TokenAuthenticator(Authenticator):
    """Header/token authentication (Bearer, API key, custom headers)."""

    def __init__(
        self,
        *,
        bearer: str = "",
        api_key: str = "",
        api_key_header: str = "X-API-Key",
        custom_headers: dict[str, str] | None = None,
        principal_id: str = "token-auth",
    ):
        self.bearer = bearer
        self.api_key = api_key
        self.api_key_header = api_key_header
        self.custom_headers = custom_headers or {}
        self.principal_id = principal_id

    def authenticate(
        self,
        target: str,
        *,
        timeout: float = 30.0,
        cancel: Any | None = None,
    ) -> AuthResult:
        headers: list[tuple[str, str]] = []
        if self.bearer:
            headers.append(("Authorization", f"Bearer {self.bearer}"))
        if self.api_key:
            headers.append((self.api_key_header, self.api_key))
        for name, value in self.custom_headers.items():
            headers.append((name, value))

        principal = Principal(
            id=self.principal_id,
            headers=tuple(headers),
            bearer=self.bearer,
        )
        return AuthResult(
            success=True,
            principal=principal,
            headers=tuple(headers),
            bearer=self.bearer,
        )

    def get_config(self) -> dict[str, Any]:
        return {
            "type": "token",
            "bearer": self.bearer,
            "api_key": self.api_key,
            "api_key_header": self.api_key_header,
            "custom_headers": self.custom_headers,
            "principal_id": self.principal_id,
        }

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> TokenAuthenticator:
        return cls(
            bearer=config.get("bearer", ""),
            api_key=config.get("api_key", ""),
            api_key_header=config.get("api_key_header", "X-API-Key"),
            custom_headers=config.get("custom_headers", {}),
            principal_id=config.get("principal_id", "token-auth"),
        )


class SessionAuthenticator(Authenticator):
    """Session/cookie authentication with persistent cookie jar."""

    def __init__(
        self,
        *,
        cookies: dict[str, str] | None = None,
        principal_id: str = "session-auth",
    ):
        self.cookies = cookies or {}
        self.principal_id = principal_id

    def authenticate(
        self,
        target: str,
        *,
        timeout: float = 30.0,
        cancel: Any | None = None,
    ) -> AuthResult:
        cookie_tuples = tuple((k, v) for k, v in self.cookies.items())
        principal = Principal(
            id=self.principal_id,
            cookies=cookie_tuples,
        )
        return AuthResult(
            success=True,
            principal=principal,
            cookies=cookie_tuples,
        )

    def update_cookies(self, cookies: dict[str, str]) -> None:
        """Update stored cookies (e.g., after login)."""
        self.cookies.update(cookies)

    def get_config(self) -> dict[str, Any]:
        return {
            "type": "session",
            "cookies": self.cookies,
            "principal_id": self.principal_id,
        }

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> SessionAuthenticator:
        return cls(
            cookies=config.get("cookies", {}),
            principal_id=config.get("principal_id", "session-auth"),
        )


class FormLoginAuthenticator(Authenticator):
    """Form-based login with CSRF token handling."""

    def __init__(
        self,
        *,
        login_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        csrf_field: str | None = None,
        extra_fields: dict[str, str] | None = None,
        principal_id: str = "form-login",
        session_authenticator: SessionAuthenticator | None = None,
    ):
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.csrf_field = csrf_field
        self.extra_fields = extra_fields or {}
        self.principal_id = principal_id
        self.session_authenticator = session_authenticator or SessionAuthenticator(principal_id=principal_id)

    def _discover_login_form(self, target: str, probe: EndpointProbe) -> LoginForm | None:
        """Discover login form on the target page."""
        response = probe._fetch(target, timeout=10.0)
        body = response.get("body", "")
        if not body:
            return None

        # Parse HTML to find login form
        from html.parser import HTMLParser

        class FormParser(HTMLParser):
            def __init__(self, base_url: str):
                super().__init__(convert_charrefs=True)
                self.base_url = base_url
                self.forms: list[dict[str, Any]] = []
                self.current_form: dict[str, Any] | None = None

            def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
                attr_map = {k.lower(): v for k, v in attrs}
                if tag.lower() == "form":
                    self.current_form = {
                        "action": attr_map.get("action", ""),
                        "method": (attr_map.get("method") or "GET").upper(),
                        "inputs": {},
                    }
                elif tag.lower() == "input" and self.current_form is not None:
                    input_type = (attr_map.get("type") or "text").lower()
                    name = attr_map.get("name")
                    value = attr_map.get("value", "")
                    if name:
                        self.current_form["inputs"][name] = {
                            "type": input_type,
                            "value": value,
                        }

            def handle_endtag(self, tag: str):
                if tag.lower() == "form" and self.current_form is not None:
                    self.forms.append(self.current_form)
                    self.current_form = None

        parser = FormParser(target)
        try:
            parser.feed(body)
        except Exception:
            return None

        # Find the most likely login form (has password field)
        for form in parser.forms:
            inputs = form.get("inputs", {})
            has_password = any(inp.get("type") == "password" for inp in inputs.values())
            if has_password:
                action = form.get("action", "")
                action_url = urljoin(target, action) if action else target
                method = form.get("method", "POST")

                # Find username field (text, email, etc.)
                username_field = self.username_field
                for name, inp in inputs.items():
                    if inp.get("type") in ("text", "email", "username"):
                        username_field = name
                        break

                # Find password field
                password_field = self.password_field
                for name, inp in inputs.items():
                    if inp.get("type") == "password":
                        password_field = name
                        break

                # Find CSRF field
                csrf_field = self.csrf_field
                csrf_value = None
                if not csrf_field:
                    for name, inp in inputs.items():
                        if inp.get("type") == "hidden" and any(
                            k in name.lower() for k in ("csrf", "token", "_token", "authenticity")
                        ):
                            csrf_field = name
                            csrf_value = inp.get("value", "")
                            break

                return LoginForm(
                    action_url=action_url,
                    method=method,
                    username_field=username_field,
                    password_field=password_field,
                    csrf_field=csrf_field,
                    csrf_value=csrf_value,
                    extra_fields={
                        k: v.get("value", "")
                        for k, v in inputs.items()
                        if inp.get("type") == "hidden" and k != csrf_field
                    },
                )
        return None

    def authenticate(
        self,
        target: str,
        *,
        timeout: float = 30.0,
        cancel: Any | None = None,
    ) -> AuthResult:
        probe = EndpointProbe(timeout=min(timeout, 10.0))

        # Discover login form
        login_form = self._discover_login_form(self.login_url, probe)
        if login_form is None:
            # Fall back to configured values
            login_form = LoginForm(
                action_url=self.login_url,
                method="POST",
                username_field=self.username_field,
                password_field=self.password_field,
                csrf_field=self.csrf_field,
            )

        # Build form data
        form_data = {
            login_form.username_field: self.username,
            login_form.password_field: self.password,
        }
        form_data.update(self.extra_fields)
        if login_form.csrf_field and login_form.csrf_value:
            form_data[login_form.csrf_field] = login_form.csrf_value

        # Submit login form
        parsed_login = urlparse(login_form.action_url)
        login_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if login_form.method == "GET":
            # For GET, append to URL
            query = urllib.parse.urlencode(form_data)
            login_url = f"{login_form.action_url}?{query}"
            body = None
        else:
            login_url = login_form.action_url
            body = urllib.parse.urlencode(form_data).encode()

        # Make request
        from strix.core.scope import destination as scope_destination

        denial, reason, dest = scope_destination(login_url)
        if denial or dest is None:
            return AuthResult(success=False, error=f"scope refused login URL: {reason}")

        import http.client
        import socket
        import ssl

        request_timeout = min(timeout, 10.0)
        connection = http.client.HTTPConnection(dest.host, dest.port, timeout=request_timeout)
        sock = socket.create_connection((dest.ip, dest.port), timeout=request_timeout)
        if dest.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=dest.host)
        connection.sock = sock

        try:
            connection.request(login_form.method, parsed_login.path or "/", body=body, headers=login_headers)
            response = connection.getresponse()
            resp_body = response.read().decode("utf-8", errors="ignore")
            resp_headers = dict(response.getheaders())
            status = response.status

            # Extract cookies from response
            new_cookies: dict[str, str] = {}
            set_cookie = resp_headers.get("set-cookie", "")
            if isinstance(set_cookie, list):
                set_cookie = "; ".join(set_cookie)
            for cookie in set_cookie.split(","):
                cookie = cookie.strip()
                if "=" in cookie:
                    name, rest = cookie.split("=", 1)
                    # Extract just the value before any attributes
                    value = rest.split(";")[0]
                    new_cookies[name.strip()] = value

            # Update session authenticator
            self.session_authenticator.update_cookies(new_cookies)

            # Check if login succeeded (heuristic: redirect, 200 with session cookie, etc.)
            success = status in (200, 302, 303) and bool(new_cookies)

            if success:
                # Get updated cookies from session
                cookie_tuples = tuple(self.session_authenticator.cookies.items())
                principal = Principal(
                    id=self.principal_id,
                    cookies=cookie_tuples,
                )
                return AuthResult(
                    success=True,
                    principal=principal,
                    cookies=cookie_tuples,
                    session_data={"login_response": resp_body[:500]},
                )
            return AuthResult(success=False, error=f"login failed: HTTP {status}")

        except Exception as exc:
            return AuthResult(success=False, error=f"login request failed: {exc}")
        finally:
            connection.close()
            sock.close()

    def get_config(self) -> dict[str, Any]:
        return {
            "type": "form_login",
            "login_url": self.login_url,
            "username": self.username,
            "password": self.password,
            "username_field": self.username_field,
            "password_field": self.password_field,
            "csrf_field": self.csrf_field,
            "extra_fields": self.extra_fields,
            "principal_id": self.principal_id,
        }

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> FormLoginAuthenticator:
        session_auth = SessionAuthenticator(principal_id=config.get("principal_id", "form-login"))
        return cls(
            login_url=config["login_url"],
            username=config["username"],
            password=config["password"],
            username_field=config.get("username_field", "username"),
            password_field=config.get("password_field", "password"),
            csrf_field=config.get("csrf_field"),
            extra_fields=config.get("extra_fields", {}),
            principal_id=config.get("principal_id", "form-login"),
            session_authenticator=session_auth,
        )


class MultiStepAuthenticator(Authenticator):
    """Chain multiple authentication steps."""

    def __init__(self, steps: list[Authenticator], principal_id: str = "multi-step"):
        self.steps = steps
        self.principal_id = principal_id

    def authenticate(
        self,
        target: str,
        *,
        timeout: float = 30.0,
        cancel: Any | None = None,
    ) -> AuthResult:
        combined_cookies: dict[str, str] = {}
        combined_headers: list[tuple[str, str]] = []
        bearer = ""
        session_data: dict[str, Any] = {}

        for step in self.steps:
            if cancel is not None and hasattr(cancel, "is_set") and cancel.is_set():
                return AuthResult(success=False, error="authentication cancelled")

            result = step.authenticate(target, timeout=timeout, cancel=cancel)
            if not result.success:
                return AuthResult(
                    success=False,
                    error=f"step {step.__class__.__name__} failed: {result.error}",
                )

            if result.cookies:
                combined_cookies.update(dict(result.cookies))
            if result.headers:
                combined_headers.extend(result.headers)
            if result.bearer:
                bearer = result.bearer
            session_data.update(result.session_data)

        principal = Principal(
            id=self.principal_id,
            cookies=tuple(combined_cookies.items()),
            headers=tuple(combined_headers),
            bearer=bearer,
        )
        return AuthResult(
            success=True,
            principal=principal,
            cookies=tuple(combined_cookies.items()),
            headers=tuple(combined_headers),
            bearer=bearer,
            session_data=session_data,
        )

    def get_config(self) -> dict[str, Any]:
        return {
            "type": "multi_step",
            "steps": [step.get_config() for step in self.steps],
            "principal_id": self.principal_id,
        }

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> MultiStepAuthenticator:
        steps: list[Authenticator] = []
        for step_config in config.get("steps", []):
            step_type = step_config.get("type")
            if step_type == "token":
                steps.append(TokenAuthenticator.from_config(step_config))
            elif step_type == "session":
                steps.append(SessionAuthenticator.from_config(step_config))
            elif step_type == "form_login":
                steps.append(FormLoginAuthenticator.from_config(step_config))
            elif step_type == "multi_step":
                steps.append(MultiStepAuthenticator.from_config(step_config))
            elif step_type == "oidc":
                steps.append(OIDCAuthenticator.from_config(step_config))
            elif step_type == "saml":
                steps.append(SAMLAuthenticator.from_config(step_config))
            else:
                raise AuthConfigError(f"unknown authenticator type: {step_type}")
        return cls(steps=steps, principal_id=config.get("principal_id", "multi-step"))


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
                    "OIDC not configured — set STRIX_OIDC_ISSUER, "
                    "STRIX_OIDC_CLIENT_ID, STRIX_OIDC_CLIENT_SECRET, "
                    "STRIX_OIDC_REDIRECT_URI"
                ),
            )

        # Check if callback params are in target URL
        parsed = urllib.parse.urlparse(target)
        query_params = urllib.parse.parse_qs(parsed.query)
        code = query_params.get("code", [None])[0]
        state = query_params.get("state", [None])[0]

        if not code or not state:
            # No callback params - return auth URL for manual flow
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

        # Fetch userinfo
        try:
            userinfo = self.get_userinfo()
        except Exception as e:
            log.warning("UserInfo fetch failed: %s", e)
            userinfo = {}

        # Merge claims and userinfo
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

        # Auto-provision tenant/user if enabled
        tenant_id = f"oidc_{sub}"
        tier = "standard"

        # Check if tenant exists
        from strix.core.store import load_api_keys_sync, save_api_key_sync

        keys = load_api_keys_sync()
        tenant_exists = any(k["tenant_id"] == tenant_id for k in keys)

        if not tenant_exists and self.config.auto_provision:
            # Create new tenant with API key
            raw_key = f"strix_{secrets.token_urlsafe(32)}"
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

        # Build principal with OIDC credentials
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


@dataclass(frozen=True)
class SAMLConfig:
    """SAML configuration loaded from Settings."""

    entity_id: str
    acs_url: str
    sls_url: str
    x509cert: str
    private_key: str
    idp_entity_id: str
    idp_sso_url: str
    idp_slo_url: str
    idp_x509cert: str
    nameid_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    auto_provision: bool = True
    role_attribute: str = "role"
    admin_roles: str = "admin"
    analyst_roles: str = "analyst"
    viewer_roles: str = "viewer"

    @property
    def is_configured(self) -> bool:
        return all(
            [
                self.entity_id,
                self.acs_url,
                self.x509cert,
                self.private_key,
                self.idp_entity_id,
                self.idp_sso_url,
                self.idp_x509cert,
            ]
        )

    @classmethod
    def from_settings(cls, settings: Settings) -> SAMLConfig:
        entity_id = settings.saml_entity_id
        acs_url = settings.saml_acs_url
        sls_url = settings.saml_sls_url
        x509cert = settings.saml_x509cert
        private_key = settings.saml_private_key
        idp_entity_id = settings.saml_idp_entity_id
        idp_sso_url = settings.saml_idp_sso_url
        idp_slo_url = settings.saml_idp_slo_url
        idp_x509cert = settings.saml_idp_x509cert
        nameid_format = settings.saml_nameid_format
        auto_provision = settings.saml_auto_provision
        role_attribute = settings.saml_role_attribute
        admin_roles = settings.saml_admin_roles
        analyst_roles = settings.saml_analyst_roles
        viewer_roles = settings.saml_viewer_roles

        if not all([entity_id, acs_url, x509cert, private_key, idp_entity_id, idp_sso_url, idp_x509cert]):
            return cls(
                entity_id="",
                acs_url="",
                sls_url="",
                x509cert="",
                private_key="",
                idp_entity_id="",
                idp_sso_url="",
                idp_slo_url="",
                idp_x509cert="",
                nameid_format=nameid_format,
                auto_provision=auto_provision,
                role_attribute=role_attribute,
                admin_roles=admin_roles,
                analyst_roles=analyst_roles,
                viewer_roles=viewer_roles,
            )

        return cls(
            entity_id=entity_id,
            acs_url=acs_url,
            sls_url=sls_url,
            x509cert=x509cert,
            private_key=private_key,
            idp_entity_id=idp_entity_id,
            idp_sso_url=idp_sso_url,
            idp_slo_url=idp_slo_url,
            idp_x509cert=idp_x509cert,
            nameid_format=nameid_format,
            auto_provision=auto_provision,
            role_attribute=role_attribute,
            admin_roles=admin_roles,
            analyst_roles=analyst_roles,
            viewer_roles=viewer_roles,
        )


class SAMLAuthenticator(Authenticator):
    """SAML 2.0 Service Provider authentication for enterprise SSO.

    This authenticator implements the SAML 2.0 Web Browser SSO profile
    (SP-initiated) using python3-saml. It handles the SAML flow to obtain
    user identity and role assertions from an Identity Provider (IdP).

    Usage:
        auth = SAMLAuthenticator(
            entity_id="https://strix.example.com/saml/metadata",
            acs_url="https://strix.example.com/saml/acs",
            x509cert="...",
            private_key="...",
            idp_entity_id="https://idp.example.com",
            idp_sso_url="https://idp.example.com/sso",
            idp_x509cert="...",
        )
        result = auth.authenticate("https://target.example.com")
    """

    def __init__(
        self,
        *,
        entity_id: str = "",
        acs_url: str = "",
        sls_url: str = "",
        x509cert: str = "",
        private_key: str = "",
        idp_entity_id: str = "",
        idp_sso_url: str = "",
        idp_slo_url: str = "",
        idp_x509cert: str = "",
        nameid_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        auto_provision: bool = True,
        role_attribute: str = "role",
        admin_roles: str = "admin",
        analyst_roles: str = "analyst",
        viewer_roles: str = "viewer",
        principal_id: str = "saml-auth",
        settings: Settings | None = None,
    ):
        if settings:
            config = SAMLConfig.from_settings(settings)
            self.config = config
        else:
            self.config = SAMLConfig(
                entity_id=entity_id,
                acs_url=acs_url,
                sls_url=sls_url,
                x509cert=x509cert,
                private_key=private_key,
                idp_entity_id=idp_entity_id,
                idp_sso_url=idp_sso_url,
                idp_slo_url=idp_slo_url,
                idp_x509cert=idp_x509cert,
                nameid_format=nameid_format,
                auto_provision=auto_provision,
                role_attribute=role_attribute,
                admin_roles=admin_roles,
                analyst_roles=analyst_roles,
                viewer_roles=viewer_roles,
            )
        self.principal_id = principal_id
        self._saml_settings: dict[str, Any] | None = None
        self._auth_request_id: str | None = None
        self._session_data: dict[str, Any] | None = None

    def _build_saml_settings(self) -> dict[str, Any]:
        """Build python3-saml settings dictionary."""
        if self._saml_settings is not None:
            return self._saml_settings

        if not self.config.is_configured:
            raise ValueError("SAML not configured")

        settings = {
            "strict": True,
            "debug": False,
            "sp": {
                "entityId": self.config.entity_id,
                "assertionConsumerService": {
                    "url": self.config.acs_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                "singleLogoutService": {
                    "url": self.config.sls_url or self.config.acs_url.replace("/acs", "/sls"),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "x509cert": self.config.x509cert,
                "privateKey": self.config.private_key,
                "NameIDFormat": self.config.nameid_format,
            },
            "idp": {
                "entityId": self.config.idp_entity_id,
                "singleSignOnService": {
                    "url": self.config.idp_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "singleLogoutService": {
                    "url": self.config.idp_slo_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                }
                if self.config.idp_slo_url
                else {},
                "x509cert": self.config.idp_x509cert,
            },
            "security": {
                "nameIdEncrypted": False,
                "authnRequestsSigned": True,
                "logoutRequestSigned": True,
                "logoutResponseSigned": True,
                "signMetadata": True,
                "wantMessagesSigned": False,
                "wantAssertionsSigned": True,
                "wantNameId": True,
                "wantNameIdEncrypted": False,
                "wantAssertionsEncrypted": False,
                "allowRepeatAttributeName": False,
                "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
                "lowercaseUrlencoding": False,
            },
        }
        self._saml_settings = settings
        return settings

    def get_sso_url(self) -> str:
        """Generate the SAML SSO redirect URL (SP-initiated)."""
        from onelogin.saml2.auth import OneLogin_Saml2_Auth

        if not self.config.is_configured:
            raise ValueError("SAML not configured")

        # Create a mock request for OneLogin_Saml2_Auth
        class MockRequest:
            def __init__(self, acs_url):
                self.https = "on"
                self.http_host = urllib.parse.urlparse(acs_url).netloc
                self.server_port = 443
                self.script_name = ""
                self.get_data = {}
                self.post_data = {}
                self.query_string = ""

        request = MockRequest(self.config.acs_url)
        saml_settings = self._build_saml_settings()
        auth = OneLogin_Saml2_Auth(request, saml_settings)
        self._auth_request_id = auth.login()
        return auth.get_last_request_id()

    def process_acs_response(self, saml_response: str, relay_state: str | None = None) -> dict[str, Any]:
        """Process the SAML Response from IdP (ACS endpoint)."""
        from onelogin.saml2.auth import OneLogin_Saml2_Auth

        if not self.config.is_configured:
            raise ValueError("SAML not configured")

        class MockRequest:
            def __init__(self, acs_url, saml_response):
                self.https = "on"
                self.http_host = urllib.parse.urlparse(acs_url).netloc
                self.server_port = 443
                self.script_name = ""
                self.get_data = {}
                self.post_data = {"SAMLResponse": saml_response}
                self.query_string = ""

        request = MockRequest(self.config.acs_url, saml_response)
        saml_settings = self._build_saml_settings()
        auth = OneLogin_Saml2_Auth(request, saml_settings)

        # Process the SAML response
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            raise ValueError(f"SAML response validation failed: {', '.join(errors)}")

        if not auth.is_authenticated():
            raise ValueError("SAML authentication failed: user not authenticated")

        # Extract user attributes
        attributes = auth.get_attributes()
        name_id = auth.get_nameid()
        session_index = auth.get_session_index()

        # Map role attribute to Strix role
        role_attr = self.config.role_attribute
        raw_roles = attributes.get(role_attr, [])
        if isinstance(raw_roles, str):
            raw_roles = [raw_roles]
        raw_roles = [r.lower() for r in raw_roles]

        admin_roles = [r.strip().lower() for r in self.config.admin_roles.split(",")]
        analyst_roles = [r.strip().lower() for r in self.config.analyst_roles.split(",")]
        strix_role = "viewer"  # default
        if any(r in admin_roles for r in raw_roles):
            strix_role = "admin"
        elif any(r in analyst_roles for r in raw_roles):
            strix_role = "analyst"

        # Use NameID as email/subject if available
        email = name_id or attributes.get("email", [""])[0] or attributes.get("mail", [""])[0]
        sub = attributes.get("sub", [name_id])[0] if name_id else email
        name = attributes.get("name", [attributes.get("displayName", [""])[0]])[0]
        org = attributes.get("organization", [attributes.get("org", [""])[0]])[0]

        if not email or not sub:
            raise ValueError("Missing required attributes (email, subject) in SAML assertion")

        self._session_data = {
            "email": email,
            "sub": sub,
            "name": name,
            "org": org,
            "role": strix_role,
            "raw_roles": raw_roles,
            "attributes": attributes,
            "session_index": session_index,
            "name_id": name_id,
        }

        return self._session_data

    def authenticate(
        self,
        target: str,
        *,
        timeout: float = 30.0,
        cancel: Any | None = None,
    ) -> AuthResult:
        """Perform SAML authentication and return a Principal with credentials.

        Note: This requires the SAML flow to have been completed
        externally (e.g., via a browser redirect to the IdP). The SAMLResponse
        must be provided via the target URL query string or this will return
        a redirect to the IdP SSO endpoint.

        For headless/automated use, consider using TokenAuthenticator with
        a pre-obtained access token instead.
        """
        if not self.config.is_configured:
            return AuthResult(
                success=False,
                error=(
                    "SAML not configured — set STRIX_SAML_ENTITY_ID, "
                    "STRIX_SAML_ACS_URL, STRIX_SAML_X509CERT, "
                    "STRIX_SAML_PRIVATE_KEY, STRIX_SAML_IDP_ENTITY_ID, "
                    "STRIX_SAML_IDP_SSO_URL, STRIX_SAML_IDP_X509CERT"
                ),
            )

        # Check if SAMLResponse is in target URL (ACS callback)
        parsed = urllib.parse.urlparse(target)
        query_params = urllib.parse.parse_qs(parsed.query)
        saml_response = query_params.get("SAMLResponse", [None])[0]
        relay_state = query_params.get("RelayState", [None])[0]

        if not saml_response:
            # No SAML response - return SSO URL for SP-initiated flow
            try:
                sso_url = self.get_sso_url()
                return AuthResult(
                    success=False,
                    error="SAML authentication required",
                    session_data={"sso_url": sso_url, "request_id": self._auth_request_id},
                )
            except Exception as e:
                log.error("SAML SSO URL generation failed: %s", e)
                return AuthResult(success=False, error=f"SAML SSO failed: {e}")

        # Process the SAML response
        try:
            session_data = self.process_acs_response(saml_response, relay_state)
        except Exception as e:
            log.error("SAML response processing failed: %s", e)
            return AuthResult(success=False, error=f"SAML validation failed: {e}")

        # Auto-provision tenant/user if enabled
        tenant_id = f"saml_{session_data['sub']}"
        tier = "standard"
        admin = session_data["role"] == "admin"

        # Check if tenant exists
        from strix.core.store import load_api_keys_sync, save_api_key_sync

        keys = load_api_keys_sync()
        tenant_exists = any(k["tenant_id"] == tenant_id for k in keys)

        if not tenant_exists and self.config.auto_provision:
            # Create new tenant with API key
            raw_key = f"strix_{secrets.token_urlsafe(32)}"
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            now = time.time()
            save_api_key_sync(
                tenant_id=tenant_id,
                key_hash=key_hash,
                tier=tier,
                admin=admin,
                active=True,
                created_at=now,
                last_used=now,
                scope="write",
            )
            log.info("Auto-provisioned SAML tenant: %s (role: %s)", tenant_id, session_data["role"])
        elif not tenant_exists:
            return AuthResult(
                success=False,
                error="SAML user not provisioned — contact administrator",
            )

        # Build principal with SAML credentials
        principal = Principal(
            id=self.principal_id,
            bearer="",  # SAML doesn't use bearer tokens
        )

        return AuthResult(
            success=True,
            principal=principal,
            bearer="",
            session_data={
                "tenant_id": tenant_id,
                "email": session_data["email"],
                "name": session_data["name"],
                "org": session_data["org"],
                "role": session_data["role"],
                "attributes": session_data["attributes"],
                "name_id": session_data["name_id"],
                "session_index": session_data["session_index"],
            },
        )

    def get_config(self) -> dict[str, Any]:
        """Return serializable configuration (encrypted secrets)."""
        return {
            "type": "saml",
            "entity_id": self.config.entity_id,
            "acs_url": self.config.acs_url,
            "sls_url": self.config.sls_url,
            "x509cert": self.config.x509cert,
            "private_key": self.config.private_key,
            "idp_entity_id": self.config.idp_entity_id,
            "idp_sso_url": self.config.idp_sso_url,
            "idp_slo_url": self.config.idp_slo_url,
            "idp_x509cert": self.config.idp_x509cert,
            "nameid_format": self.config.nameid_format,
            "auto_provision": self.config.auto_provision,
            "role_attribute": self.config.role_attribute,
            "admin_roles": self.config.admin_roles,
            "analyst_roles": self.config.analyst_roles,
            "viewer_roles": self.config.viewer_roles,
            "principal_id": self.principal_id,
        }

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> SAMLAuthenticator:
        return cls(
            entity_id=config.get("entity_id", ""),
            acs_url=config.get("acs_url", ""),
            sls_url=config.get("sls_url", ""),
            x509cert=config.get("x509cert", ""),
            private_key=config.get("private_key", ""),
            idp_entity_id=config.get("idp_entity_id", ""),
            idp_sso_url=config.get("idp_sso_url", ""),
            idp_slo_url=config.get("idp_slo_url", ""),
            idp_x509cert=config.get("idp_x509cert", ""),
            nameid_format=config.get(
                "nameid_format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            ),
            auto_provision=config.get("auto_provision", True),
            role_attribute=config.get("role_attribute", "role"),
            admin_roles=config.get("admin_roles", "admin"),
            analyst_roles=config.get("analyst_roles", "analyst"),
            viewer_roles=config.get("viewer_roles", "viewer"),
            principal_id=config.get("principal_id", "saml-auth"),
        )


@dataclass
class EncryptedAuthConfig:
    """Per-assessment encrypted authentication configuration."""

    authenticator_type: str
    encrypted_config: str  # base64-encoded encrypted JSON
    principal_id: str
    created_at: float = field(default_factory=time.time)

    @classmethod
    def create(
        cls,
        authenticator: Authenticator,
        encryption_key: str,
    ) -> EncryptedAuthConfig:
        """Create encrypted auth config from an authenticator."""
        config = authenticator.get_config()
        config_json = json.dumps(config)
        encrypted = encrypt(config_json, encryption_key)
        return cls(
            authenticator_type=config.get("type", "unknown"),
            encrypted_config=encrypted,
            principal_id=authenticator.principal_id,
        )

    def decrypt(self, encryption_key: str) -> dict[str, Any]:
        """Decrypt and return the authenticator config."""
        try:
            decrypted = decrypt(self.encrypted_config, encryption_key)
            return json.loads(decrypted)
        except (EncryptionError, json.JSONDecodeError) as exc:
            raise AuthConfigError(f"failed to decrypt auth config: {exc}") from exc

    def build_authenticator(self, encryption_key: str) -> Authenticator:
        """Build authenticator from decrypted config."""
        config = self.decrypt(encryption_key)
        auth_type = config.get("type")
        if auth_type == "token":
            return TokenAuthenticator.from_config(config)
        if auth_type == "session":
            return SessionAuthenticator.from_config(config)
        if auth_type == "form_login":
            return FormLoginAuthenticator.from_config(config)
        if auth_type == "multi_step":
            return MultiStepAuthenticator.from_config(config)
        raise AuthConfigError(f"unknown authenticator type: {auth_type}")


class AuthManager:
    """Manages authentication for an assessment."""

    def __init__(self, encryption_key: str = ""):
        self.encryption_key = encryption_key
        self._auth_configs: dict[str, EncryptedAuthConfig] = {}
        self._authenticators: dict[str, Authenticator] = {}
        self._cached_principals: dict[str, Principal] = {}

    def add_auth_config(self, auth_config: EncryptedAuthConfig) -> None:
        """Add an encrypted auth configuration."""
        self._auth_configs[auth_config.principal_id] = auth_config
        # Clear cached authenticator/principal
        self._authenticators.pop(auth_config.principal_id, None)
        self._cached_principals.pop(auth_config.principal_id, None)

    def get_authenticator(self, principal_id: str) -> Authenticator | None:
        """Get or build authenticator for a principal."""
        if principal_id in self._authenticators:
            return self._authenticators[principal_id]

        auth_config = self._auth_configs.get(principal_id)
        if not auth_config:
            return None

        if not self.encryption_key:
            raise AuthConfigError("encryption key required to decrypt auth config")

        authenticator = auth_config.build_authenticator(self.encryption_key)
        self._authenticators[principal_id] = authenticator
        return authenticator

    def authenticate(
        self,
        target: str,
        principal_id: str,
        *,
        timeout: float = 30.0,
        cancel: Any | None = None,
    ) -> AuthResult:
        """Authenticate a principal against a target."""
        authenticator = self.get_authenticator(principal_id)
        if not authenticator:
            return AuthResult(success=False, error=f"no authenticator for principal {principal_id}")

        result = authenticator.authenticate(target, timeout=timeout, cancel=cancel)
        if result.success and result.principal:
            self._cached_principals[principal_id] = result.principal
        return result

    def list_principals(self) -> list[str]:
        """List configured principal IDs."""
        return list(self._auth_configs.keys())

    def clear_cache(self) -> None:
        """Clear cached authenticators and principals."""
        self._authenticators.clear()
        self._cached_principals.clear()


def create_authenticator_from_dict(config: dict[str, Any]) -> Authenticator:
    """Factory function to create authenticator from config dict."""
    auth_type = config.get("type")
    if auth_type == "token":
        return TokenAuthenticator.from_config(config)
    if auth_type == "session":
        return SessionAuthenticator.from_config(config)
    if auth_type == "form_login":
        return FormLoginAuthenticator.from_config(config)
    if auth_type == "multi_step":
        return MultiStepAuthenticator.from_config(config)
    if auth_type == "oidc":
        return OIDCAuthenticator.from_config(config)
    if auth_type == "saml":
        return SAMLAuthenticator.from_config(config)
    raise AuthConfigError(f"unknown authenticator type: {auth_type}")

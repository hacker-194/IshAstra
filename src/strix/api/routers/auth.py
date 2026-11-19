"""SSO/OIDC/SAML Authentication Router for Strix Web UI.

Provides endpoints for OIDC and SAML authentication flows.
Local API keys are retained for automation and programmatic access.
Fail-closed when misconfigured.
"""

from __future__ import annotations

import logging
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from strix.api.deps import get_settings
from strix.api.security import api_keys
from strix.config import Settings
from strix.core.auth import generate_nonce, generate_pkce_pair, generate_state

log = logging.getLogger(__name__)

_STATE_TTL = 300  # 5 minutes
_NONCE_TTL = 300


@dataclass
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


# In-memory session store (use Redis in production multi-worker)
_oidc_sessions: dict[str, dict[str, Any]] = {}
_pkce_verifiers: dict[str, str] = {}  # state -> code_verifier|timestamp
_nonces: dict[str, float] = {}  # nonce -> timestamp


def _cleanup_expired() -> None:
    """Remove expired sessions and PKCE verifiers."""
    now = time.time()
    # Clean PKCE verifiers
    expired_states = [s for s, v in _pkce_verifiers.items() if now - float(v.split("|")[1]) > _STATE_TTL]
    for s in expired_states:
        _pkce_verifiers.pop(s, None)
    # Clean nonces
    expired_nonces = [n for n, t in _nonces.items() if now - t > _NONCE_TTL]
    for n in expired_nonces:
        _nonces.pop(n, None)


class OIDCProviderConfig(BaseModel):
    """OIDC Provider Configuration (from .well-known/openid-configuration)."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None
    end_session_endpoint: str | None = None


async def fetch_oidc_config(issuer: str) -> OIDCProviderConfig:
    """Fetch OIDC provider configuration from discovery endpoint."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{issuer.rstrip('/')}/.well-known/openid-configuration")
        resp.raise_for_status()
        return OIDCProviderConfig(**resp.json())


async def exchange_code_for_tokens(
    config: OIDCConfig,
    provider: OIDCProviderConfig,
    code: str,
    code_verifier: str,
) -> dict[str, Any]:
    """Exchange authorization code for tokens."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
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


async def fetch_userinfo(
    provider: OIDCProviderConfig,
    access_token: str,
) -> dict[str, Any]:
    """Fetch user info from OIDC provider."""
    if not provider.userinfo_endpoint:
        return {}
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            provider.userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()


async def validate_id_token(
    id_token: str,
    provider: OIDCProviderConfig,
    client_id: str,
    nonce: str | None,
) -> dict[str, Any]:
    """Validate ID token signature and claims."""
    # Fetch JWKS
    async with httpx.AsyncClient(timeout=10.0) as client:
        jwks_resp = await client.get(provider.jwks_uri)
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

    # Ensure we have a public key for validation
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

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


@dataclass
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


# In-memory SAML session store
_saml_sessions: dict[str, dict[str, Any]] = {}  # request_id -> session_data


router = APIRouter(prefix="/auth", tags=["auth"])


# =============================================================================
# OIDC Endpoints
# =============================================================================


@router.get("/oidc/login")
async def oidc_login(request: Request, settings: Settings = Depends(get_settings)):
    """Initiate OIDC Authorization Code flow with PKCE."""
    config = OIDCConfig.from_settings(settings)
    if not config.is_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "OIDC not configured — set STRIX_OIDC_ISSUER, "
                "STRIX_OIDC_CLIENT_ID, STRIX_OIDC_CLIENT_SECRET, "
                "STRIX_OIDC_REDIRECT_URI"
            ),
        )

    _cleanup_expired()

    # Generate PKCE pair
    code_verifier, code_challenge = generate_pkce_pair()
    state = generate_state()
    nonce = generate_nonce()

    # Store PKCE verifier with timestamp
    _pkce_verifiers[state] = f"{code_verifier}|{time.time()}"
    _nonces[nonce] = time.time()

    # Store state in session cookie
    session_id = secrets.token_urlsafe(16)
    _oidc_sessions[session_id] = {
        "state": state,
        "nonce": nonce,
        "created_at": time.time(),
    }

    # Fetch provider config
    try:
        provider = await fetch_oidc_config(config.issuer)
    except Exception as e:
        log.error("Failed to fetch OIDC config: %s", e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC provider unavailable",
        ) from e

    # Build authorization URL
    params = {
        "response_type": "code",
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "scope": config.scopes,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
    }
    auth_url = f"{provider.authorization_endpoint}?{urlencode(params)}"

    response = RedirectResponse(url=auth_url, status_code=302)
    response.set_cookie(
        key="oidc_session",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=_STATE_TTL,
        path="/",
    )
    return response


@router.get("/oidc/callback")
async def oidc_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    settings: Settings = Depends(get_settings),
):
    """Handle OIDC callback."""
    config = OIDCConfig.from_settings(settings)
    if not config.is_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC not configured",
        )

    # Check for OAuth error
    if error:
        log.warning("OIDC error: %s", error)
        return RedirectResponse(url="/?error=oidc_denied", status_code=302)

    if not code or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing code or state parameter",
        )

    # Retrieve session
    session_id = request.cookies.get("oidc_session")
    if not session_id or session_id not in _oidc_sessions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired session",
        )

    session = _oidc_sessions.pop(session_id)
    if session["state"] != state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="State mismatch",
        )

    # Get PKCE verifier
    pkce_data = _pkce_verifiers.pop(state, None)
    if not pkce_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="PKCE verifier not found",
        )
    code_verifier = pkce_data.split("|")[0]

    # Get nonce string from session (not the timestamp from _nonces)
    nonce_str = session.get("nonce")

    # Clean up the timestamp entry
    _nonces.pop(session["nonce"], None)

    # Fetch provider config
    try:
        provider = await fetch_oidc_config(config.issuer)
    except Exception as e:
        log.error("Failed to fetch OIDC config: %s", e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC provider unavailable",
        ) from e

    # Exchange code for tokens
    try:
        tokens = await exchange_code_for_tokens(config, provider, code, code_verifier)
    except httpx.HTTPStatusError as e:
        log.error("Token exchange failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token exchange failed",
        ) from e

    # Validate ID token
    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No ID token returned",
        )

    try:
        claims = await validate_id_token(id_token, provider, config.client_id, nonce_str)
    except Exception as e:
        log.error("ID token validation failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID token validation failed",
        ) from e

    # Extract user info
    email = claims.get("email")
    sub = claims.get("sub")

    if not email or not sub:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required claims (email, sub)",
        )

    # Find or create tenant/user
    tenant_id = f"oidc_{sub}"
    tier = "standard"

    # Check if tenant exists
    tenant_key = await api_keys.validate_async(f"tenant:{tenant_id}")
    if not tenant_key and config.auto_provision:
        # Create new tenant with API key
        raw_key = await api_keys.register_async(
            tenant_id=tenant_id,
            tier=tier,
            admin=False,
            scope="write",
        )
        tenant_key = await api_keys.validate_async(raw_key)
        if not tenant_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to provision tenant",
            )
    elif not tenant_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="OIDC user not provisioned — contact administrator",
        )

    # Create session token (simple approach: use the API key as session)
    assert tenant_key is not None
    session_token = tenant_key["record"]["key_hash"][:32]  # Use key hash prefix as session token

    # Set session cookie
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key="strix_session",
        value=session_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=3600,  # 1 hour
        path="/",
    )
    # Clear OIDC session cookie
    response.delete_cookie(key="oidc_session", path="/", secure=True, samesite="lax")

    return response


@router.post("/oidc/logout")
async def oidc_logout(request: Request, settings: Settings = Depends(get_settings)):
    """Logout - clear session cookie."""
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie(key="strix_session", path="/", secure=True, samesite="strict")
    # Optionally redirect to OIDC provider end_session_endpoint
    config = OIDCConfig.from_settings(settings)
    if config.is_configured:
        try:
            provider = await fetch_oidc_config(config.issuer)
            if provider.end_session_endpoint:
                params = {"post_logout_redirect_uri": "/"}
                response = RedirectResponse(
                    url=f"{provider.end_session_endpoint}?{urlencode(params)}",
                    status_code=302,
                )
        except Exception:
            pass  # Fall back to local logout
    return response


# =============================================================================
# SAML Endpoints
# =============================================================================


@router.get("/saml/login")
async def saml_login(request: Request, settings: Settings = Depends(get_settings)):
    """Initiate SAML SP-initiated SSO flow."""
    config = SAMLConfig.from_settings(settings)
    if not config.is_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "SAML not configured — set STRIX_SAML_ENTITY_ID, "
                "STRIX_SAML_ACS_URL, STRIX_SAML_X509CERT, "
                "STRIX_SAML_PRIVATE_KEY, STRIX_SAML_IDP_ENTITY_ID, "
                "STRIX_SAML_IDP_SSO_URL, STRIX_SAML_IDP_X509CERT"
            ),
        )

    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth

        class MockRequest:
            def __init__(self, acs_url):
                self.https = "on"
                self.http_host = urllib.parse.urlparse(acs_url).netloc
                self.server_port = 443
                self.script_name = ""
                self.get_data = {}
                self.post_data = {}
                self.query_string = ""

        request_obj = MockRequest(config.acs_url)
        saml_settings = _build_saml_settings(config)
        auth = OneLogin_Saml2_Auth(request_obj, saml_settings)
        sso_url = auth.login()
        request_id = auth.get_last_request_id()

        # Store request ID for validation
        _saml_sessions[request_id] = {
            "created_at": time.time(),
            "config": config,
        }

        return RedirectResponse(url=sso_url, status_code=302)

    except Exception as e:
        log.error("SAML login failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SAML login failed",
        ) from e


@router.post("/saml/acs")
async def saml_acs(
    request: Request,
    SAMLResponse: str | None = None,
    RelayState: str | None = None,
    settings: Settings = Depends(get_settings),
):
    """Handle SAML Assertion Consumer Service (ACS) callback."""
    config = SAMLConfig.from_settings(settings)
    if not config.is_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SAML not configured",
        )

    if not SAMLResponse:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing SAMLResponse parameter",
        )

    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth

        class MockRequest:
            def __init__(self, acs_url, saml_response):
                self.https = "on"
                self.http_host = urllib.parse.urlparse(acs_url).netloc
                self.server_port = 443
                self.script_name = ""
                self.get_data = {}
                self.post_data = {"SAMLResponse": saml_response}
                self.query_string = ""

        request_obj = MockRequest(config.acs_url, SAMLResponse)
        saml_settings = _build_saml_settings(config)
        auth = OneLogin_Saml2_Auth(request_obj, saml_settings)

        # Process the SAML response
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            log.error("SAML response validation errors: %s", errors)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"SAML validation failed: {', '.join(errors)}",
            )

        if not auth.is_authenticated():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="SAML authentication failed",
            )

        # Extract user attributes
        attributes = auth.get_attributes()
        name_id = auth.get_nameid()
        # Map role attribute to Strix role
        role_attr = config.role_attribute
        raw_roles = attributes.get(role_attr, [])
        if isinstance(raw_roles, str):
            raw_roles = [raw_roles]
        raw_roles = [r.lower() for r in raw_roles]

        admin_roles = [r.strip().lower() for r in config.admin_roles.split(",")]
        analyst_roles = [r.strip().lower() for r in config.analyst_roles.split(",")]

        strix_role = "viewer"  # default
        if any(r in admin_roles for r in raw_roles):
            strix_role = "admin"
        elif any(r in analyst_roles for r in raw_roles):
            strix_role = "analyst"

        # Use NameID as email/subject if available
        email = name_id or attributes.get("email", [""])[0] or attributes.get("mail", [""])[0]
        sub = attributes.get("sub", [name_id])[0] if name_id else email

        if not email or not sub:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing required attributes (email, subject) in SAML assertion",
            )

        # Find or create tenant/user
        tenant_id = f"saml_{sub}"
        tier = "standard"
        admin = strix_role == "admin"

        # Check if tenant exists
        tenant_key = await api_keys.validate_async(f"tenant:{tenant_id}")
        if not tenant_key and config.auto_provision:
            # Create new tenant with API key
            raw_key = await api_keys.register_async(
                tenant_id=tenant_id,
                tier=tier,
                admin=admin,
                scope="write",
            )
            tenant_key = await api_keys.validate_async(raw_key)
            if not tenant_key:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to provision tenant",
                )
        elif not tenant_key:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="SAML user not provisioned — contact administrator",
            )

        # Create session token
        assert tenant_key is not None
        session_token = tenant_key["record"]["key_hash"][:32]

        # Set session cookie
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key="strix_session",
            value=session_token,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=3600,  # 1 hour
            path="/",
        )
        return response

    except HTTPException:
        raise
    except Exception as e:
        log.error("SAML ACS processing failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SAML authentication failed",
        ) from e


@router.get("/saml/slo")
async def saml_slo(
    request: Request,
    SAMLRequest: str | None = None,
    SAMLResponse: str | None = None,
    settings: Settings = Depends(get_settings),
):
    """Handle SAML Single Logout (SLO)."""
    config = SAMLConfig.from_settings(settings)
    if not config.is_configured or not config.idp_slo_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SAML SLO not configured",
        )

    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth

        class MockRequest:
            def __init__(self, sls_url, saml_request=None, saml_response=None):
                self.https = "on"
                self.http_host = urllib.parse.urlparse(sls_url).netloc
                self.server_port = 443
                self.script_name = ""
                self.get_data = {}
                self.post_data = {}
                if saml_request:
                    self.get_data["SAMLRequest"] = saml_request
                if saml_response:
                    self.post_data["SAMLResponse"] = saml_response
                self.query_string = ""

        # Determine if this is a logout request from IdP or logout response
        if SAMLRequest:
            # IdP-initiated logout request
            request_obj = MockRequest(config.sls_url, saml_request=SAMLRequest)
            saml_settings = _build_saml_settings(config)
            auth = OneLogin_Saml2_Auth(request_obj, saml_settings)
            auth.process_slo()
            errors = auth.get_errors()
            if errors:
                log.error("SAML SLO errors: %s", errors)
            # Redirect to local logout
            return RedirectResponse(url="/auth/logout", status_code=302)
        if SAMLResponse:
            # Response to our SP-initiated logout
            request_obj = MockRequest(config.sls_url, saml_response=SAMLResponse)
            saml_settings = _build_saml_settings(config)
            auth = OneLogin_Saml2_Auth(request_obj, saml_settings)
            auth.process_slo()
            errors = auth.get_errors()
            if errors:
                log.error("SAML SLO response errors: %s", errors)
            # Redirect to home
            return RedirectResponse(url="/", status_code=302)
        # SP-initiated logout - redirect to IdP
        request_obj = MockRequest(config.sls_url)
        saml_settings = _build_saml_settings(config)
        auth = OneLogin_Saml2_Auth(request_obj, saml_settings)
        slo_url = auth.logout()
        return RedirectResponse(url=slo_url, status_code=302)

    except Exception as e:
        log.error("SAML SLO failed: %s", e)
        # Fall back to local logout
        return RedirectResponse(url="/auth/logout", status_code=302)


@router.post("/logout")
async def logout(request: Request):
    """Local logout - clear session cookie."""
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie(key="strix_session", path="/", secure=True, samesite="strict")
    return response


@router.get("/status")
async def auth_status(request: Request, settings: Settings = Depends(get_settings)):
    """Check authentication status."""
    # Check for session cookie
    session_cookie = request.cookies.get("strix_session")
    if session_cookie:
        # Validate session - check if it matches a known tenant key
        tenant = await api_keys.validate_async(session_cookie)
        if tenant:
            return {
                "authenticated": True,
                "tenant_id": tenant["tenant_id"],
                "tier": tenant["tier"],
                "role": tenant.get("role", "analyst"),
                "method": "oidc"
                if tenant["tenant_id"].startswith("oidc_")
                else ("saml" if tenant["tenant_id"].startswith("saml_") else "api_key"),
            }

    # Check for API key (Bearer token)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        api_key = auth_header[7:]
        tenant = await api_keys.validate_async(api_key)
        if tenant:
            return {
                "authenticated": True,
                "tenant_id": tenant["tenant_id"],
                "tier": tenant["tier"],
                "role": tenant.get("role", "analyst"),
                "method": "api_key",
            }

    oidc_config = OIDCConfig.from_settings(settings)
    saml_config = SAMLConfig.from_settings(settings)
    return {
        "authenticated": False,
        "oidc_configured": oidc_config.is_configured,
        "saml_configured": saml_config.is_configured,
    }


def _build_saml_settings(config: SAMLConfig) -> dict[str, Any]:
    """Build python3-saml settings dictionary."""
    if not config.is_configured:
        raise ValueError("SAML not configured")

    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": config.entity_id,
            "assertionConsumerService": {
                "url": config.acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": config.sls_url or config.acs_url.replace("/acs", "/sls"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": config.x509cert,
            "privateKey": config.private_key,
            "NameIDFormat": config.nameid_format,
        },
        "idp": {
            "entityId": config.idp_entity_id,
            "singleSignOnService": {
                "url": config.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": config.idp_slo_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            }
            if config.idp_slo_url
            else {},
            "x509cert": config.idp_x509cert,
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

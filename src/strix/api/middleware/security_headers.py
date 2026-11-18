"""
Security Headers Middleware for Strix API.

Implements comprehensive security headers per OWASP recommendations:
- Content Security Policy (CSP)
- HTTP Strict Transport Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy (COOP)
- Cross-Origin-Resource-Policy (CORP)
- Cross-Origin-Embedder-Policy (COEP)
"""

from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

log = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds security headers to all responses.

    Headers implemented:
    - Content-Security-Policy: Restricts resource loading to prevent XSS
    - Strict-Transport-Security: Enforces HTTPS
    - X-Frame-Options: Prevents clickjacking
    - X-Content-Type-Options: Prevents MIME sniffing
    - Referrer-Policy: Controls referrer information
    - Permissions-Policy: Controls browser features
    - Cross-Origin-Opener-Policy: Isolates browsing context
    - Cross-Origin-Resource-Policy: Controls resource sharing
    - Cross-Origin-Embedder-Policy: Requires explicit cross-origin permissions
    - Cache-Control: Prevents caching of sensitive data
    - X-Permitted-Cross-Domain-Policies: Controls Adobe Flash/PDF policies
    """

    def __init__(
        self,
        app,
        *,
        csp_policy: str | None = None,
        hsts_max_age: int = 31536000,
        hsts_include_subdomains: bool = True,
        hsts_preload: bool = True,
        frame_options: str = "DENY",
        referrer_policy: str = "strict-origin-when-cross-origin",
        permissions_policy: str | None = None,
        coop_policy: str = "same-origin",
        corp_policy: str = "same-origin",
        coep_policy: str = "require-corp",
        cache_control_authenticated: str = "no-store, no-cache, must-revalidate, private",
        cache_control_public: str = "public, max-age=3600",
        remove_server_header: bool = True,
    ) -> None:
        super().__init__(app)

        # Default CSP - restrictive but functional for Strix SPA
        self.csp_policy = csp_policy or (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "font-src 'self' data:; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "block-all-mixed-content; "
            "upgrade-insecure-requests"
        )

        self.hsts_max_age = hsts_max_age
        self.hsts_include_subdomains = hsts_include_subdomains
        self.hsts_preload = hsts_preload
        self.frame_options = frame_options
        self.referrer_policy = referrer_policy

        # Default permissions policy - disable unnecessary browser features
        self.permissions_policy = permissions_policy or (
            "accelerometer=(), "
            "autoplay=(), "
            "camera=(), "
            "clipboard-read=(), "
            "clipboard-write=(), "
            "encrypted-media=(), "
            "fullscreen=(self), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "microphone=(), "
            "midi=(), "
            "payment=(), "
            "picture-in-picture=(), "
            "publickey-credentials-get=(), "
            "screen-wake-lock=(), "
            "sync-xhr=(), "
            "usb=(), "
            "web-share=(), "
            "xr-spatial-tracking=()"
        )

        self.coop_policy = coop_policy
        self.corp_policy = corp_policy
        self.coep_policy = coep_policy
        self.cache_control_authenticated = cache_control_authenticated
        self.cache_control_public = cache_control_public
        self.remove_server_header = remove_server_header

    def _is_authenticated_request(self, request: Request) -> bool:
        """Check if request has authentication credentials."""
        auth_header = request.headers.get("Authorization", "")
        session_cookie = request.cookies.get("strix_session")
        csrf_cookie = request.cookies.get("strix_csrf")
        return bool(auth_header.startswith("Bearer ") or session_cookie or csrf_cookie)

    def _build_hsts_header(self) -> str:
        """Build HSTS header value."""
        parts = [f"max-age={self.hsts_max_age}"]
        if self.hsts_include_subdomains:
            parts.append("includeSubDomains")
        if self.hsts_preload:
            parts.append("preload")
        return "; ".join(parts)

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Content Security Policy
        response.headers["Content-Security-Policy"] = self.csp_policy

        # HTTP Strict Transport Security (only on HTTPS)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = self._build_hsts_header()

        # X-Frame-Options - prevent clickjacking
        response.headers["X-Frame-Options"] = self.frame_options

        # X-Content-Type-Options - prevent MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Referrer-Policy - control referrer information
        response.headers["Referrer-Policy"] = self.referrer_policy

        # Permissions-Policy - control browser features
        response.headers["Permissions-Policy"] = self.permissions_policy

        # Cross-Origin-Opener-Policy - isolate browsing context
        response.headers["Cross-Origin-Opener-Policy"] = self.coop_policy

        # Cross-Origin-Resource-Policy - control resource sharing
        response.headers["Cross-Origin-Resource-Policy"] = self.corp_policy

        # Cross-Origin-Embedder-Policy - require explicit cross-origin permissions
        response.headers["Cross-Origin-Embedder-Policy"] = self.coep_policy

        # X-Permitted-Cross-Domain-Policies - disable Adobe Flash/PDF cross-domain
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        # Cache-Control - prevent caching of sensitive authenticated responses
        if self._is_authenticated_request(request):
            response.headers["Cache-Control"] = self.cache_control_authenticated
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        elif request.url.path.startswith("/static/") or request.url.path in ("/", "/favicon.ico"):
            # Allow caching for static assets
            response.headers["Cache-Control"] = self.cache_control_public

        # Remove server header to avoid information disclosure
        if self.remove_server_header and "server" in response.headers:
            del response.headers["server"]

        # Remove X-Powered-By if present
        if "x-powered-by" in response.headers:
            del response.headers["x-powered-by"]

        return response


def create_security_headers_middleware(
    *,
    csp_policy: str | None = None,
    hsts_max_age: int = 31536000,
    hsts_include_subdomains: bool = True,
    hsts_preload: bool = True,
    frame_options: str = "DENY",
    referrer_policy: str = "strict-origin-when-cross-origin",
    permissions_policy: str | None = None,
    coop_policy: str = "same-origin",
    corp_policy: str = "same-origin",
    coep_policy: str = "require-corp",
    cache_control_authenticated: str = "no-store, no-cache, must-revalidate, private",
    cache_control_public: str = "public, max-age=3600",
    remove_server_header: bool = True,
):
    """
    Factory function to create SecurityHeadersMiddleware with custom configuration.

    Usage:
        app.add_middleware(
            SecurityHeadersMiddleware,
            csp_policy="default-src 'self'; script-src 'self'",
            hsts_max_age=31536000,
        )
    """

    def middleware_factory(app):
        return SecurityHeadersMiddleware(
            app,
            csp_policy=csp_policy,
            hsts_max_age=hsts_max_age,
            hsts_include_subdomains=hsts_include_subdomains,
            hsts_preload=hsts_preload,
            frame_options=frame_options,
            referrer_policy=referrer_policy,
            permissions_policy=permissions_policy,
            coop_policy=coop_policy,
            corp_policy=corp_policy,
            coep_policy=coep_policy,
            cache_control_authenticated=cache_control_authenticated,
            cache_control_public=cache_control_public,
            remove_server_header=remove_server_header,
        )

    return middleware_factory

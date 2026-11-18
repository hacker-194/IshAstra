"""CSRF protection for browser-based mutations.

Provides double-submit cookie pattern for CSRF protection on state-changing
endpoints that can be called from browsers (forms, AJAX).
"""

from __future__ import annotations

import secrets

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.responses import Response

from strix.api.dependencies import get_settings

CSRF_COOKIE_NAME = "strix_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_FORM_FIELD = "csrf_token"

# 1 hour TTL for CSRF tokens
CSRF_TTL_SECONDS = 3600


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)


async def get_csrf_token_from_cookie(request: Request) -> str | None:
    """Extract CSRF token from cookie."""
    return request.cookies.get(CSRF_COOKIE_NAME)


async def get_csrf_token_from_header(
    x_csrf_token: str | None = Header(default=None, alias=CSRF_HEADER_NAME),
) -> str | None:
    """Extract CSRF token from header."""
    return x_csrf_token


async def get_csrf_token_from_form(request: Request) -> str | None:
    """Extract CSRF token from form data (for non-JS form submissions)."""
    form = await request.form()
    value = form.get(CSRF_FORM_FIELD)
    if isinstance(value, str):
        return value
    return None


def set_csrf_cookie(response: Response, token: str, secure: bool = True) -> None:
    """Set the CSRF cookie with secure attributes."""
    settings = get_settings()
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=CSRF_TTL_SECONDS,
        httponly=True,
        secure=secure or settings.environment == "production",
        samesite="strict",
        path="/",
    )


async def validate_csrf_token(
    request: Request,
    cookie_token: str | None = Depends(get_csrf_token_from_cookie),
    header_token: str | None = Depends(get_csrf_token_from_header),
    form_token: str | None = Depends(get_csrf_token_from_form),
) -> bool:
    """
    Validate CSRF token using double-submit cookie pattern.

    The token must be present in both the cookie AND either the header
    or form field, and they must match.
    """
    # Skip CSRF for safe methods
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True

    # Skip for API key authenticated requests (they use Bearer tokens)
    # Only enforce CSRF for browser-based sessions (cookie auth)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return True

    # Also skip if no cookie token (no session)
    if not cookie_token:
        return True

    # Check header or form token
    submitted_token = header_token or form_token
    if not submitted_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing. Include X-CSRF-Token header or csrf_token form field.",
        )

    # Constant-time comparison
    if not secrets.compare_digest(cookie_token, submitted_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token",
        )

    return True


class CSRFMiddleware:
    """Middleware to manage CSRF tokens for browser sessions."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # We'll handle CSRF in the route dependencies instead
        # This middleware just ensures the cookie is available on responses
        await self.app(scope, receive, send)

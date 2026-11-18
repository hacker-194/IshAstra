"""Organization invitations.

An invitation is a signed, expiring token: nothing has to be stored for it to
be honoured, and revoking one is a matter of rotating the signing key. Delivery
uses SMTP from the standard library, so no extra dependency is involved.
"""

from __future__ import annotations

import smtplib
import time
from email.message import EmailMessage
from typing import Any

INVITE_TTL_SECONDS = 7 * 24 * 3600
TOKEN_TYPE = "org_invite"


class SMTPNotConfigured(RuntimeError):
    """Raised when STRIX_SMTP_HOST / STRIX_SMTP_FROM are missing."""


def create_invite_token(
    *,
    org_id: str,
    email: str,
    role: str,
    secret: str,
    team_id: str | None = None,
    ttl: int = INVITE_TTL_SECONDS,
    now: float | None = None,
) -> str:
    """Sign an invitation for ``email`` to join ``org_id`` with ``role``."""
    import jwt

    if not secret:
        raise ValueError("an invitation signing key is required")
    issued = int(now if now is not None else time.time())
    claims: dict[str, Any] = {
        "token_type": TOKEN_TYPE,
        "org_id": org_id,
        "email": email.strip().lower(),
        "role": role,
        "iat": issued,
        "exp": issued + int(ttl),
    }
    if team_id:
        claims["team_id"] = team_id
    return jwt.encode(claims, secret, algorithm="HS256")


def verify_invite_token(token: str, secret: str) -> dict[str, Any]:
    """Return the claims, or raise ValueError (expired, forged, wrong type)."""
    import jwt

    if not secret:
        raise ValueError("an invitation signing key is required")
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={"require": ["exp", "org_id", "email", "role"]},
        )
    except jwt.PyJWTError as exc:
        raise ValueError("invalid or expired invitation token") from exc
    if claims.get("token_type") != TOKEN_TYPE:
        raise ValueError("token is not an organization invitation")
    return claims


def build_invite_link(base_url: str, token: str) -> str:
    """Acceptance URL when a public base URL is configured, else the raw token."""
    base = (base_url or "").rstrip("/")
    return f"{base}/accept-invite?token={token}" if base else token


def render_invite_message(*, to: str, sender: str, org_name: str, role: str, link: str) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = f"You have been invited to {org_name} on Strix"
    message["From"] = sender
    message["To"] = to
    message.set_content(
        f"You have been invited to join {org_name} on Strix as {role}.\n\n"
        f"Accept the invitation:\n{link}\n\n"
        "If you did not expect this message, ignore it.\n"
    )
    return message


def send_invite_email(settings: Any, *, to: str, org_name: str, role: str, token: str) -> str:
    """Send the invitation. Returns the link that was delivered."""
    host = getattr(settings, "smtp_host", "")
    sender = getattr(settings, "smtp_from", "") or getattr(settings, "smtp_username", "")
    if not host or not sender:
        raise SMTPNotConfigured(
            "Email invitations need STRIX_SMTP_HOST and STRIX_SMTP_FROM; "
            "add members directly with POST /api/v2/orgs/{org_id}/members instead"
        )

    link = build_invite_link(getattr(settings, "public_base_url", ""), token)
    message = render_invite_message(to=to, sender=sender, org_name=org_name, role=role, link=link)

    port = int(getattr(settings, "smtp_port", 587) or 587)
    username = getattr(settings, "smtp_username", "")
    password = getattr(settings, "smtp_password", "")
    use_tls = bool(getattr(settings, "smtp_starttls", True))
    with smtplib.SMTP(host, port, timeout=15) as smtp:
        if use_tls:
            smtp.starttls()
        if username:
            smtp.login(username, password)
        smtp.send_message(message)
    return link

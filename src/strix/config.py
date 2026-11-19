"""Runtime configuration, read once from the environment.

Fail-closed: a value that would quietly change security behavior (unknown
scope mode, placeholder bootstrap key, unparsable trusted proxy, unknown log
format) raises at startup instead of being coerced into something plausible.
A bad integer falls back to its documented default -- it cannot widen access.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass

# Example values shipped in .env.example and documentation. A deployment that
# keeps one of these is protected by a published secret, so it must not start.
_PLACEHOLDER = re.compile(
    r"change[-_ ]?me|replace[-_ ]?me|your[-_ ]?(api[-_ ]?key|secret|token)|"
    r"placeholder|example|dummy|^secret$|^test$"
)

MIN_SECRET_LENGTH = 16
_LOG_FORMATS = frozenset({"text", "json"})
_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


def _int(name: str, default: int, *, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except ValueError:
        return default


def _csv(name: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.environ.get(name, "").split(",") if item.strip())


def _secret(name: str, value: str) -> str:
    """A bootstrap secret, or '' when unset; refuses weak/placeholder values."""
    if not value:
        return ""
    if len(value) < MIN_SECRET_LENGTH:
        raise ValueError(f"{name} must be at least {MIN_SECRET_LENGTH} characters")
    if _PLACEHOLDER.search(value.strip().lower()):
        raise ValueError(
            f"{name} still contains an example/placeholder value; generate a "
            "random secret (e.g. `openssl rand -base64 32`)"
        )
    return value


def _choice(name: str, value: str, allowed: frozenset[str], *, lower: bool) -> str:
    normalized = value.strip().lower() if lower else value.strip().upper()
    if normalized not in allowed:
        raise ValueError(f"{name} must be one of: {', '.join(sorted(allowed))}")
    return normalized


def _proxies(
    name: str, entries: tuple[str, ...]
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Trusted proxy addresses, as literal IPs or CIDR networks.

    Kept as networks: membership testing is the stdlib's job, so a /8 stays one
    object instead of being expanded into 16 million strings.
    """
    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(entry.strip(), strict=False))
        except ValueError:
            raise ValueError(
                f"{name} entries must be IP addresses or CIDR networks (got {entry!r})"
            ) from None
    return tuple(networks)


@dataclass(frozen=True)
class Settings:
    environment: str = "development"
    scope_file: str = "scope.json"
    # SQLite file path, or the PostgreSQL DSN when STRIX_DATABASE_URL is set.
    # Callers pass this straight to store.configure().
    db_path: str = "strix.db"
    # The PostgreSQL DSN as supplied (empty when SQLite is used).
    database_url: str = ""
    api_key: str = ""  # bootstrap admin key
    # Authorization operating mode: "global" (single organization, scope file),
    # "managed" (per-tenant engagement policies), or "auto" (managed as soon as
    # a policy exists in the database, global before that).
    scope_mode: str = "auto"
    # JWKS file with Ed25519 public keys for signed scope documents. When set,
    # only a document signed by one of those keys may load.
    scope_jwks: str = ""
    # How old a signed scope document may be, in seconds. A document older than
    # this is refused even though its signature verifies.
    scope_max_age: int = 86_400
    workers: int = 1
    queue_max: int = 32
    cors_origins: tuple[str, ...] = ()
    trusted_proxies: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    rate_limit_disabled: bool = False
    redis_required: bool = False
    disable_docs: bool = False
    debug: bool = False
    audit_max_entries: int = 10_000
    audit_hmac_key: str = ""
    webhook_secret: str = ""  # HMAC key for alert webhook signatures
    # Outbound email for organization invitations (SMTP, stdlib client).
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_starttls: bool = True
    # Used to build acceptance links in outgoing mail.
    public_base_url: str = ""
    # Encryption key for webhook secrets at rest (AES-GCM, 32 bytes base64).
    # If not set, webhook URLs are stored in plaintext (not recommended for production).
    encryption_key: str = ""
    # 0 disables retention: evidence is never deleted silently on upgrade. A
    # positive value prunes finished jobs/findings and plain audit entries that
    # old; the sealed audit chain is always kept in full.
    retention_days: int = 0
    max_body_bytes: int = 1_048_576
    max_nesting_depth: int = 10
    log_format: str = "text"
    log_level: str = "INFO"
    redis_url: str = "redis://localhost:6379/0"
    # Worker memory limit in MB (0 = disabled)
    worker_memory_mb: int = 1024
    # OIDC Configuration (for web UI SSO)
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""
    oidc_scopes: str = "openid email profile"
    oidc_auto_provision: bool = True

    # SAML Configuration (for enterprise SSO)
    saml_entity_id: str = ""
    saml_acs_url: str = ""
    saml_sls_url: str = ""
    saml_x509cert: str = ""
    saml_private_key: str = ""
    saml_idp_entity_id: str = ""
    saml_idp_sso_url: str = ""
    saml_idp_slo_url: str = ""
    saml_idp_x509cert: str = ""
    saml_nameid_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    saml_auto_provision: bool = True
    saml_role_attribute: str = "role"  # Attribute containing user role
    saml_admin_roles: str = "admin"  # Comma-separated list of roles that map to admin
    saml_analyst_roles: str = "analyst"  # Comma-separated list of roles that map to analyst
    saml_viewer_roles: str = "viewer"  # Comma-separated list of roles that map to viewer

    @classmethod
    def from_env(cls) -> Settings:
        environment = os.environ.get("STRIX_ENV", "development").strip().lower()
        if environment not in {"development", "test", "staging", "production"}:
            raise ValueError("STRIX_ENV must be one of: development, test, staging, production")
        scope_mode = os.environ.get("STRIX_SCOPE_MODE", "auto").strip().lower()
        if scope_mode not in {"auto", "global", "managed"}:
            raise ValueError("STRIX_SCOPE_MODE must be one of: auto, global, managed")
        database_url = os.environ.get("STRIX_DATABASE_URL", "").strip()
        api_key = _secret("STRIX_API_KEY", os.environ.get("STRIX_API_KEY", "").strip())
        encryption_key = _secret(
            "STRIX_ENCRYPTION_KEY",
            os.environ.get("STRIX_ENCRYPTION_KEY", "").strip(),
        )
        audit_hmac_key_b64 = os.environ.get("STRIX_AUDIT_HMAC_KEY", "").strip()
        audit_hmac_key = ""
        if audit_hmac_key_b64:
            import base64

            try:
                audit_hmac_key = base64.b64decode(audit_hmac_key_b64).decode()
            except Exception:
                audit_hmac_key = audit_hmac_key_b64  # fallback: treat as raw
            audit_hmac_key = _secret("STRIX_AUDIT_HMAC_KEY", audit_hmac_key)
        if environment == "production":
            missing = [
                name
                for name, value in (
                    ("STRIX_API_KEY", api_key),
                    ("STRIX_AUDIT_HMAC_KEY", audit_hmac_key),
                    ("STRIX_ENCRYPTION_KEY", encryption_key),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    "STRIX_ENV=production requires " + ", ".join(missing) + "; refusing to start without them"
                )
            from strix.crypto import EncryptionError, decode_key

            try:
                decode_key(encryption_key)
            except EncryptionError as exc:
                raise ValueError("STRIX_ENCRYPTION_KEY must be base64-encoded 32-byte key material") from exc
            if os.environ.get("STRIX_DEBUG", "").strip() == "1":
                raise ValueError("STRIX_DEBUG must be disabled in production")
            if os.environ.get("STRIX_RATE_LIMIT_DISABLED", "").strip() == "1":
                raise ValueError("STRIX_RATE_LIMIT_DISABLED must be disabled in production")
        docs_disabled = environment == "production" or os.environ.get(
            "STRIX_DISABLE_DOCS", ""
        ).strip().lower() in {"1", "true", "yes"}
        return cls(
            environment=environment,
            scope_file=os.environ.get("STRIX_SCOPE_FILE", "scope.json"),
            # PostgreSQL wins when configured; otherwise the SQLite file path.
            db_path=database_url or os.environ.get("STRIX_DB", "strix.db"),
            api_key=api_key,
            smtp_host=os.environ.get("STRIX_SMTP_HOST", "").strip(),
            smtp_port=int(os.environ.get("STRIX_SMTP_PORT", "587") or 587),
            smtp_username=os.environ.get("STRIX_SMTP_USERNAME", "").strip(),
            smtp_password=_secret("STRIX_SMTP_PASSWORD", os.environ.get("STRIX_SMTP_PASSWORD", "")),
            smtp_from=os.environ.get("STRIX_SMTP_FROM", "").strip(),
            smtp_starttls=os.environ.get("STRIX_SMTP_STARTTLS", "1").strip().lower() in {"1", "true", "yes"},
            public_base_url=os.environ.get("STRIX_PUBLIC_BASE_URL", "").strip().rstrip("/"),
            scope_mode=scope_mode,
            scope_jwks=os.environ.get("STRIX_SCOPE_JWKS", "").strip(),
            scope_max_age=_int("STRIX_SCOPE_MAX_AGE_SECONDS", 86_400),
            workers=_int("STRIX_WORKERS", 1),
            queue_max=_int("STRIX_QUEUE_MAX", 32),
            cors_origins=_csv("STRIX_CORS_ORIGINS"),
            trusted_proxies=_proxies("STRIX_TRUSTED_PROXIES", _csv("STRIX_TRUSTED_PROXIES")),
            rate_limit_disabled=os.environ.get("STRIX_RATE_LIMIT_DISABLED") == "1",
            redis_required=os.environ.get("STRIX_REDIS_REQUIRED") == "1",
            disable_docs=docs_disabled,
            debug=os.environ.get("STRIX_DEBUG", "").strip().lower() == "1",
            audit_max_entries=_int("STRIX_AUDIT_MAX_ENTRIES", 10_000),
            max_nesting_depth=_int("STRIX_MAX_NESTING_DEPTH", 10),
            audit_hmac_key=audit_hmac_key,
            webhook_secret=_secret(
                "STRIX_WEBHOOK_SECRET",
                os.environ.get("STRIX_WEBHOOK_SECRET", "").strip(),
            ),
            retention_days=_int("STRIX_RETENTION_DAYS", 0, minimum=0),
            max_body_bytes=_int("STRIX_MAX_BODY_BYTES", 1_048_576),
            log_format=_choice(
                "STRIX_LOG_FORMAT",
                os.environ.get("STRIX_LOG_FORMAT", "text"),
                _LOG_FORMATS,
                lower=True,
            ),
            log_level=_choice(
                "STRIX_LOG_LEVEL",
                os.environ.get("STRIX_LOG_LEVEL", "INFO"),
                _LOG_LEVELS,
                lower=False,
            ),
            redis_url=os.environ.get("STRIX_REDIS_URL", "redis://localhost:6379/0"),
            worker_memory_mb=_int("STRIX_WORKER_MEMORY_MB", 1024, minimum=0),
            database_url=database_url,
            encryption_key=encryption_key,
            oidc_issuer=os.environ.get("STRIX_OIDC_ISSUER", "").strip(),
            oidc_client_id=os.environ.get("STRIX_OIDC_CLIENT_ID", "").strip(),
            oidc_client_secret=_secret(
                "STRIX_OIDC_CLIENT_SECRET",
                os.environ.get("STRIX_OIDC_CLIENT_SECRET", "").strip(),
            ),
            oidc_redirect_uri=os.environ.get("STRIX_OIDC_REDIRECT_URI", "").strip(),
            oidc_scopes=os.environ.get("STRIX_OIDC_SCOPES", "openid email profile").strip(),
            oidc_auto_provision=os.environ.get("STRIX_OIDC_AUTO_PROVISION", "true").strip().lower()
            in {"1", "true", "yes"},
            # SAML Configuration
            saml_entity_id=os.environ.get("STRIX_SAML_ENTITY_ID", "").strip(),
            saml_acs_url=os.environ.get("STRIX_SAML_ACS_URL", "").strip(),
            saml_sls_url=os.environ.get("STRIX_SAML_SLS_URL", "").strip(),
            saml_x509cert=os.environ.get("STRIX_SAML_X509CERT", "").strip(),
            saml_private_key=os.environ.get("STRIX_SAML_PRIVATE_KEY", "").strip(),
            saml_idp_entity_id=os.environ.get("STRIX_SAML_IDP_ENTITY_ID", "").strip(),
            saml_idp_sso_url=os.environ.get("STRIX_SAML_IDP_SSO_URL", "").strip(),
            saml_idp_slo_url=os.environ.get("STRIX_SAML_IDP_SLO_URL", "").strip(),
            saml_idp_x509cert=os.environ.get("STRIX_SAML_IDP_X509CERT", "").strip(),
            saml_nameid_format=os.environ.get(
                "STRIX_SAML_NAMEID_FORMAT", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            ).strip(),
            saml_auto_provision=os.environ.get("STRIX_SAML_AUTO_PROVISION", "true").strip().lower()
            in {"1", "true", "yes"},
            saml_role_attribute=os.environ.get("STRIX_SAML_ROLE_ATTRIBUTE", "role").strip(),
            saml_admin_roles=os.environ.get("STRIX_SAML_ADMIN_ROLES", "admin").strip(),
            saml_analyst_roles=os.environ.get("STRIX_SAML_ANALYST_ROLES", "analyst").strip(),
            saml_viewer_roles=os.environ.get("STRIX_SAML_VIEWER_ROLES", "viewer").strip(),
        )


# The process settings, read from the environment once. Every subsystem uses
# get_settings() rather than calling Settings.from_env() itself: a second read
# would silently disagree with the object the API already handed out (different
# STRIX_DB, different audit HMAC key). reset_settings() exists for tests that
# change the environment between cases.
_settings: Settings | None = None


def get_settings() -> Settings:
    """The process settings, read from the environment on first use."""
    global _settings
    if _settings is None:
        _settings = Settings.from_env()
    return _settings


def reset_settings() -> None:
    """Drop the cached settings so the next get_settings() re-reads the environment."""
    global _settings
    _settings = None

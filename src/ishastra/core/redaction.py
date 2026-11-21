"""Secret protection: one place that knows what a secret looks like.

``redact`` recursively redacts JSON-shaped data; ``redact_query`` and
``sanitize_target`` remove sensitive query values and embedded user-info
credentials while keeping host and path, so a stored target still identifies
the asset; both are built on ``redact_text``. Replacement is one-way and left
as a labeled marker (``[REDACTED]``, ``[REDACTED_JWT]``) so an operator can
see a credential was present and rotate it. Non-sensitive parameters, hosts
and finding ids survive, so evidence stays reproducible.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode

from ishastra.core.urls import parse_url

REDACTED = "[REDACTED]"


CREDENTIAL = re.compile(
    r"\b(secret|password|passwd|pwd|pass|token|session|session_?id|sess|sid|jwt|"
    r"api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|oauth[_-]?token|"
    r"session[_-]?token|client[_-]?secret|auth[_-]?token|credential|credentials|"
    r"auth|authorization|signature|sig|mac|sas|otp)\b"
    r"(\s*['\"]?\s*[:=]\s*['\"]?)([^\s'\",;\\]+)",
    re.IGNORECASE,
)


_BEARER = re.compile(r"\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)


_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")


_AWS_KEY = re.compile(r"\bA[KS]IA[0-9A-Z]{16}\b")


_PEM_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z ]*PRIVATE KEY" r"(?: BLOCK)?-----|$)",
    re.DOTALL,
)


_GITHUB_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")


_GITLAB_TOKEN = re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")


_AZURE_SECRET = re.compile(
    r"\b[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\b"
    r"|[A-Za-z0-9+/]{88,}"
    r"|msal\.[A-Za-z0-9._-]{20,}",
    re.IGNORECASE,
)


_GCP_TOKEN = re.compile(
    r"\bya29\.[A-Za-z0-9._-]{20,}\b" r"|\bAIza[A-Za-z0-9_-]{35,39}\b" r"|\"type\":\s*\"service_account\""
)


_K8S_TOKEN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    r"|kubeconfig[_-]?token\s*[:=]\s*[A-Za-z0-9._-]{20,}"
    r"|kubeconfig[_-]?token[_\-][A-Za-z0-9._-]{20,}"
)


_AWS_SECRET_KEY = re.compile(r"\b[A-Za-z0-9+/=]{40,42}\b")


_FS_PATH = re.compile(
    r"(?:^|(?<=[\s\"'\(\[]))(?:/opt|/srv|/var|/etc|/home|/root|/tmp|/usr|/run)/[^\s\"'\",;\\]*",
    re.IGNORECASE,
)


_INTERNAL_HOST = re.compile(
    r"(?i)\b(?:[A-Za-z0-9_-]+\.)+(?:internal|local|localhost|lan|corp|home\.arpa|localdomain)\b"
)


_URL_USERINFO = re.compile(r'(?P<prefix>//|\b)(?P<user>[\w.+-]{1,64}):(?P<value>(?!\d+@)[^\s/@:"]{1,128})@')


def _userinfo_sub(text: str) -> str:
    return _URL_USERINFO.sub(lambda m: f"{m.group('prefix')}{m.group('user')}:{REDACTED}@", text)


_SIGNED_PARAM = re.compile(
    r"(?i)([?&](?:x-goog-signature|x-amz-signature|x-amz-credential|"
    r"sig|signature|mac|hash|token|access_token|refresh_token|id_token|oauth_token|"
    r"session_token|api_?key|apikey|"
    r"session_?id|sessionid|sid|sess|jwt|client_?secret|password|passwd|pwd|"
    r"private_?key|secret|auth|authorization|otp|sas|aws_access_key_id|"
    r"aws_session_token|x-amz-security-token|x-goog-security-token|code)=)([^&\s]*)"
)

_MAX_REDACT_INPUT = 10_485_760
_TRUNCATED = "\n[TRUNCATED: text exceeded the redaction limit]"


def redact_text(value: str) -> str:
    """Remove credential-shaped values from ``value``, keeping structure/ids.

    Oversized input is truncated to the redaction budget and marked, never
    returned unchanged: silently skipping redaction for a large string would
    leak exactly the secrets this module exists to remove (a dumped config, a
    multi-megabyte log line). Losing the tail is the documented trade-off.
    """
    if not value:
        return value
    truncated = len(value) > _MAX_REDACT_INPUT
    if truncated:
        value = value[:_MAX_REDACT_INPUT]
    out = _PEM_KEY.sub("[REDACTED_PRIVATE_KEY]", value)
    out = _JWT.sub("[REDACTED_JWT]", out)
    out = _AWS_KEY.sub("[REDACTED_AWS_KEY]", out)
    out = _AWS_SECRET_KEY.sub("[REDACTED_AWS_SECRET_KEY]", out)
    out = _GITHUB_TOKEN.sub("[REDACTED_GITHUB_TOKEN]", out)
    out = _GITLAB_TOKEN.sub("[REDACTED_GITLAB_TOKEN]", out)
    out = _AZURE_SECRET.sub("[REDACTED_AZURE_SECRET]", out)
    out = _GCP_TOKEN.sub("[REDACTED_GCP_TOKEN]", out)
    out = _K8S_TOKEN.sub("[REDACTED_K8S_TOKEN]", out)
    out = _INTERNAL_HOST.sub("[REDACTED_HOST]", out)
    out = _FS_PATH.sub(lambda m: REDACTED, out)
    out = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", out)
    out = _SIGNED_PARAM.sub(lambda m: f"{m.group(1)}{REDACTED}", out)
    out = _userinfo_sub(out)

    out = CREDENTIAL.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", out)
    return f"{out}{_TRUNCATED}" if truncated else out


_SENSITIVE_FIELDS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pass",
        "secret",
        "clientsecret",
        "privatekey",
        "token",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "oauthtoken",
        "sessiontoken",
        "session",
        "sessionid",
        "sess",
        "sid",
        "jwt",
        "credential",
        "credentials",
        "authorization",
        "proxyauthorization",
        "cookie",
        "setcookie",
        "apikey",
        "accesskey",
        "secretkey",
        "authtoken",
        "xapikey",
        "xaccesstoken",
        "xrefreshtoken",
        "xauthtoken",
        "xsessiontoken",
        "xclientsecret",
        "xamzcredential",
        "xamzsecuritytoken",
        "xamzsignature",
        "xgoogcredential",
        "xgoogsecuritytoken",
        "xgoogsignature",
        "awsaccesskeyid",
        "awssessiontoken",
    }
)


def _sensitive_field_name(name: Any) -> str:
    """Normalize JSON/header field names before comparing them with secret names."""
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def redact(value: Any) -> Any:
    """Recursively redact JSON, including secrets whose *field name* gives them away.

    Content-only redaction cannot recognize a response such as
    ``{"x-api-key": "short-secret"}`` because the value itself has no marker.
    Key-aware redaction closes that leak while retaining the useful attributes
    of Set-Cookie headers (cookie values are still removed).
    """
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, item in value.items():
            field_name = _sensitive_field_name(key)
            if field_name == "setcookie":
                if isinstance(item, list):
                    result[key] = [redact_cookie_value(v) if isinstance(v, str) else REDACTED for v in item]
                elif isinstance(item, str):
                    result[key] = redact_cookie_value(item)
                else:
                    result[key] = REDACTED
            elif field_name in _SENSITIVE_FIELDS:
                result[key] = REDACTED
            else:
                result[key] = redact(item)
        return result
    return value


def redact_query(url: str) -> str:
    """Redact the values of sensitive query parameters, keeping name and position.

    Non-sensitive parameters, the host, path and fragment are untouched, so a
    sanitized target still identifies the asset and reproduces the request.
    Unparseable input falls back to :func:`redact_text`.
    """
    parsed = parse_url(url)
    if parsed is None:
        return redact_text(url)
    if not parsed.query:
        return url
    try:
        params = parse_qsl(parsed.query, keep_blank_values=True)
        kept = [(name, REDACTED if _is_sensitive_param(name) else value) for name, value in params]
        return parsed._replace(query=urlencode(kept)).geturl()
    except ValueError:
        return redact_text(url)


def _is_sensitive_param(name: str) -> bool:
    bare = name.rsplit("[", 1)[0].strip().lower()
    return bare in _SENSITIVE_PARAMS


_SENSITIVE_PARAMS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pass",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "session_token",
        "api_key",
        "apikey",
        "api-key",
        "access_key",
        "secret_key",
        "private_key",
        "auth",
        "authorization",
        "authenticate",
        "auth_token",
        "oauth_token",
        "oauth_code",
        "code",
        "session",
        "sessionid",
        "session_id",
        "sess",
        "sid",
        "jwt",
        "sig",
        "signature",
        "mac",
        "hash",
        "sas",
        "otp",
        "credential",
        "credentials",
        "aws_access_key_id",
        "aws_session_token",
        "x-amz-signature",
        "x-goog-signature",
        "x-goog-credential",
        "x-amz-credential",
        "x-amz-security-token",
        "x-goog-security-token",
        "verify",
        "verification_code",
        "reset_token",
    }
)


def has_sensitive_query_params(url: str) -> bool:
    """Whether a URL query contains credential-like parameter names.

    Use this before storing long-lived monitoring/webhook destinations that
    must remain usable after restart. Such destinations are rejected rather
    than persisted with a redacted (and therefore nonfunctional) credential.
    """
    parsed = parse_url(url)
    if parsed is None:
        return redact_text(url) != url
    if not parsed.query:
        return False
    try:
        return any(_is_sensitive_param(name) for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
    except ValueError:
        return True


def sanitize_target(url: str) -> str:
    """The persistable form of a target URL: no credentials, no secrets in queries.

    Applied before a target reaches the database, an audit entry, the tamper-
    evident chain, an API response or an alert. The live assessment keeps using
    the original in-memory URL; only what is stored or exposed is sanitized.
    """
    if not isinstance(url, str) or not url:
        return url if isinstance(url, str) else ""
    return redact_query(_userinfo_sub(url))


def redact_cookie_value(header_value: str) -> str:
    """Redact the values of one Set-Cookie header (keep name and attributes).

    ``session=abc123; Path=/; Secure`` -> ``session=[REDACTED]; Path=/; Secure``.
    Cookie attributes carry the diagnostic value (flags); the value is the
    session material.
    """
    if not isinstance(header_value, str) or not header_value:
        return header_value
    first, _sep, attributes = header_value.partition(";")
    name, eq, _value = first.partition("=")
    if not eq:
        return header_value
    return f"{name}={REDACTED}" + (f";{attributes}" if attributes else "")

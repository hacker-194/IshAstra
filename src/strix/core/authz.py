"""Test principals and authorization-difference logic.

Credentials come from the scope document and live in memory only; raw values
never reach findings, the database or logs -- evidence refers to principals by
id and reports statuses and body-hash prefixes instead of bodies.

An endpoint is reported as an authorization problem only when the evidence
supports one: anonymous and authenticated callers get the same answer
(``authorization_missing``), or two principals received byte-identical object
data (a BOLA/IDOR indicator, labelled inferred). A 200/403 difference means the
endpoint does enforce authorization and is recorded as a note, not a finding.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl

from strix.core.urls import parse_url

_PRINCIPAL_ID = re.compile(r"[A-Za-z0-9_.-]{1,64}")
# Object-reference query parameters: id, order_id, user-id, orderId.
_ID_PARAM = re.compile(r"(?:[A-Za-z][A-Za-z0-9_]*[_-]?)?id", re.IGNORECASE)
_COOKIE_NAME = re.compile(r"[A-Za-z0-9_.!#$%&'*+\-^`|~]{1,128}")
_HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,128}")
_MAX_VALUE_LEN = 4096
_MAX_ENDPOINTS = 8
# Query parameters whose variation is part of the endpoint's function, not an
# object reference (pagination, formatting, filters).
_NON_OBJECT_PARAMS = frozenset(
    {
        "page",
        "per_page",
        "limit",
        "offset",
        "sort",
        "order",
        "format",
        "q",
        "search",
        "filter",
    }
)


def _clean_header_value(value: str) -> str:
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("credential values must not contain control characters")
    if len(value) > _MAX_VALUE_LEN:
        raise ValueError("credential value too long")
    return value


@dataclass(frozen=True)
class Principal:
    """One test identity: id plus the credentials attached to its requests."""

    id: str
    cookies: tuple[tuple[str, str], ...] = ()
    headers: tuple[tuple[str, str], ...] = ()
    bearer: str = ""

    def __post_init__(self) -> None:
        if not _PRINCIPAL_ID.fullmatch(self.id):
            raise ValueError(f"principal id {self.id!r} must match {_PRINCIPAL_ID.pattern}")
        for name, value in self.cookies:
            if not _COOKIE_NAME.fullmatch(name):
                raise ValueError(f"cookie name {name!r} is not a valid cookie name")
            _clean_header_value(value)
        for name, value in self.headers:
            if not _HEADER_NAME.fullmatch(name):
                raise ValueError(f"header name {name!r} is not a valid header name")
            _clean_header_value(value)
        if self.bearer:
            _clean_header_value(self.bearer)

    @property
    def has_credentials(self) -> bool:
        return bool(self.cookies or self.headers or self.bearer)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Principal:
        if not isinstance(data, dict) or not isinstance(data.get("id"), str):
            raise ValueError("auth user entry needs an id")
        cookies = []
        for raw in data.get("cookies", {}) or {}:
            if isinstance(raw, dict) and isinstance(raw.get("name"), str):
                cookies.append((raw["name"], str(raw.get("value", ""))))
            elif isinstance(raw, str):
                # "name=value" convenience form
                name, sep, value = raw.partition("=")
                if not sep:
                    raise ValueError(f"cookie entry {raw!r} must be name=value")
                cookies.append((name, value))
        headers = [(str(k), str(v)) for k, v in (data.get("headers", {}) or {}).items()]
        return cls(
            id=data["id"],
            cookies=tuple(cookies),
            headers=tuple(headers),
            bearer=str(data.get("bearer", "")),
        )


@dataclass(frozen=True)
class AuthConfig:
    """The engagement's test principals (in-memory only)."""

    users: tuple[Principal, ...] = ()

    def __post_init__(self) -> None:
        ids = [user.id for user in self.users]
        if len(ids) != len(set(ids)):
            raise ValueError("principal ids must be unique")
        if any(not user.has_credentials for user in self.users):
            raise ValueError("every principal needs at least one credential")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthConfig:
        if not isinstance(data, dict):
            raise ValueError("auth configuration must be an object")
        users_raw = data.get("users", [])
        if not isinstance(users_raw, list) or not users_raw:
            raise ValueError("auth.users must be a non-empty list")
        return cls(users=tuple(Principal.from_dict(item) for item in users_raw))

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(user.id for user in self.users)


def candidate_endpoints(urls: list[str], *, max_endpoints: int = _MAX_ENDPOINTS) -> list[str]:
    """URLs that look like object references worth testing for authorization.

    A candidate has a numeric path segment (``/api/orders/1001``) or an
    id-shaped query parameter (``?order_id=42``). Pagination and search
    parameters do not count. Order is stable and the list is capped.
    """
    candidates: list[str] = []
    for url in urls:
        parsed = parse_url(url)
        if parsed is None or parsed.scheme not in ("http", "https"):
            continue
        is_candidate = False
        for segment in parsed.path.split("/"):
            if segment.isdigit() and len(segment) <= 12:
                is_candidate = True
                break
        if not is_candidate and parsed.query:
            for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                if _ID_PARAM.fullmatch(name) and value.isdigit() and name.lower() not in _NON_OBJECT_PARAMS:
                    is_candidate = True
                    break
        if is_candidate:
            candidates.append(url)
        if len(candidates) >= max_endpoints:
            break
    return candidates


def body_digest(body: str) -> str:
    """Short digest for differential comparison — bodies are never stored."""
    return hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()[:16]


@dataclass(frozen=True)
class DifferentialResult:
    endpoint: str
    responses: tuple[tuple[str, int | str, str], ...]  # (principal, status, digest)
    anonymous_matches_first: bool = False
    principals_identical: bool = False

    def evidence_line(self) -> str:
        parts = [f"{pid}: HTTP {status} body={digest}" for pid, status, digest in self.responses]
        return "; ".join(parts)


def classify(differential: DifferentialResult) -> list[str]:
    """Categories the differential supports, in reporting order."""
    categories: list[str] = []
    if differential.anonymous_matches_first:
        categories.append("authorization_missing")
    if differential.principals_identical:
        categories.append("object_access_unscoped")
    return categories

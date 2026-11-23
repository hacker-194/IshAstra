"""Program scope and authorization gate.

The default is deny: without an authorization record and an explicit host
allowlist, nothing is contacted. ``check`` is the advisory gate scans use;
``destination`` is authoritative for connections -- it resolves, validates
every returned address and hands back the one IP to connect to, because
re-resolving later reopens DNS rebinding. Loopback, link-local, multicast,
private and other special-use addresses are refused unless
``authorized_networks`` names their network.

``configure()`` installs the global policy for single-organization
deployments; ``bound`` swaps in one engagement policy for one thread and one
job execution, so a tenant's job is never judged against another tenant's
authorization. ``load()`` is strict and atomic: a malformed document raises
``ValueError`` and leaves the previous valid policy installed -- never an
unrestricted one.

Schema versioning:
- v1: Legacy format (no version field, no revocation, no metadata)
- v2: Current format with version field, revocation support, expiration,
  metadata, and stricter validation via JSON Schema
"""

from __future__ import annotations

import asyncio
import contextvars
import ipaddress
import json
import logging
import os
import re
import socket
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from datetime import time as clock_time
from pathlib import Path
from typing import Any
from urllib.parse import ParseResult, urlparse

import jsonschema

from ishastra.core import scope_signing
from ishastra.core.authz import AuthConfig
from ishastra.core.collab import CollabConfig
from ishastra.core.urls import parse_url

log = logging.getLogger(__name__)


CURRENT_SCHEMA_VERSION = 2
MIN_SUPPORTED_VERSION = 1
MAX_SUPPORTED_VERSION = 2

# Python/platform matrix: supported versions and configurations
# This gates Phase 5 decisions on API backward compatibility
SUPPORTED_PYTHON_VERSIONS = ("3.10", "3.11", "3.12", "3.13")
SUPPORTED_PLATFORMS = ("linux-glibc", "linux-musl", "darwin")
ALPINE_MUSL_COMPATIBLE = True  # notes Alpine musl glibc considerations

# Rootless runtime availability
# Docker rootless / Podman rootless: noted for Phase 6 deployment considerations
ROOTLESS_RUNTIME_AVAILABLE = True  # verified: rootless Docker works on this host

# Scanner redistribution
# How IshAstra deals with scanner redistribution of findings:
# - Findings are deduped by (job_id, fingerprint) primary key
# - Scope gates apply at the gate layer before redistribution
# - Redistributed findings retain original scope authorization
SCANNER_REDISTRIBUTION_POLICY = "dedupe_by_fingerprint_with_scope_gate"


@dataclass(frozen=True)
class ValidationResult:
    """Detailed result of a scope validation check.

    Attributes:
        allowed: Whether the target is authorized (True) or denied (False).
        reason: Human-readable reason for the decision.
        denial_code: Machine-readable denial code (empty string if allowed).
        host: The target host that was validated (empty if invalid URL).
        port: The target port that was validated (None if not specified or invalid URL).
        resolved_ips: List of resolved IP addresses (empty if resolution failed or not performed).
    """

    allowed: bool
    reason: str
    denial_code: str = ""
    host: str = ""
    port: int | None = None
    resolved_ips: tuple[str, ...] = field(default=())


_pinned_destination: contextvars.ContextVar[Destination | None] = contextvars.ContextVar(
    "pinned_destination", default=None
)


def set_pinned_destination(dest: Destination) -> contextvars.Token[Destination | None]:
    """Pin the destination for the current task. Returns token for reset."""
    return _pinned_destination.set(dest)


def reset_pinned_destination(token: contextvars.Token[Destination | None]) -> None:
    """Reset the pinned destination."""
    _pinned_destination.reset(token)


def get_pinned_destination() -> Destination | None:
    """Get the pinned destination for the current task, if any."""
    return _pinned_destination.get(None)


INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")


RESOLVE_TIMEOUT = 3.0
MAX_CONCURRENT_RESOLUTIONS = 16


RESOLVE_BURST = 64
RESOLVE_REFILL_PER_SECOND = 64.0
_resolution_semaphore: asyncio.Semaphore | None = None
_host_buckets: dict[str, tuple[float, float]] = {}


_asn_lookup: Callable[[str], int | None] | None = None
_country_lookup: Callable[[str], str | None] | None = None
COUNTRY_CODE = re.compile(r"[A-Z]{2}")


def register_intel(
    *,
    asn: Callable[[str], int | None] | None = None,
    country: Callable[[str], str | None] | None = None,
) -> None:
    """Install the lookups ``allowed_asns`` and ``allowed_countries`` consult."""
    global _asn_lookup, _country_lookup
    _asn_lookup, _country_lookup = asn, country


SCOPE_INTEL_FILE_ENV = "ISHASTRA_SCOPE_INTEL_FILE"


def _prefix_table(entries: Any, kind: type, path: Path) -> list[tuple[Any, Any]]:
    """Validate ``{prefix: value}`` into a longest-prefix-first lookup table."""
    if not isinstance(entries, dict):
        raise ValueError(f"scope intel file {path}: each table must be a JSON object")
    table: list[tuple[Any, Any]] = []
    for prefix, value in entries.items():
        try:
            network = ipaddress.ip_network(str(prefix), strict=False)
        except ValueError:
            raise ValueError(f"scope intel file {path}: {prefix!r} is not a CIDR prefix") from None
        if kind is int:
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"scope intel file {path}: ASN for {prefix} must be a positive integer")
        else:
            value = str(value).strip().upper()
            if not COUNTRY_CODE.fullmatch(value):
                raise ValueError(f"scope intel file {path}: country for {prefix} must be ISO 3166-1 alpha-2")
        table.append((network, value))
    table.sort(key=lambda item: item[0].prefixlen, reverse=True)
    return table


def _provider(table: list[tuple[Any, Any]]) -> Callable[[str], Any]:
    """A lookup over ``table``; no matching prefix returns None (a denial)."""

    def lookup(raw: str) -> Any:
        try:
            address = ipaddress.ip_address(str(raw).split("%")[0])
        except ValueError:
            return None
        for network, value in table:
            if address.version == network.version and address in network:
                return value
        return None

    return lookup


def configure_intel_from_env() -> bool:
    """Install ASN/GeoIP lookups from ``ISHASTRA_SCOPE_INTEL_FILE``.

    The file is JSON such as
    ``{"asn": {"93.184.216.0/24": 15133}, "country": {"93.184.216.0/24": "US"}}``.
    Longest prefix wins. Returns False when no file is configured; a malformed
    file raises, because a half-loaded intel table would silently deny.
    """
    raw = os.environ.get(SCOPE_INTEL_FILE_ENV, "").strip()
    if not raw:
        return False
    path = Path(raw).expanduser()
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"scope intel file {path} is unreadable: {exc}") from None
    if not isinstance(data, dict):
        raise ValueError(f"scope intel file {path} must be a JSON object")
    asn_table = _prefix_table(data.get("asn", {}), int, path)
    country_table = _prefix_table(data.get("country", {}), str, path)
    register_intel(
        asn=_provider(asn_table) if asn_table else None,
        country=_provider(country_table) if country_table else None,
    )
    return True


SCOPE_JIT_URL_ENV = "ISHASTRA_SCOPE_JIT_URL"
SCOPE_JIT_TIMEOUT = 2.0


def jit_url() -> str:
    """The just-in-time authorization endpoint, empty when none is configured."""
    return os.environ.get(SCOPE_JIT_URL_ENV, "").strip()


async def _post_json(url: str, payload: dict[str, Any]) -> Any:
    """POST a decision request; tests replace this seam instead of calling out."""
    import httpx

    async with httpx.AsyncClient(timeout=SCOPE_JIT_TIMEOUT) as client:
        return await client.post(url, json=payload)


def _post_json_sync(url: str, payload: dict[str, Any]) -> Any:
    """Synchronous POST for the scan path; tests replace this seam."""
    import httpx

    with httpx.Client(timeout=SCOPE_JIT_TIMEOUT) as client:
        return client.post(url, json=payload)


def _jit_payload(scope: Scope, target: str, host: str, port: int | None) -> dict[str, Any]:
    """The decision input an OPA-style endpoint answers."""
    return {
        "input": {
            "target": target,
            "host": host,
            "port": port,
            "tenant": scope.tenant_id,
            "policy_id": scope.policy_id,
            "policy_version": scope.policy_version,
        }
    }


def _jit_verdict(response: Any) -> tuple[str, str]:
    """(denial, reason) for a decision-point answer; only an explicit allow passes."""
    try:
        if response.status_code != 200:
            return "policy_unavailable", f"authorization service answered HTTP {response.status_code}"
        body = response.json()
    except Exception as exc:
        return "policy_unavailable", f"authorization service unusable ({type(exc).__name__})"
    result = body.get("result") if isinstance(body, dict) else None
    if not isinstance(result, dict) or result.get("allow") is not True:
        return "out_of_scope", "authorization service did not allow this target"
    return "", ""


async def _jit_denial_async(scope: Scope, target: str, host: str, port: int | None) -> tuple[str, str]:
    """(denial, reason) from the decision point for async callers."""
    url = jit_url()
    if not url:
        return "", ""
    try:
        response = await _post_json(url, _jit_payload(scope, target, host, port))
    except Exception as exc:
        return "policy_unavailable", f"authorization service unavailable ({type(exc).__name__})"
    return _jit_verdict(response)


def _jit_denial(scope: Scope, target: str, host: str, port: int | None) -> tuple[str, str]:
    """(denial, reason) from the decision point for the synchronous scan path."""
    url = jit_url()
    if not url:
        return "", ""
    try:
        response = _post_json_sync(url, _jit_payload(scope, target, host, port))
    except Exception as exc:
        return "policy_unavailable", f"authorization service unavailable ({type(exc).__name__})"
    return _jit_verdict(response)


def _host_bucket_allow(host: str, *, now: float | None = None) -> bool:
    """True while ``host`` is under its resolution budget."""
    moment = time.monotonic() if now is None else now
    tokens, last = _host_buckets.get(host, (float(RESOLVE_BURST), moment))
    tokens = min(float(RESOLVE_BURST), tokens + (moment - last) * RESOLVE_REFILL_PER_SECOND)
    if tokens < 1.0:
        _host_buckets[host] = (tokens, moment)
        return False

    if len(_host_buckets) > 4096:
        _host_buckets.clear()
    _host_buckets[host] = (tokens - 1.0, moment)
    return True


async def resolve(host: str, port: int | None = None) -> list[str]:
    """Addresses for ``host``; empty list on failure, overload, or timeout.

    Uses a semaphore to bound concurrent resolutions and asyncio.wait_for
    for timeout enforcement. Runs the blocking getaddrinfo in a thread pool
    to avoid blocking the event loop.
    """
    global _resolution_semaphore
    if not _host_bucket_allow(host):
        return []
    if _resolution_semaphore is None:
        _resolution_semaphore = asyncio.Semaphore(MAX_CONCURRENT_RESOLUTIONS)

    async with _resolution_semaphore:
        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port or 443, proto=socket.IPPROTO_TCP),
                timeout=RESOLVE_TIMEOUT,
            )
            return [str(info[4][0]) for info in infos]
        except (OSError, UnicodeError, TimeoutError):
            return []


def resolve_sync(host: str, port: int | None = None) -> list[str]:
    """Synchronous version of resolve for use in sync contexts.

    Uses blocking socket.getaddrinfo directly with a timeout via
    socket.setdefaulttimeout. No daemon threads involved.
    """
    if not _host_bucket_allow(host):
        return []
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(RESOLVE_TIMEOUT)
        try:
            infos = socket.getaddrinfo(host, port or 443, proto=socket.IPPROTO_TCP)
            return [str(info[4][0]) for info in infos]
        finally:
            socket.setdefaulttimeout(old_timeout)
    except (OSError, UnicodeError):
        return []


_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIXTOFOUR = ipaddress.ip_network("2002::/16")

_TEREDO_SERVER = ipaddress.ip_network("2001:0000::/32")


def embedded_ipv4(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 transition address would reach, if it carries one.

    IPv4-mapped (``::ffff:a.b.c.d``), NAT64 (``64:ff9b::/96``), 6to4
    (``2002:aabb:ccdd::/48``) and Teredo (``2001::/32``, client address stored
    inverted and bit-flipped) all embed an IPv4 destination. A hostname that
    resolves to e.g. ``64:ff9b::a00:1`` looks public to ``is_global`` while a
    NAT64 gateway forwards it to 10.0.0.1, so the embedded address must be
    judged as well as the outer one. (The RFC 8215 local-use prefix
    ``64:ff9b:1::/48`` is not global in Python's tables, so its own prefix is
    enough to deny it.)

    For Teredo (RFC 4380), we validate the prefix is exactly 2001:0000::/32
    before extracting the client IPv4 from the last 32 bits (bitwise-negated).
    """
    if not isinstance(address, ipaddress.IPv6Address):
        return None
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    packed = address.packed
    if address in _NAT64:
        return ipaddress.IPv4Address(packed[12:16])
    if address in _SIXTOFOUR:
        return ipaddress.IPv4Address(packed[2:6])
    if address in _TEREDO_SERVER:
        return ipaddress.IPv4Address(bytes(byte ^ 0xFF for byte in packed[12:16]))
    return None


def is_special_use(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Loopback, link-local, multicast, private, reserved, unspecified, ULA.

    ``is_global`` alone misses some of these (multicast in particular), so each
    class is named. Anything special-use is denied unless a scope document
    explicitly authorizes its network.

    An IPv6 transition address is additionally judged by the IPv4 destination
    it embeds: ``64:ff9b::a00:1`` is globally scoped as a prefix but reaches
    10.0.0.1 through a NAT64 gateway.
    """
    if embedded_is_special_use(address):
        return True
    return bool(
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_private
        or address.is_reserved
        or getattr(address, "is_site_local", False)
        or not address.is_global
    )


def embedded_is_special_use(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Whether the IPv4 address an IPv6 transition address carries is special-use."""
    inner = embedded_ipv4(address)
    if inner is None:
        return False
    return is_special_use(inner)


_MAX_HOST = 253
_LABEL = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?")


_MIN_PREFIX = {4: 8, 6: 8}


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.split("%")[0])
    except ValueError:
        return False
    return True


def _host_pattern_error(pattern: str) -> str:
    """Why ``pattern`` is not an acceptable include/exclude entry ('' = fine)."""
    if not isinstance(pattern, str) or not pattern.strip():
        return "host entries must be non-empty strings"
    host = pattern.strip().lower().strip(".")
    if host.startswith("*."):
        host = host[2:]
    if not host:
        return f"host entry {pattern!r} has no name after the wildcard"
    if _is_ip_literal(host.split("%")[0]):
        return ""
    labels = host[:-1].split(".") if host.endswith(".") else host.split(".")
    if len(host) > _MAX_HOST or not all(_LABEL.fullmatch(label) for label in labels):
        return f"host entry {pattern!r} is not a valid DNS name (IDNs must be given as punycode)"
    return ""


def _pattern_covers(parent: str, child: str) -> bool:
    """True when every host ``child`` matches is also matched by ``parent``.

    Scope patterns are exact hosts or ``*.domain`` (subdomains only), so a
    wildcard parent covers an equal pattern and any host ending in its suffix.
    """
    if parent == child:
        return True
    return parent.startswith("*.") and child.endswith(parent[1:])


def _intersect_values(one: tuple[Any, ...], other: tuple[Any, ...], label: str) -> tuple[Any, ...]:
    """Values both policies allow; an empty list on either side means "any"."""
    if not one or not other:
        return one or other
    common = tuple(sorted(set(one) & set(other)))
    if not common:
        raise ValueError(f"inherited scope allows no {label}: the parent and child lists are disjoint")
    return common


def _intersect_ports(child: tuple[int, ...], parent: tuple[int, ...]) -> tuple[int, ...]:
    """Ports both scopes allow; an empty list on either side means "all"."""
    return _intersect_values(child, parent, "port")


def _nested_network(child: str, parent: str) -> str:
    """The narrower of two networks when one contains the other, else ''."""
    try:
        narrow = ipaddress.ip_network(child, strict=False)
        wide = ipaddress.ip_network(parent, strict=False)
    except ValueError:
        return ""
    if narrow.version != wide.version:
        return ""

    if isinstance(narrow, ipaddress.IPv4Network) and isinstance(wide, ipaddress.IPv4Network):
        if narrow.subnet_of(wide):
            return str(narrow)
        return str(wide) if wide.subnet_of(narrow) else ""
    if isinstance(narrow, ipaddress.IPv6Network) and isinstance(wide, ipaddress.IPv6Network):
        if narrow.subnet_of(wide):
            return str(narrow)
        return str(wide) if wide.subnet_of(narrow) else ""
    return ""


def _intersect_networks(child: tuple[str, ...], parent: tuple[str, ...]) -> tuple[str, ...]:
    """Networks both scopes authorize; an empty list authorizes no internal one."""
    if not child or not parent:
        return ()
    kept: list[str] = []
    for candidate in child:
        for allowed in parent:
            narrow = _nested_network(candidate, allowed)
            if narrow and narrow not in kept:
                kept.append(narrow)
    return tuple(kept)


def _earlier_expiry(*stamps: str) -> str:
    """The earliest of the given ISO 8601 timestamps ('' when none is set)."""
    parsed: list[datetime] = []
    for stamp in stamps:
        if not stamp:
            continue
        try:
            parsed.append(datetime.fromisoformat(str(stamp).replace("Z", "+00:00")))
        except ValueError:
            return str(stamp)
    return min(parsed).isoformat() if parsed else ""


def _ambiguous(url: str, parsed: ParseResult) -> str:
    """Reason a URL is refused because parsers could disagree about its host.

    Python reads ``http://evil.com\\@ok.com/`` as host ``ok.com``; browsers and
    most other clients treat the backslash as a path separator and connect to
    ``evil.com``. The raw string is handed to external tools, so any URL whose
    host depends on which parser reads it is refused rather than interpreted.
    """
    if any(ord(ch) <= 32 or ord(ch) == 127 for ch in url):
        return "target contains whitespace or control characters"
    if "\\" in url:
        return "target contains a backslash, which parsers read differently"
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return "target must not contain credentials"
    if "%" in parsed.netloc:
        return "target host must not be percent-encoded"
    host = parsed.hostname or ""
    if _is_ip_literal(host):
        return ""
    labels = host[:-1].split(".") if host.endswith(".") else host.split(".")
    if len(host) > _MAX_HOST or not all(_LABEL.fullmatch(label) for label in labels):
        return "target host is not a valid DNS name (IDNs must be given as punycode)"
    return ""


@dataclass(frozen=True)
class Destination:
    """The single address a connection is allowed to use."""

    scheme: str
    host: str
    port: int
    ip: str


@dataclass(frozen=True)
class Scope:
    """Validated authorization scope for a security assessment engagement.

    Attributes:
        program: Human-readable program/engagement name
        authorized_by: Name/title of the authorizing authority
        authorization_ref: External reference (contract, ticket, email)
        include: In-scope host patterns (wildcards cover subdomains only)
        exclude: Out-of-scope host patterns (takes precedence over include)
        authorized_networks: Explicitly authorized internal networks (CIDR)
        allowed_ports: Allowed TCP/UDP service ports (empty = all)
        auth: Optional test principals for authorization-difference testing
        collab: Optional out-of-band canary listener for blind SSRF
        policy_id: Engagement policy identifier (multi-tenant mode)
        policy_version: Policy version for audit trail
        tenant_id: Tenant identifier (multi-tenant mode)
        allow_broad_networks: Allow networks broader than /8 (dangerous)
        version: Schema version of the originating document
        revoked: Whether this scope has been revoked
        revoked_at: ISO 8601 timestamp of revocation
        revoked_by: Identity of party who revoked
        revocation_reason: Reason for revocation
        expires_at: ISO 8601 timestamp when scope expires
        metadata: Arbitrary metadata for tooling and audit trails
        rules_of_engagement: Rules of Engagement (testing_hours, rate_limit_rps, prohibited_techniques, etc.)
    """

    program: str
    authorized_by: str
    authorization_ref: str
    include: tuple[str, ...]
    exclude: tuple[str, ...] = field(default=())
    authorized_networks: tuple[str, ...] = field(default=())
    allowed_ports: tuple[int, ...] = field(default=())
    auth: AuthConfig | None = None
    collab: CollabConfig | None = None
    policy_id: str = ""
    policy_version: int = 0
    tenant_id: str = ""
    allow_broad_networks: bool = False
    allowed_asns: tuple[int, ...] = ()
    allowed_countries: tuple[str, ...] = ()
    rules_of_engagement: dict = field(default_factory=dict)

    version: int = CURRENT_SCHEMA_VERSION
    revoked: bool = False
    revoked_at: str = ""
    revoked_by: str = ""
    revocation_reason: str = ""
    expires_at: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        missing = [
            name
            for name in ("program", "authorized_by", "authorization_ref")
            if not str(getattr(self, name)).strip()
        ]
        if missing:
            raise ValueError(f"authorization record incomplete: missing {', '.join(missing)}")
        if not self.include:
            raise ValueError("scope has no in-scope hosts")
        for host in (*self.include, *self.exclude):
            complaint = _host_pattern_error(host)
            if complaint:
                raise ValueError(complaint)
        for network in self.authorized_networks:
            try:
                parsed_network = ipaddress.ip_network(network, strict=False)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"authorized_networks entry {network!r} is not a CIDR network") from exc
            if parsed_network.version == 6 and parsed_network.network_address.ipv4_mapped is not None:
                raise ValueError(
                    f"authorized_networks entry {network!r} is an IPv4-mapped IPv6 "
                    "network; authorize the IPv4 CIDR directly (e.g. 10.0.0.0/8)"
                )
            floor = _MIN_PREFIX[parsed_network.version]
            if parsed_network.prefixlen < floor and not self.allow_broad_networks:
                raise ValueError(
                    f"authorized_networks entry {network!r} covers more than a "
                    f"/{floor} (it is /{parsed_network.prefixlen}); refusing a "
                    "dangerously broad authorization — split the range or set "
                    "allow_broad_networks=true to override deliberately"
                )
        if any(
            not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
            for port in self.allowed_ports
        ):
            raise ValueError("allowed_ports entries must be integers from 1 to 65535")
        if any(not isinstance(asn, int) or isinstance(asn, bool) or asn < 1 for asn in self.allowed_asns):
            raise ValueError("allowed_asns entries must be positive AS numbers")
        if any(not COUNTRY_CODE.fullmatch(code) for code in self.allowed_countries):
            raise ValueError("allowed_countries entries must be ISO 3166-1 alpha-2 codes")

        if self.rules_of_engagement:
            self._validate_rules_of_engagement()

        if not MIN_SUPPORTED_VERSION <= self.version <= MAX_SUPPORTED_VERSION:
            raise ValueError(
                f"unsupported schema version {self.version}; "
                f"supported range: {MIN_SUPPORTED_VERSION}-{MAX_SUPPORTED_VERSION}"
            )

        if self.revoked:
            if not self.revoked_at:
                raise ValueError("revoked scope must have revoked_at timestamp")
            if not self.revoked_by:
                raise ValueError("revoked scope must have revoked_by identity")
            if not self.revocation_reason:
                raise ValueError("revoked scope must have revocation_reason")

            try:
                datetime.fromisoformat(self.revoked_at.replace("Z", "+00:00"))
            except ValueError:
                raise ValueError("revoked_at must be a valid ISO 8601 timestamp") from None

        if self.expires_at:
            try:
                datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            except ValueError:
                raise ValueError("expires_at must be a valid ISO 8601 timestamp") from None

    def is_revoked(self) -> bool:
        """Check if this scope has been revoked."""
        return self.revoked

    def is_expired(self, now: datetime | None = None) -> bool:
        """Check if this scope has expired.

        Args:
            now: Optional datetime to check against (default: UTC now)

        Returns:
            True if expires_at is set and in the past
        """
        if not self.expires_at:
            return False
        if now is None:
            now = datetime.now(UTC)
        try:
            expires = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            return now >= expires
        except ValueError:
            return False

    def is_valid(self, now: datetime | None = None) -> bool:
        """Check if this scope is valid (not revoked, not expired)."""
        return not self.is_revoked() and not self.is_expired(now)

    def _validate_rules_of_engagement(self) -> None:
        """Validate Rules of Engagement configuration."""
        roe = self.rules_of_engagement

        testing_hours = roe.get("testing_hours", "")
        if testing_hours and not isinstance(testing_hours, str):
            raise ValueError("rules_of_engagement.testing_hours must be a string")
        if testing_hours and self._parse_testing_hours(testing_hours) is None:
            raise ValueError(
                "rules_of_engagement.testing_hours must look like "
                "'HH:MM-HH:MM [UTC], Day-Day' (e.g. '09:00-18:00 UTC, Mon-Fri'); "
                f"got {testing_hours!r}"
            )

        rate_limit = roe.get("rate_limit_rps", 0)
        if rate_limit is not None and (
            not isinstance(rate_limit, int)
            or isinstance(rate_limit, bool)
            or rate_limit < 0
            or rate_limit > 1000
        ):
            raise ValueError("rules_of_engagement.rate_limit_rps must be an integer from 0 to 1000")

        prohibited = roe.get("prohibited_techniques", [])
        if prohibited and (
            not isinstance(prohibited, list) or not all(isinstance(t, str) for t in prohibited)
        ):
            raise ValueError("rules_of_engagement.prohibited_techniques must be a list of strings")

        notifications = roe.get("required_notifications", [])
        if notifications and (
            not isinstance(notifications, list) or not all(isinstance(n, str) for n in notifications)
        ):
            raise ValueError("rules_of_engagement.required_notifications must be a list of strings")

        high_risk = roe.get("high_risk_allowed")
        if high_risk is not None and not isinstance(high_risk, bool):
            raise ValueError("rules_of_engagement.high_risk_allowed must be a boolean")

        data_handling = roe.get("data_handling", {})
        if data_handling and not isinstance(data_handling, dict):
            raise ValueError("rules_of_engagement.data_handling must be an object")

        valid_pii_values = ("prohibited", "restricted", "allowed")
        valid_cred_values = ("prohibited", "restricted", "allowed")
        if data_handling:
            pii_access = data_handling.get("pii_access")
            if pii_access and pii_access not in valid_pii_values:
                raise ValueError(
                    f"rules_of_engagement.data_handling.pii_access must be one of {valid_pii_values}"
                )
            cred_access = data_handling.get("credential_access")
            if cred_access and cred_access not in valid_cred_values:
                raise ValueError(
                    f"rules_of_engagement.data_handling.credential_access must be one of {valid_cred_values}"
                )
            retention = data_handling.get("evidence_retention_days")
            if retention is not None and (
                not isinstance(retention, int) or retention < 1 or retention > 3650
            ):
                raise ValueError(
                    "rules_of_engagement.data_handling.evidence_retention_days "
                    "must be an integer from 1 to 3650"
                )

    def _enforce_rules_of_engagement(self) -> tuple[str, str]:
        """Enforce Rules of Engagement during gate checks.

        Returns:
            (denial_code, reason) - empty strings if allowed, denial code and reason if denied.
        """

        roe = self.rules_of_engagement
        if not roe:
            return "", ""

        testing_hours = roe.get("testing_hours", "")
        if testing_hours and not self._is_within_testing_hours(testing_hours):
            return "roe_violation", f"Testing outside authorized hours: {testing_hours}"

        return "", ""

    _TIME_OF_DAY = re.compile(r"(?P<hour>\d{2}):(?P<minute>\d{2})")
    _TIME_RANGE = re.compile(
        r"^(?P<start>\d{2}:\d{2})\s*-\s*(?P<end>\d{2}:\d{2})(?:\s+(?P<tz>[A-Za-z][A-Za-z0-9_+/-]*))?$"
    )
    _DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")

    @classmethod
    def _parse_testing_hours(cls, testing_hours: str) -> tuple[clock_time, clock_time, str] | None:
        """Parse 'HH:MM-HH:MM [UTC], Day-Day' into (start, end, days).

        Returns None for anything this module cannot enforce exactly, so callers
        can reject the schedule instead of guessing. Only UTC (or an omitted
        zone) is accepted: silently treating '09:00-18:00 America/New_York' as
        UTC would authorize the wrong window. Overnight ranges are supported.
        """
        if not isinstance(testing_hours, str) or not testing_hours.strip():
            return None
        time_part, _, days_part = testing_hours.partition(",")
        if "," in days_part:
            return None
        match = cls._TIME_RANGE.match(time_part.strip())
        if not match:
            return None
        if (match.group("tz") or "UTC").strip().upper() not in (
            "UTC",
            "Z",
            "GMT",
        ):
            return None
        try:
            start = datetime.strptime(match.group("start"), "%H:%M").time()
            end = datetime.strptime(match.group("end"), "%H:%M").time()
        except ValueError:
            return None
        days = days_part.strip()
        if days and cls._parse_day_ranges(days) is None:
            return None
        return start, end, days

    @classmethod
    def _parse_day_ranges(cls, days_spec: str) -> list[tuple[int, int]] | None:
        """Parse 'Mon-Fri,Sun' into inclusive index ranges, or None if invalid."""
        ranges: list[tuple[int, int]] = []
        for part in days_spec.split(","):
            part = part.strip()
            if not part:
                return None
            if "-" in part:
                first, _, last = part.partition("-")
                starts = [d for d in cls._DAYS if d.lower() == first.strip().lower()[:3]]
                ends = [d for d in cls._DAYS if d.lower() == last.strip().lower()[:3]]
                if not starts or not ends:
                    return None
                ranges.append((cls._DAYS.index(starts[0]), cls._DAYS.index(ends[0])))
            else:
                matches = [d for d in cls._DAYS if d.lower() == part.lower()[:3]]
                if not matches:
                    return None
                index = cls._DAYS.index(matches[0])
                ranges.append((index, index))
        return ranges

    def _is_within_testing_hours(self, testing_hours: str) -> bool:
        """Whether now is inside the authorized testing window.

        Fails closed: a schedule that cannot be parsed exactly (or whose
        construction bypassed validation) denies the scan rather than allowing
        it. Denying is the only safe default for an authorization control.
        """
        parsed = self._parse_testing_hours(testing_hours)
        if parsed is None:
            log.error("Unenforceable testing_hours %r; denying scan", testing_hours)
            return False
        start, end, days = parsed
        now = datetime.now(UTC)
        if days:
            ranges = self._parse_day_ranges(days)
            if not ranges:
                log.error("Unparseable testing days %r; denying scan", days)
                return False
            today = now.weekday()  # Mon=0 .. Sun=6, matching _DAYS
            allowed = any(
                (first <= today <= last) if first <= last else (today >= first or today <= last)
                for first, last in ranges
            )
            if not allowed:
                return False
        current = now.time()
        if start <= end:
            return start <= current <= end
        return current >= start or current <= end

    def _listed(self, host: str, patterns: tuple[str, ...]) -> bool:
        host = host.strip().lower().strip(".")
        for pattern in patterns:
            pattern = pattern.strip().lower().strip(".")
            if pattern.startswith("*."):
                if host.endswith(pattern[1:]) and host != pattern[2:]:
                    return True
            elif host == pattern:
                return True
        return False

    def _networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(net, strict=False) for net in self.authorized_networks]

    def _gate(self, url: str) -> tuple[str, str, str, int | None]:
        """(denial, reason, host, port) from the URL alone."""
        parsed = parse_url(url)
        if parsed is None or parsed.scheme not in ("http", "https") or not parsed.hostname:
            return "invalid_target", "target must be an absolute http(s) URL", "", None
        if ".." in url:
            return "invalid_target", "target contains a traversal sequence", "", None
        ambiguity = _ambiguous(url, parsed)
        if ambiguity:
            return "invalid_target", ambiguity, "", None
        host = parsed.hostname.lower()
        if self._listed(host, self.exclude):
            return (
                "out_of_scope",
                f"{host} is explicitly out of scope",
                host,
                parsed.port,
            )
        if not self._listed(host, self.include):
            return (
                "out_of_scope",
                f"{host} is not in the authorized scope",
                host,
                parsed.port,
            )
        effective_port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if effective_port < 1:
            return (
                "invalid_target",
                "port 0 is not a connectable service port",
                host,
                parsed.port,
            )
        if self.allowed_ports and effective_port not in self.allowed_ports:
            return (
                "out_of_scope",
                f"port {effective_port} is not in the authorized port scope",
                host,
                parsed.port,
            )
        roe_denial, roe_reason = self._enforce_rules_of_engagement()
        if roe_denial:
            return roe_denial, roe_reason, host, parsed.port
        return "", "", host, parsed.port

    def _judge_addresses(
        self, host: str, addresses: list[str], *, fail_on_empty: bool = True
    ) -> tuple[str, str]:
        """(denial, reason) for a resolution result; every address must pass.

        Shared by the sync and async entry points so the policy exists once.
        ``authorized_networks`` is an exhaustive allowlist when non-empty: an
        address outside it is refused even when it is public. With no networks
        configured (legacy) public addresses pass and only special-use ones are
        refused.
        """
        if not addresses:
            if host == "localhost" or host.endswith(INTERNAL_SUFFIXES):
                return "out_of_scope", f"{host} is an internal host name"
            if fail_on_empty:
                return "resolution_failed", f"cannot resolve {host} (timeout or overload)"
            return "", ""
        networks = self._networks()
        for value in addresses:
            address = ipaddress.ip_address(value.split("%")[0])
            intel_denial = self._judge_intel(address, value, host)
            if intel_denial is not None:
                return intel_denial
            if networks:
                if any(address in network for network in networks):
                    continue
            elif not is_special_use(address):
                continue
            if is_special_use(address):
                if host == str(address):
                    return "out_of_scope", f"{address} is a non-public address"
                return "out_of_scope", f"{host} resolves to non-public address {address}"
            return (
                "out_of_scope",
                f"{host} resolves to address {address} not in authorized networks",
            )
        return "", ""

    def _judge_intel(self, address: Any, raw: str, host: str) -> tuple[str, str] | None:
        """(denial, reason) when ASN or country policy refuses ``address``.

        Fail closed: a policy that is set without a usable data source, or an
        address the source has no answer for, is refused rather than allowed.
        """
        if self.allowed_asns:
            if _asn_lookup is None:
                return (
                    "policy_unavailable",
                    f"allowed_asns is set but no ASN lookup is configured (refusing {host})",
                )
            try:
                asn = _asn_lookup(raw)
            except Exception:
                asn = None
            if asn is None:
                return ("policy_unavailable", f"no ASN data for {address} (refusing {host})")
            if asn not in self.allowed_asns:
                return ("out_of_scope", f"{host} is announced by AS{asn}, which is not authorized")
        if self.allowed_countries:
            if _country_lookup is None:
                return (
                    "policy_unavailable",
                    f"allowed_countries is set but no country lookup is configured (refusing {host})",
                )
            try:
                country = _country_lookup(raw)
            except Exception:
                country = None
            if not country:
                return ("policy_unavailable", f"no country data for {address} (refusing {host})")
            if str(country).upper() not in self.allowed_countries:
                return (
                    "out_of_scope",
                    f"{host} is geolocated to {str(country).upper()}, which is not authorized",
                )
        return None

    def _authorize_sync(
        self, host: str, port: int | None, *, fail_on_empty: bool = True
    ) -> tuple[str, str, list[str]]:
        """(denial, reason, addresses) for a fresh synchronous resolution."""
        addresses = resolve_sync(host, port)
        denial, reason = self._judge_addresses(host, addresses, fail_on_empty=fail_on_empty)
        return denial, reason, addresses

    async def _authorize(
        self, host: str, port: int | None, *, fail_on_empty: bool = True
    ) -> tuple[str, str, list[str]]:
        """(denial, reason, addresses) for a fresh asynchronous resolution."""
        addresses = await resolve(host, port)
        denial, reason = self._judge_addresses(host, addresses, fail_on_empty=fail_on_empty)
        return denial, reason, addresses

    def inherited_from(self, base: Scope) -> Scope:
        """This scope narrowed by ``base``; never broadens either one.

        ``include`` keeps only patterns ``base`` also covers, ``exclude`` takes
        the union, ports and authorized networks intersect, and the earlier
        expiry wins. Raises ``ValueError`` when the intersection is empty: an
        empty include or port list means "everything", which an inherited scope
        must never produce.
        """
        include = tuple(p for p in self.include if any(_pattern_covers(b, p) for b in base.include))
        if not include:
            raise ValueError(
                "inherited scope allows no host: no in-scope pattern is covered by the parent policy"
            )
        revoked = base.revoked or self.revoked
        source = base if base.revoked else self
        return replace(
            self,
            include=include,
            exclude=tuple(dict.fromkeys((*base.exclude, *self.exclude))),
            allowed_ports=_intersect_ports(self.allowed_ports, base.allowed_ports),
            authorized_networks=_intersect_networks(self.authorized_networks, base.authorized_networks),
            allowed_asns=_intersect_values(self.allowed_asns, base.allowed_asns, "ASN"),
            allowed_countries=_intersect_values(self.allowed_countries, base.allowed_countries, "country"),
            allow_broad_networks=base.allow_broad_networks and self.allow_broad_networks,
            revoked=revoked,
            revoked_at=source.revoked_at,
            revoked_by=source.revoked_by,
            revocation_reason=source.revocation_reason,
            expires_at=_earlier_expiry(self.expires_at, base.expires_at),
        )

    def diff(self, other: Scope) -> dict[str, dict[str, list[Any]]]:
        """What ``other`` adds and removes relative to this scope.

        Reviewers read this before a policy change is applied: each of the four
        authorization lists is reported as sorted ``added``/``removed`` entries,
        both empty meaning that list is unchanged.
        """

        def _change(mine: tuple[Any, ...], theirs: tuple[Any, ...]) -> dict[str, list[Any]]:
            added = set(theirs) - set(mine)
            removed = set(mine) - set(theirs)
            return {"added": sorted(added), "removed": sorted(removed)}

        return {
            "include": _change(self.include, other.include),
            "exclude": _change(self.exclude, other.exclude),
            "allowed_ports": _change(self.allowed_ports, other.allowed_ports),
            "authorized_networks": _change(self.authorized_networks, other.authorized_networks),
            "allowed_asns": _change(self.allowed_asns, other.allowed_asns),
            "allowed_countries": _change(self.allowed_countries, other.allowed_countries),
        }

    def gate(self, url: str) -> tuple[str, str]:
        """(denial, reason) judged from the URL alone, without DNS.

        Offline verifiers use this: whether a recorded action matched the
        authorization, independent of what DNS answers today.
        """
        with _gate_span("url") as span:
            denial, reason, _host, _port = self._gate(url)
            _annotate_span(span, self, denial)
        return denial, reason

    def _record_decision(self, denial: str, elapsed: float) -> None:
        """Record decision count and latency (never affects the verdict)."""
        from ishastra import metrics

        metrics.record_scope_decision(
            "blocked" if denial else "allowed",
            denial or "allowed",
            self.tenant_id or "global",
        )
        metrics.observe_scope_decision("blocked" if denial else "allowed", elapsed)

    def check(self, url: str) -> tuple[str, str]:
        """Return ("", "") when the target may be contacted, else (denial, reason)."""
        started = time.perf_counter()
        with _gate_span("address") as span:
            denial, reason = self._check(url)
            _annotate_span(span, self, denial)
        self._record_decision(denial, time.perf_counter() - started)
        return denial, reason

    def _check(self, url: str) -> tuple[str, str]:

        if not self.is_valid():
            if self.is_revoked():
                return "revoked", f"scope revoked: {self.revocation_reason}"
            return "expired", "scope document has expired"
        denial, reason, host, port = self._gate(url)
        if denial:
            return denial, reason
        denial, reason, _addresses = self._authorize_sync(host, port, fail_on_empty=False)
        return denial, reason

    def destination(self, url: str) -> tuple[str, str, Destination | None]:
        """Authoritative pre-connect validation (sync).

        The caller MUST connect to the returned :class:`Destination` and to
        nothing else: connecting anywhere else re-resolves the name and reopens
        DNS rebinding between validation and use.

        The resolved IP is pinned to the current task ContextVar;
        connecting to any other address re-raises as a rebinding risk.
        """
        started = time.perf_counter()
        with _gate_span("address") as span:
            denial, reason, dest = self._destination(url)
            if dest is not None:
                _pinned_destination.set(dest)
            _annotate_span(span, self, denial)
        self._record_decision(denial, time.perf_counter() - started)
        return denial, reason, dest

    def _destination(self, url: str) -> tuple[str, str, Destination | None]:

        if not self.is_valid():
            if self.is_revoked():
                return "revoked", f"scope revoked: {self.revocation_reason}", None
            return "expired", "scope document has expired", None
        denial, reason, host, port = self._gate(url)
        if denial:
            return denial, reason, None
        denial, reason, addresses = self._authorize_sync(host, port)
        if denial:
            return denial, reason, None
        if not addresses:
            return "resolution_failed", f"cannot resolve {host}", None
        scheme = (parse_url(url) or urlparse(url)).scheme
        connect_port = port if port is not None else (443 if scheme == "https" else 80)
        jit_denial, jit_reason = _jit_denial(self, url, host, connect_port)
        if jit_denial:
            return jit_denial, jit_reason, None
        return (
            "",
            "",
            Destination(scheme=scheme, host=host, port=connect_port, ip=addresses[0]),
        )

    async def destination_async(self, url: str) -> tuple[str, str, Destination | None]:
        """Async version of destination for use in async contexts."""
        started = time.perf_counter()
        with _gate_span("address") as span:
            denial, reason, dest = await self._destination_async(url)
            _annotate_span(span, self, denial)
        self._record_decision(denial, time.perf_counter() - started)
        return denial, reason, dest

    async def _destination_async(self, url: str) -> tuple[str, str, Destination | None]:

        if not self.is_valid():
            if self.is_revoked():
                return "revoked", f"scope revoked: {self.revocation_reason}", None
            return "expired", "scope document has expired", None
        denial, reason, host, port = self._gate(url)
        if denial:
            return denial, reason, None
        denial, reason, addresses = await self._authorize(host, port)
        if denial:
            return denial, reason, None
        if not addresses:
            return "resolution_failed", f"cannot resolve {host}", None
        scheme = (parse_url(url) or urlparse(url)).scheme
        connect_port = port if port is not None else (443 if scheme == "https" else 80)
        jit_denial, jit_reason = await _jit_denial_async(self, url, host, connect_port)
        if jit_denial:
            return jit_denial, jit_reason, None
        return (
            "",
            "",
            Destination(scheme=scheme, host=host, port=connect_port, ip=addresses[0]),
        )


_active: Scope | None = None


_bound: contextvars.ContextVar[Scope | None] = contextvars.ContextVar("bound_scope")


_observer: contextvars.ContextVar[Callable[[str, str, str], None] | None] = contextvars.ContextVar(
    "scope_observer", default=None
)


@contextmanager
def _gate_span(stage: str) -> Iterator[Any]:
    """A span for one gate decision; a no-op span when OTel is not configured."""
    from ishastra import otel

    with otel.traced_span(f"scope.{stage}", {"scope.stage": stage}) as span:
        yield span


def _annotate_span(span: Any, scope: Scope, denial: str) -> None:
    """Record the verdict on the span -- never the target that produced it."""
    if span is None:
        return
    span.set_attribute("scope.decision", "blocked" if denial else "allowed")
    span.set_attribute("scope.denial", denial or "")
    span.set_attribute("scope.tenant", scope.tenant_id or "global")


def set_observer(observer: Callable[[str, str, str], None]) -> contextvars.Token:
    """Install a callback receiving (url, denial, reason) for every gate decision."""
    return _observer.set(observer)


def reset_observer(token: contextvars.Token) -> None:
    _observer.reset(token)


def _notify(url: str, denial: str, reason: str) -> None:
    """Tell the installed observer; it can never break a gate call."""
    observer = _observer.get()
    if observer is None:
        return
    try:
        observer(url, denial, reason)
    except Exception:
        log.exception("gate observer failed for %s", url)


class bound:
    """Judge gate calls on this task against ``snapshot`` until the with-block ends.

    Used by the job executor (:mod:`ishastra.core.jobs`) and the probe endpoint so
    a multi-tenant deployment enforces the *submitting tenant's* engagement
    policy -- not whatever global policy happens to be installed -- for every
    outbound connection, redirect judgment and secondary target of that job.
    """

    def __init__(self, snapshot: Scope) -> None:
        if not isinstance(snapshot, Scope):
            raise TypeError("bound() requires a validated Scope snapshot")
        self._snapshot = snapshot
        self._token: contextvars.Token[Scope | None] | None = None

    def __enter__(self) -> Scope:
        self._token = _bound.set(self._snapshot)
        return self._snapshot

    def __exit__(self, *_exc: object) -> None:
        if self._token is not None:
            _bound.reset(self._token)
        self._token = None


_sentinel = object()


def current() -> Scope | None:
    """The scope judging this task: the job-bound policy, else the global one."""
    thread_scope = _bound.get(None)
    if isinstance(thread_scope, Scope):
        return thread_scope
    return _active if _active is not None else None


_signing_keys: dict[str, Any] | None = None
_signing_file: str | None = None
_signing_file_identity: tuple[int, int, int] | None = None
_signing_explicit = False


_signing_max_age: int | None = scope_signing.DEFAULT_MAX_AGE_SECONDS


def configure_signing(
    jwks: dict[str, Any] | str | Path | None,
    *,
    max_age: int | None = scope_signing.DEFAULT_MAX_AGE_SECONDS,
) -> None:
    """Install the Ed25519 key set that signed scope documents are verified against.

    ``None`` clears an installed set, so ISHASTRA_SCOPE_JWKS is consulted again on
    the next load. Installs atomically: a key set that fails to parse raises and
    leaves whatever was installed before untouched. ``max_age`` is how old a
    signed document may be, in seconds; ``None`` disables the freshness check
    and reopens replay of an older signed document.
    """
    global _signing_keys, _signing_max_age, _signing_file, _signing_file_identity, _signing_explicit
    _signing_keys = None if jwks is None else scope_signing.key_set(jwks)
    _signing_max_age = max_age
    _signing_file = str(jwks) if isinstance(jwks, (str, Path)) else None
    stat = Path(_signing_file).stat() if _signing_file else None
    _signing_file_identity = (stat.st_mtime_ns, stat.st_size, stat.st_ino) if stat else None
    _signing_explicit = jwks is not None and _signing_file is None


def _signing_key_set() -> dict[str, Any] | None:
    """The installed key set, else the one named by ISHASTRA_SCOPE_JWKS.

    A key set that fails to parse raises on every load rather than falling back
    to "no signing": an unreadable key file must not widen who can author a
    scope document.
    """
    global _signing_keys, _signing_max_age, _signing_file, _signing_file_identity
    path = _signing_file or os.environ.get("ISHASTRA_SCOPE_JWKS", "").strip()
    if path and not _signing_explicit:
        stat = Path(path).stat()
        identity = (stat.st_mtime_ns, stat.st_size, stat.st_ino)
        if path != _signing_file or identity != _signing_file_identity:
            _signing_keys = scope_signing.load_jwks(path)
            _signing_file = path
            _signing_file_identity = identity
            raw_age = os.environ.get("ISHASTRA_SCOPE_MAX_AGE_SECONDS", "").strip()
            if raw_age:
                _signing_max_age = int(raw_age)
    return _signing_keys


def _verify_signature(data: dict[str, Any]) -> str:
    """Require and verify a signature when signing is configured; name the key id."""
    keys = _signing_key_set()
    if keys is None:
        if scope_signing.is_signed(data):
            raise ValueError(
                "scope document is signed but no verification key set is configured; set "
                "ISHASTRA_SCOPE_JWKS (or call scope.configure_signing()) or the document "
                "cannot be trusted"
            )
        return ""
    return scope_signing.verify_document(data, keys, max_age=_signing_max_age)


def _apply_signature(data: dict[str, Any], key: str | Path | None, kid: str | None) -> dict[str, Any]:
    """Sign an edited document, or refuse to leave an existing signature stale."""
    if key is not None:
        if not kid:
            raise ValueError("signing a scope document requires the key id (kid)")
        signing_key = scope_signing.load_private_key_file(Path(key))
        return scope_signing.sign_document(data, signing_key, kid)
    if scope_signing.is_signed(data):
        raise ValueError(
            "scope document is signed; editing it requires the signing key (private_key and kid) "
            "so the signature stays verifiable"
        )
    return data


_SCOPE_SCHEMA: dict[str, Any] | None = None


def _load_schema() -> dict[str, Any]:
    """Load the JSON Schema for scope documents from the package."""
    global _SCOPE_SCHEMA
    if _SCOPE_SCHEMA is None:
        schema_path = Path(__file__).parent / "scope_schema.json"
        _SCOPE_SCHEMA = json.loads(schema_path.read_text())
    return _SCOPE_SCHEMA


def _validate_schema(data: dict[str, Any]) -> None:
    """Validate data against the JSON Schema.

    Raises:
        ValueError: If validation fails, with a descriptive message.
    """
    schema = _load_schema()
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as exc:
        path = " -> ".join(str(p) for p in exc.path) if exc.path else "root"
        raise ValueError(f"scope document validation failed at {path}: {exc.message}") from None
    except jsonschema.SchemaError as exc:
        raise ValueError(f"scope schema error: {exc.message}") from None


def parse_scope_document(data: Any) -> Scope:
    """Validate a parsed scope document and turn it into an installed Scope.

    This function:
    1. Validates the document structure against the JSON Schema (v2)
    2. For v1 documents (no version field), applies legacy validation
    3. Performs additional semantic validation (host patterns, CIDR, ports)
    4. Creates a Scope instance with all validated fields

    Raises ``ValueError`` naming the first structural problem. Never mutates
    the active configuration: either the whole document validates (and is
    installed), or nothing changes.
    """
    if not isinstance(data, dict):
        raise ValueError(
            "scope document must be a JSON object with fields such as program, "
            f"include, authorized_networks (got {type(data).__name__})"
        )

    _verify_signature(data)

    version = data.get("version", 1)

    if version >= 2:
        _validate_schema(data)
        _KNOWN_SCOPE_FIELDS_V2 = {
            "program",
            "authorized_by",
            "authorization_ref",
            "include",
            "exclude",
            "signature",
            "issued_at",
            "authorized_networks",
            "allowed_ports",
            "allowed_asns",
            "allowed_countries",
            "auth",
            "collab",
            "allow_broad_networks",
            "version",
            "revoked",
            "revoked_at",
            "revoked_by",
            "revocation_reason",
            "expires_at",
            "metadata",
            "rules_of_engagement",
        }
        unknown = sorted(set(data) - _KNOWN_SCOPE_FIELDS_V2)
        if unknown:
            raise ValueError(
                f"scope document has unknown field(s): {', '.join(unknown)}; allowed "
                f"fields are: {', '.join(sorted(_KNOWN_SCOPE_FIELDS_V2))}"
            )
    else:
        pass

    _REQUIRED_SCOPE_FIELDS = ("program", "authorized_by", "authorization_ref", "include")
    for name in _REQUIRED_SCOPE_FIELDS:
        value = data.get(name)
        if name == "include":
            valid = isinstance(value, list) and bool(value)
        else:
            valid = isinstance(value, str) and bool(value.strip())
        if not valid:
            shape = "a non-empty list" if name == "include" else "a non-empty string"
            raise ValueError(f"scope document field {name!r} is required ({shape})")

    for name in ("include", "exclude"):
        entries = data.get(name, [])
        for entry in entries:
            if not isinstance(entry, str):
                raise ValueError(f"scope document {name}: entries must be strings")
            complaint = _host_pattern_error(entry)
            if complaint:
                raise ValueError(f"scope document {name}: {complaint}")

    for entry in data.get("authorized_networks", []):
        if not isinstance(entry, str) or not entry.strip():
            raise ValueError("authorized_networks entries must be non-empty CIDR strings")
        try:
            network = ipaddress.ip_network(entry.strip(), strict=False)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"authorized_networks entry {entry!r} is not a valid CIDR: {exc}") from None
        if network.version == 6 and network.network_address.ipv4_mapped is not None:
            raise ValueError(
                f"authorized_networks entry {entry!r} is an IPv4-mapped IPv6 "
                "network; authorize the IPv4 CIDR directly (e.g. 10.0.0.0/8)"
            )

    for port in data.get("allowed_ports", []):
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError(f"scope document allowed_ports: {port!r} is not an integer from 1 to 65535")

    for asn in data.get("allowed_asns", []):
        if not isinstance(asn, int) or isinstance(asn, bool) or asn < 1:
            raise ValueError(f"scope document allowed_asns: {asn!r} is not a positive AS number")
    countries = [str(code).strip().upper() for code in data.get("allowed_countries", [])]
    for code in countries:
        if not COUNTRY_CODE.fullmatch(code):
            raise ValueError(f"scope document allowed_countries: {code!r} is not an ISO 3166-1 alpha-2 code")

    auth_config: AuthConfig | None = None
    if isinstance(data.get("auth"), dict):
        try:
            auth_config = AuthConfig.from_dict(data["auth"])
        except ValueError as exc:
            raise ValueError(f"scope document auth: {exc}") from None

    collab_config: CollabConfig | None = None
    if isinstance(data.get("collab"), dict):
        try:
            collab_config = CollabConfig.from_dict(data["collab"])
        except ValueError as exc:
            raise ValueError(f"scope document collab: {exc}") from None

    allow_broad_networks = bool(data.get("allow_broad_networks", False))
    revoked = bool(data.get("revoked", False))
    revoked_at = str(data.get("revoked_at", ""))
    revoked_by = str(data.get("revoked_by", ""))
    revocation_reason = str(data.get("revocation_reason", ""))
    expires_at = str(data.get("expires_at", ""))
    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    metadata = {str(k): str(v) for k, v in metadata.items()}

    rules_of_engagement = data.get("rules_of_engagement", {})
    if not isinstance(rules_of_engagement, dict):
        rules_of_engagement = {}

    return configure(
        program=data["program"].strip(),
        authorized_by=data["authorized_by"].strip(),
        authorization_ref=data["authorization_ref"].strip(),
        include=data["include"],
        exclude=data.get("exclude", []),
        authorized_networks=data.get("authorized_networks", []),
        allowed_ports=data.get("allowed_ports", []),
        allowed_asns=data.get("allowed_asns", []),
        allowed_countries=countries,
        auth=auth_config,
        collab=collab_config,
        allow_broad_networks=allow_broad_networks,
        version=version,
        revoked=revoked,
        revoked_at=revoked_at,
        revoked_by=revoked_by,
        revocation_reason=revocation_reason,
        expires_at=expires_at,
        metadata=metadata,
        rules_of_engagement=rules_of_engagement,
    )


def configure(
    program: str,
    authorized_by: str,
    authorization_ref: str,
    include: list[str] | tuple[str, ...],
    exclude: list[str] | tuple[str, ...] = (),
    authorized_networks: list[str] | tuple[str, ...] = (),
    allowed_ports: list[int] | tuple[int, ...] = (),
    allowed_asns: list[int] | tuple[int, ...] = (),
    allowed_countries: list[str] | tuple[str, ...] = (),
    auth: AuthConfig | None = None,
    collab: CollabConfig | None = None,
    policy_id: str = "",
    policy_version: int = 0,
    tenant_id: str = "",
    allow_broad_networks: bool = False,
    version: int = CURRENT_SCHEMA_VERSION,
    revoked: bool = False,
    revoked_at: str = "",
    revoked_by: str = "",
    revocation_reason: str = "",
    expires_at: str = "",
    metadata: dict[str, str] | None = None,
    rules_of_engagement: dict | None = None,
) -> Scope:
    """Install the active scope. Raises ValueError if the record is incomplete.

    Atomic: the new policy becomes active only if it fully validates; a failed
    call leaves the previous configuration untouched.
    """
    global _active
    _active = Scope(
        program=program,
        authorized_by=authorized_by,
        authorization_ref=authorization_ref,
        include=tuple(include),
        exclude=tuple(exclude),
        authorized_networks=tuple(authorized_networks),
        allowed_ports=tuple(allowed_ports),
        allowed_asns=tuple(allowed_asns),
        allowed_countries=tuple(allowed_countries),
        auth=auth,
        collab=collab,
        policy_id=policy_id,
        policy_version=int(policy_version),
        tenant_id=tenant_id,
        allow_broad_networks=bool(allow_broad_networks),
        version=version,
        revoked=revoked,
        revoked_at=revoked_at,
        revoked_by=revoked_by,
        revocation_reason=revocation_reason,
        expires_at=expires_at,
        metadata=metadata or {},
        rules_of_engagement=rules_of_engagement or {},
    )
    return _active


def active() -> Scope | None:
    """The scope in force on this thread (job-bound snapshot or global)."""
    return current()


def check(url: str) -> tuple[str, str]:
    """Gate used by the scanner, the adapters and the HTTP probe."""
    thread_scope = current()
    if thread_scope is None:
        denial, reason = (
            "out_of_scope",
            "no authorized scope configured — nothing may be scanned",
        )
    else:
        denial, reason = thread_scope.check(url)
    _notify(url, denial, reason)
    return denial, reason


def destination(url: str) -> tuple[str, str, Destination | None]:
    """Authoritative gate for code that opens a socket."""
    thread_scope = current()
    if thread_scope is None:
        denial, reason, dest = (
            "out_of_scope",
            "no authorized scope configured — nothing may be scanned",
            None,
        )
    else:
        denial, reason, dest = thread_scope.destination(url)
    _notify(url, denial, reason)
    return denial, reason, dest


def load(path: str | Path) -> Scope | None:
    """Load a scope document (see scope.example.json). Returns None if absent.

    Reload policy (explicit): if the document is missing, the active
    configuration is left exactly as it is. If the document exists but fails
    validation, ``ValueError`` is raised **before** anything is installed, so
    the previous valid configuration remains active — the caller (application
    startup) decides to refuse scanning when no valid policy exists at all.
    """
    document = Path(path)
    if not document.is_file():
        return None
    try:
        data = json.loads(document.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"scope document {document} is not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})"
        ) from None
    loaded = parse_scope_document(data)
    _require_intel(loaded)
    return loaded


def _require_intel(loaded: Scope) -> None:
    """Refuse a deployment whose document needs a data source nobody installed.

    The gate would stay closed by denying every request, which is safe but
    silent; at startup the operator can see and fix the cause instead.
    """
    missing = []
    if loaded.allowed_asns and _asn_lookup is None:
        missing.append("allowed_asns (register_intel(asn=...))")
    if loaded.allowed_countries and _country_lookup is None:
        missing.append("allowed_countries (register_intel(country=...))")
    if missing:
        raise ValueError(
            "scope document requires network intelligence that is not configured: " + ", ".join(missing)
        )


def validate_scope_file(path: str | Path) -> tuple[bool, str | None]:
    """Validate a scope document file without installing it.

    Args:
        path: Path to the scope.json file

    Returns:
        Tuple of (is_valid, error_message). error_message is None if valid.
    """
    document = Path(path)
    if not document.is_file():
        return False, f"scope document not found: {document}"
    try:
        data = json.loads(document.read_text())
    except json.JSONDecodeError as exc:
        return False, (
            f"scope document {document} is not valid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})"
        )
    try:
        parse_scope_document(data)
        return True, None
    except ValueError as exc:
        return False, str(exc)


def revoke_scope(
    path: str | Path,
    revoked_by: str,
    reason: str,
    *,
    private_key: str | Path | None = None,
    kid: str | None = None,
) -> Scope:
    """Revoke a scope document by updating it in place.

    Args:
        path: Path to the scope.json file
        revoked_by: Identity of the party revoking the scope
        reason: Reason for revocation
        private_key: Signing key, required when the document is already signed
            (revocation changes signed fields, so it must be re-signed)
        kid: Key id matching ``private_key``

    Returns:
        The revoked Scope instance

    Raises:
        ValueError: If the document doesn't exist or is already revoked
    """
    document = Path(path)
    if not document.is_file():
        raise ValueError(f"scope document not found: {document}")

    data = json.loads(document.read_text())

    if data.get("revoked", False):
        raise ValueError("scope document is already revoked")

    data["revoked"] = True
    data["revoked_at"] = datetime.now(UTC).isoformat()
    data["revoked_by"] = revoked_by
    data["revocation_reason"] = reason
    data = _apply_signature(data, private_key, kid)

    document.write_text(json.dumps(data, indent=2))

    return parse_scope_document(data)


def extend_scope_expiry(
    path: str | Path,
    new_expires_at: str,
    *,
    private_key: str | Path | None = None,
    kid: str | None = None,
) -> Scope:
    """Extend the expiry of a scope document.

    Args:
        path: Path to the scope.json file
        new_expires_at: New ISO 8601 expiry timestamp
        private_key: Signing key, required when the document is already signed
            (expiry is signed, so it cannot be extended without re-signing)
        kid: Key id matching ``private_key``

    Returns:
        The updated Scope instance

    Raises:
        ValueError: If the document doesn't exist or new_expires_at is invalid
    """
    document = Path(path)
    if not document.is_file():
        raise ValueError(f"scope document not found: {document}")

    try:
        datetime.fromisoformat(new_expires_at.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("new_expires_at must be a valid ISO 8601 timestamp") from None

    data = json.loads(document.read_text())

    if data.get("revoked", False):
        raise ValueError("cannot extend expiry of revoked scope")

    data["expires_at"] = new_expires_at
    data = _apply_signature(data, private_key, kid)

    document.write_text(json.dumps(data, indent=2))

    return parse_scope_document(data)


class ScopeGate:
    """Default-deny authorization gate for outbound connections.

    Wraps a Scope to provide a validate_outbound(target, scope) -> ValidationResult
    interface. Returns a detailed ValidationResult with the authorization decision
    and reason. Default-deny: returns allowed=False unless target explicitly
    allowed by scope.
    """

    @staticmethod
    def validate_outbound(target: str, scope: Scope) -> ValidationResult:
        """Validate an outbound target and count the decision for metrics."""
        started = time.perf_counter()
        result = ScopeGate._validate_outbound(target, scope)
        scope._record_decision(result.denial_code, time.perf_counter() - started)
        return result

    @staticmethod
    async def validate_outbound_async(target: str, scope: Scope) -> ValidationResult:
        """validate_outbound plus a fail-closed just-in-time decision.

        The local scope is judged first, so an out-of-scope target never reaches
        the external service; a service that is down, slow or malformed denies.
        """
        started = time.perf_counter()
        result = ScopeGate._validate_outbound(target, scope)
        if result.allowed:
            denial, reason = await _jit_denial_async(scope, target, result.host, result.port)
            if denial:
                result = replace(result, allowed=False, denial_code=denial, reason=reason)
        scope._record_decision(result.denial_code, time.perf_counter() - started)
        return result

    @staticmethod
    def _validate_outbound(target: str, scope: Scope) -> ValidationResult:
        """Validate an outbound target against the given scope.

        Args:
            target: The target URL (e.g., "https://example.com/")
            scope: The Scope instance to validate against

        Returns:
            ValidationResult with allowed (bool), reason (str), denial_code (str),
            host (str), port (int|None), and resolved_ips (tuple[str, ...]).

        The method performs:
        1. URL syntax and scheme validation (must be http/https)
        2. Host allowlist/denylist check
        3. Port authorization check (if allowed_ports is configured)
        4. DNS resolution and address authorization (checks authorized_networks
           and rejects special-use addresses unless explicitly authorized)
        """

        denial, reason, host, raw_port = scope._gate(target)

        parsed = parse_url(target)
        default_port = 443 if (parsed and parsed.scheme == "https") else 80
        effective_port = raw_port if raw_port is not None else default_port

        if denial:
            port_for_result = effective_port if denial == "out_of_scope" else None
            return ValidationResult(
                allowed=False,
                reason=reason,
                denial_code=denial,
                host=host,
                port=port_for_result,
                resolved_ips=(),
            )

        denial, reason, addresses = scope._authorize_sync(host, raw_port, fail_on_empty=False)

        if not addresses and not denial:
            denial = "resolution_failed"
            reason = f"cannot resolve {host} (timeout or overload)"

        if denial:
            return ValidationResult(
                allowed=False,
                reason=reason,
                denial_code=denial,
                host=host,
                port=effective_port,
                resolved_ips=tuple(addresses) if addresses else (),
            )

        return ValidationResult(
            allowed=True,
            reason="target is within authorized scope",
            denial_code="",
            host=host,
            port=effective_port,
            resolved_ips=tuple(addresses) if addresses else (),
        )

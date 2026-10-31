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
"""
from __future__ import annotations

import asyncio
import contextvars
import ipaddress
import json
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import ParseResult, urlparse

from strix.core.authz import AuthConfig
from strix.core.collab import CollabConfig
from strix.core.urls import parse_url

INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")

# getaddrinfo has no native timeout. Use a bounded thread pool executor
# with asyncio.wait_for to enforce timeout without daemon threads.
RESOLVE_TIMEOUT = 3.0
MAX_CONCURRENT_RESOLUTIONS = 16
_resolution_semaphore: asyncio.Semaphore | None = None


async def resolve(host: str, port: int | None = None) -> list[str]:
    """Addresses for ``host``; empty list on failure, overload, or timeout.

    Uses a semaphore to bound concurrent resolutions and asyncio.wait_for
    for timeout enforcement. Runs the blocking getaddrinfo in a thread pool
    to avoid blocking the event loop.
    """
    global _resolution_semaphore
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
    try:
        # Set a timeout on the socket operations
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(RESOLVE_TIMEOUT)
        try:
            infos = socket.getaddrinfo(host, port or 443, proto=socket.IPPROTO_TCP)
            return [str(info[4][0]) for info in infos]
        finally:
            socket.setdefaulttimeout(old_timeout)
    except (OSError, UnicodeError):
        return []


# IPv6 transition mechanisms that carry an IPv4 destination address inside a
# wider IPv6 address. Python's ``is_global`` table does not treat all of them as
# special-use (NAT64 in 64:ff9b::/96 is "global"), so the embedded address has
# to be judged explicitly instead of trusting the prefix.
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIXTOFOUR = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")


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
    if address in _TEREDO:
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
        address.is_loopback or address.is_link_local or address.is_multicast
        or address.is_unspecified or address.is_private or address.is_reserved
        or getattr(address, "is_site_local", False) or not address.is_global
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

# An explicitly configured network must not silently authorize half the
# internet. Networks broader than a /8 (IPv4 e.g. 0.0.0.0/0, 128.0.0.0/1;
# IPv6 e.g. ::/0, 8000::/1) are refused unless the document sets
# allow_broad_networks=true — a deliberate, auditable override for the rare
# engagement that genuinely needs it. Conventional internal ranges
# (10.0.0.0/8, 127.0.0.0/8, fd00::/8, ...) pass the guard unchanged.
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
        return (f"host entry {pattern!r} is not a valid DNS name "
                "(IDNs must be given as punycode)")
    return ""


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
        # Also keeps option-shaped hosts such as "-iL.example.com" away from the
        # external tools: a DNS label never starts with a hyphen.
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
    program: str
    authorized_by: str
    authorization_ref: str
    include: tuple[str, ...]
    exclude: tuple[str, ...] = field(default=())
    # Explicitly authorized internal networks (CIDR). Empty by default:
    # private/loopback/link-local space is denied until named here.
    authorized_networks: tuple[str, ...] = field(default=())
    # When non-empty, only these TCP/UDP service ports are in scope. Empty
    # preserves host-wide authorization for legacy scope files; production
    # scopes should enumerate ports (e.g. [80, 443]).
    allowed_ports: tuple[int, ...] = field(default=())
    # Optional test principals for authorization-difference testing. Loaded
    # from the scope document, kept in memory only, never serialized back out.
    auth: AuthConfig | None = None
    # Optional out-of-band canary listener for blind SSRF confirmation:
    # {"host": "...", "port": N} — port 0 selects the in-process listener.
    collab: CollabConfig | None = None
    # Engagement binding (multi-tenant mode). Empty in global mode.
    policy_id: str = ""
    policy_version: int = 0
    tenant_id: str = ""
    # Deliberate override for networks broader than _MIN_PREFIX (see above).
    allow_broad_networks: bool = False

    def __post_init__(self) -> None:
        missing = [
            name for name in ("program", "authorized_by", "authorization_ref")
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
                raise ValueError(
                    f"authorized_networks entry {network!r} is not a CIDR network") from exc
            if (parsed_network.version == 6
                    and parsed_network.network_address.ipv4_mapped is not None):
                raise ValueError(
                    f"authorized_networks entry {network!r} is an IPv4-mapped IPv6 "
                    "network; authorize the IPv4 CIDR directly (e.g. 10.0.0.0/8)")
            floor = _MIN_PREFIX[parsed_network.version]
            if parsed_network.prefixlen < floor and not self.allow_broad_networks:
                raise ValueError(
                    f"authorized_networks entry {network!r} covers more than a "
                    f"/{floor} (it is /{parsed_network.prefixlen}); refusing a "
                    "dangerously broad authorization — split the range or set "
                    "allow_broad_networks=true to override deliberately")
        if any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
               for port in self.allowed_ports):
            raise ValueError("allowed_ports entries must be integers from 1 to 65535")

    def _listed(self, host: str, patterns: tuple[str, ...]) -> bool:
        for pattern in patterns:
            pattern = pattern.strip().lower().strip(".")
            if pattern.startswith("*."):
                # *.example.com covers subdomains only, never the apex
                if host.endswith(pattern[1:]) and host != pattern[2:]:
                    return True
            elif host == pattern:
                return True
        return False

    def _networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(net, strict=False) for net in self.authorized_networks]

    # ------------------------------------------------------------------
    # Layer 1: URL / host gate (no DNS)
    # ------------------------------------------------------------------
    def _gate(self, url: str) -> tuple[str, str, str, int | None]:
        """(denial, reason, host, port) from the URL alone."""
        parsed = parse_url(url)
        if (parsed is None or parsed.scheme not in ("http", "https")
                or not parsed.hostname):
            return "invalid_target", "target must be an absolute http(s) URL", "", None
        if ".." in url:
            return "invalid_target", "target contains a traversal sequence", "", None
        ambiguity = _ambiguous(url, parsed)
        if ambiguity:
            return "invalid_target", ambiguity, "", None
        host = parsed.hostname.lower()
        if self._listed(host, self.exclude):
            return "out_of_scope", f"{host} is explicitly out of scope", host, parsed.port
        if not self._listed(host, self.include):
            return "out_of_scope", f"{host} is not in the authorized scope", host, parsed.port
        effective_port = parsed.port if parsed.port is not None \
            else (443 if parsed.scheme == "https" else 80)
        if effective_port < 1:
            return ("invalid_target", "port 0 is not a connectable service port",
                    host, parsed.port)
        if self.allowed_ports and effective_port not in self.allowed_ports:
            return ("out_of_scope",
                    f"port {effective_port} is not in the authorized port scope",
                    host, parsed.port)
        return "", "", host, parsed.port

    # ------------------------------------------------------------------
    # Layer 2: address policy over a fresh resolution (sync)
    # ------------------------------------------------------------------
    def _authorize_sync(
        self, host: str, port: int | None, *, fail_on_empty: bool = True
    ) -> tuple[str, str, list[str]]:
        """(denial, reason, addresses). Every returned address must pass. Sync version."""
        networks = self._networks()
        addresses = resolve_sync(host, port)
        if not addresses:
            if host == "localhost" or host.endswith(INTERNAL_SUFFIXES):
                return "out_of_scope", f"{host} is an internal host name", []
            if fail_on_empty:
                return "resolution_failed", f"cannot resolve {host} (timeout or overload)", []
            return "", "", []
        for value in addresses:
            address = ipaddress.ip_address(value.split("%")[0])
            if any(address in network for network in networks):
                continue
            if not is_special_use(address):
                continue
            if host == str(address):
                return "out_of_scope", f"{address} is a non-public address", []
            return "out_of_scope", f"{host} resolves to non-public address {address}", []
        return "", "", addresses

    # ------------------------------------------------------------------
    # Layer 2: address policy over a fresh resolution (async)
    # ------------------------------------------------------------------
    async def _authorize(
        self, host: str, port: int | None, *, fail_on_empty: bool = True
    ) -> tuple[str, str, list[str]]:
        """(denial, reason, addresses). Every returned address must pass. Async version."""
        networks = self._networks()
        addresses = await resolve(host, port)
        if not addresses:
            if host == "localhost" or host.endswith(INTERNAL_SUFFIXES):
                return "out_of_scope", f"{host} is an internal host name", []
            if fail_on_empty:
                return "resolution_failed", f"cannot resolve {host} (timeout or overload)", []
            return "", "", []
        for value in addresses:
            address = ipaddress.ip_address(value.split("%")[0])
            if any(address in network for network in networks):
                continue
            if not is_special_use(address):
                continue
            if host == str(address):
                return "out_of_scope", f"{address} is a non-public address", []
            return "out_of_scope", f"{host} resolves to non-public address {address}", []
        return "", "", addresses

    def check(self, url: str) -> tuple[str, str]:
        """Return ("", "") when the target may be contacted, else (denial, reason)."""
        denial, reason, host, port = self._gate(url)
        if denial:
            return denial, reason
        denial, reason, _addresses = self._authorize_sync(host, port, fail_on_empty=False)
        return denial, reason

    async def check_async(self, url: str) -> tuple[str, str]:
        """Async version of check for use in async contexts."""
        denial, reason, host, port = self._gate(url)
        if denial:
            return denial, reason
        denial, reason, _addresses = await self._authorize(host, port, fail_on_empty=False)
        return denial, reason

    def destination(self, url: str) -> tuple[str, str, Destination | None]:
        """Authoritative pre-connect validation (sync).

        The caller MUST connect to the returned :class:`Destination` and to
        nothing else: connecting anywhere else re-resolves the name and reopens
        DNS rebinding between validation and use.
        """
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
        return "", "", Destination(scheme=scheme, host=host,
                                   port=connect_port, ip=addresses[0])

    async def destination_async(self, url: str) -> tuple[str, str, Destination | None]:
        """Async version of destination for use in async contexts."""
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
        return "", "", Destination(scheme=scheme, host=host,
                                   port=connect_port, ip=addresses[0])

_active: Scope | None = None

# Per-task scope binding: the worker installs the engagement policy its job
# was authorized under for exactly one job execution. Nothing else may set it.
# ContextVar propagates correctly across async boundaries (unlike threading.local).
_bound: contextvars.ContextVar[Scope | None] = contextvars.ContextVar("bound_scope")


class bound:
    """Judge gate calls on this task against ``snapshot`` until the with-block ends.

    Used by the job executor (:mod:`strix.core.jobs`) and the probe endpoint so
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
    return thread_scope if isinstance(thread_scope, Scope) else _active


def configure(
    program: str,
    authorized_by: str,
    authorization_ref: str,
    include: list[str] | tuple[str, ...],
    exclude: list[str] | tuple[str, ...] = (),
    authorized_networks: list[str] | tuple[str, ...] = (),
    allowed_ports: list[int] | tuple[int, ...] = (),
    auth: AuthConfig | None = None,
    collab: CollabConfig | None = None,
    policy_id: str = "",
    policy_version: int = 0,
    tenant_id: str = "",
    allow_broad_networks: bool = False,
) -> Scope:
    """Install the active scope. Raises ValueError if the record is incomplete.

    Atomic: the new policy becomes active only if it fully validates; a failed
    call leaves the previous configuration untouched.
    """
    global _active
    _active = Scope(program, authorized_by, authorization_ref, tuple(include),
                    tuple(exclude), tuple(authorized_networks), tuple(allowed_ports),
                    auth, collab, policy_id, int(policy_version), tenant_id,
                    bool(allow_broad_networks))
    return _active


def active() -> Scope | None:
    """The scope in force on this thread (job-bound snapshot or global)."""
    return current()


def check(url: str) -> tuple[str, str]:
    """Gate used by the scanner, the adapters and the HTTP probe."""
    thread_scope = current()
    if thread_scope is None:
        return "out_of_scope", "no authorized scope configured — nothing may be scanned"
    return thread_scope.check(url)


def destination(url: str) -> tuple[str, str, Destination | None]:
    """Authoritative gate for code that opens a socket."""
    thread_scope = current()
    if thread_scope is None:
        return "out_of_scope", "no authorized scope configured — nothing may be scanned", None
    return thread_scope.destination(url)


# Fields a scope document may carry, with the types each must have. Anything
# else — including a plausible-looking typo — is refused: an unrecognized field
# would otherwise be silently ignored and the operator would believe they had
# authorized something they had not.
_SCOPE_FIELD_TYPES: dict[str, tuple[type, ...]] = {
    "program": (str,), "authorized_by": (str,), "authorization_ref": (str,),
    "include": (list,), "exclude": (list,), "authorized_networks": (list,),
    "allowed_ports": (list,), "auth": (dict,), "collab": (dict,),
    "allow_broad_networks": (bool,),
}
_REQUIRED_SCOPE_FIELDS = ("program", "authorized_by", "authorization_ref", "include")


def parse_scope_document(data: Any) -> Scope:
    """Validate a parsed scope document and turn it into an installed Scope.

    Raises ``ValueError`` naming the first structural problem. Never mutates
    the active configuration: either the whole document validates (and is
    installed), or nothing changes.
    """
    if not isinstance(data, dict):
        raise ValueError(
            "scope document must be a JSON object with fields such as program, "
            f"include, authorized_networks (got {type(data).__name__})")
    unknown = sorted(set(data) - set(_SCOPE_FIELD_TYPES))
    if unknown:
        raise ValueError(
            f"scope document has unknown field(s): {', '.join(unknown)}; allowed "
            f"fields are: {', '.join(sorted(_SCOPE_FIELD_TYPES))}")
    for name in _REQUIRED_SCOPE_FIELDS:
        value = data.get(name)
        if name == "include":
            valid = isinstance(value, list) and bool(value)
        else:
            valid = isinstance(value, str) and bool(value.strip())
        if not valid:
            shape = "a non-empty list" if name == "include" else "a non-empty string"
            raise ValueError(f"scope document field {name!r} is required ({shape})")
    for name, expected in _SCOPE_FIELD_TYPES.items():
        if name in data and not isinstance(data[name], expected):
            wanted = "true or false" if expected == (bool,) else expected[0].__name__
            raise ValueError(f"scope document field {name!r} must be {wanted}")
    for name in ("include", "exclude", "authorized_networks"):
        entries = data.get(name, [])
        for entry in entries:
            if name == "authorized_networks":
                if not isinstance(entry, str) or not entry.strip():
                    raise ValueError(f"{name} entries must be non-empty CIDR strings")
                continue
            complaint = _host_pattern_error(entry)
            if complaint:
                raise ValueError(f"scope document {name}: {complaint}")
    ports = data.get("allowed_ports", [])
    for port in ports:
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError(
                f"scope document allowed_ports: {port!r} is not an integer from 1 to 65535")
    auth_config: AuthConfig | None = None
    if isinstance(data.get("auth"), dict):
        # A malformed principal fails the whole scope: credentials must never
        # be half-loaded.
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
    return configure(
        program=data["program"].strip(),
        authorized_by=data["authorized_by"].strip(),
        authorization_ref=data["authorization_ref"].strip(),
        include=data["include"],
        exclude=data.get("exclude", []),
        authorized_networks=data.get("authorized_networks", []),
        allowed_ports=ports,
        auth=auth_config,
        collab=collab_config,
        allow_broad_networks=bool(data.get("allow_broad_networks", False)),
    )


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
            f"scope document {document} is not valid JSON: {exc.msg} "
            f"(line {exc.lineno}, column {exc.colno})") from None
    return parse_scope_document(data)

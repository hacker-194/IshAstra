"""Strix Proof: verifiable evidence that security testing was authorized.

Three artifacts, all plain JSON, so anything can verify them without Strix:

* a **grant** -- the asset owner's Ed25519-signed authorization: who may test
  what, until when;
* a **receipt** -- one signed, hash-chained record per gate decision (allow or
  deny) taken under that grant;
* a **proof pack** -- grant + receipts + the gate's public key, verified
  offline with :func:`verify_pack`.

The trust rule is the whole point: a signature only proves the holder signed
it, so a verifier must pin the issuer key it trusts (``trusted_issuer``). A
self-signed grant verifies cryptographically and is reported as
``issuer_trusted: false`` -- never presented as trusted authorization.

Scope of enforcement: the gate decides before an action and records it. The
built-in adapters honour the same grant through :mod:`strix.core.scope`, which
pins the resolved address it validated. For a third-party agent the gate is an
authorization service, not a network firewall -- it cannot stop an agent that
ignores it, but every action it saw is receipted and everything it did not
authorize is provably absent from the ledger.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from strix.core.scope import Scope

log = logging.getLogger(__name__)

VERSION = "strix-proof/1"
GENESIS = "0" * 64
MAX_BODY = 64 * 1024
LEDGER_TYPE = "gate-ledger"


class ProofError(ValueError):
    """The proof artifact is unusable; nothing was trusted, written or started."""


# Raw Ed25519 private and public keys are both 32 bytes, so a bare file cannot
# say which it holds. Key files written here are prefixed to remove the doubt.
PRIVATE_KEY_PREFIX = "strix-proof-private:"


# -- keys and canonical encoding ---------------------------------------------


def _b64(raw: bytes) -> str:
    # Standard alphabet, not URL-safe: a key starting with '-' cannot be passed
    # as a command-line argument (argparse reads it as an option).
    return base64.b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4))


def canonical(value: Any) -> bytes:
    """The exact bytes that get signed: sorted keys, no whitespace."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def new_keypair() -> tuple[str, str]:
    """(private, public) Ed25519 keys, URL-safe base64 without padding."""
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _b64(private), _b64(public)


def public_key(private_key: str) -> str:
    """The public key for ``private_key`` (raises ProofError when malformed)."""
    try:
        key = Ed25519PrivateKey.from_private_bytes(_unb64(private_key))
    except (ValueError, TypeError) as exc:
        raise ProofError(f"invalid Ed25519 private key: {exc}") from None
    return _b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def fingerprint(public: str) -> str:
    """Short stable identifier for a key, safe to publish and compare."""
    try:
        return hashlib.sha256(_unb64(public)).hexdigest()[:32]
    except (ValueError, TypeError) as exc:
        raise ProofError(f"invalid Ed25519 public key: {exc}") from None


def sign(payload: Any, private_key: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(_unb64(private_key))
    return _b64(key.sign(canonical(payload)))


def verify_signature(payload: Any, signature: str, public: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(public)).verify(
            _unb64(signature), canonical(payload)
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def write_private_key(path: str | Path, private_key: str) -> None:
    """Write a key file readable by its owner only."""
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(PRIVATE_KEY_PREFIX + private_key + "\n")
    os.chmod(target, 0o600)


def load_private_key(path: str | Path) -> str:
    text = Path(path).expanduser().read_text().strip()
    if text.startswith(PRIVATE_KEY_PREFIX):
        text = text[len(PRIVATE_KEY_PREFIX) :]
    public_key(text)  # validates it decodes and is usable as a private key
    return text


def load_public_key(path: str | Path) -> str:
    text = Path(path).expanduser().read_text().strip()
    if text.startswith(PRIVATE_KEY_PREFIX):
        raise ProofError(
            f"{path} holds a private key; pass the matching public key instead "
        )
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(text))
    except (ValueError, TypeError) as exc:
        raise ProofError(f"invalid Ed25519 public key in {path}: {exc}") from None
    return text


def _iso(moment: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(moment))


# -- grant -------------------------------------------------------------------

_GRANT_FIELDS = (
    "version",
    "grant_id",
    "program",
    "authorized_by",
    "authorization_ref",
    "include",
    "exclude",
    "authorized_networks",
    "allowed_ports",
    "allow_broad_networks",
    "not_before",
    "not_after",
    "issuer",
)


@dataclass(frozen=True)
class Grant:
    """A signed authorization to test a named program until ``not_after``."""

    grant_id: str
    program: str
    authorized_by: str
    authorization_ref: str
    include: tuple[str, ...]
    exclude: tuple[str, ...] = ()
    authorized_networks: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = ()
    allow_broad_networks: bool = False
    not_before: float = 0.0
    not_after: float = 0.0
    issuer: str = ""
    signature: str = ""

    def __post_init__(self) -> None:
        missing = [
            name
            for name in ("grant_id", "program", "authorized_by", "authorization_ref")
            if not str(getattr(self, name, "") or "").strip()
        ]
        if missing:
            raise ProofError(f"grant incomplete: missing {', '.join(missing)}")

    def body(self) -> dict[str, Any]:
        """The signed content -- everything except the signature itself."""
        return {
            "version": VERSION,
            "grant_id": self.grant_id,
            "program": self.program,
            "authorized_by": self.authorized_by,
            "authorization_ref": self.authorization_ref,
            "include": list(self.include),
            "exclude": list(self.exclude),
            "authorized_networks": list(self.authorized_networks),
            "allowed_ports": list(self.allowed_ports),
            "allow_broad_networks": self.allow_broad_networks,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "issuer": self.issuer,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Any) -> Grant:
        if not isinstance(data, dict):
            raise ProofError("grant must be a JSON object")
        unknown = sorted(set(data) - set(_GRANT_FIELDS) - {"signature"})
        if unknown:
            raise ProofError(
                f"grant has unknown field(s): {', '.join(unknown)}; allowed fields "
                f"are: {', '.join(sorted(_GRANT_FIELDS))}, signature"
            )
        if data.get("version") != VERSION:
            raise ProofError(
                f"unsupported grant version {data.get('version')!r} (expected {VERSION})"
            )
        try:
            signature = data["signature"]
            include = data["include"]
            if not isinstance(include, list) or not include:
                raise ProofError("grant field 'include' must be a non-empty list")
            for field in ("exclude", "authorized_networks", "allowed_ports"):
                if not isinstance(data.get(field, []), list):
                    raise ProofError(f"grant field {field!r} must be a list")
            return cls(
                grant_id=str(data["grant_id"]),
                program=str(data["program"]),
                authorized_by=str(data["authorized_by"]),
                authorization_ref=str(data["authorization_ref"]),
                include=tuple(str(host) for host in include),
                exclude=tuple(str(host) for host in data.get("exclude", [])),
                authorized_networks=tuple(
                    str(net) for net in data.get("authorized_networks", [])
                ),
                allowed_ports=tuple(int(port) for port in data.get("allowed_ports", [])),
                allow_broad_networks=bool(data.get("allow_broad_networks", False)),
                not_before=float(data["not_before"]),
                not_after=float(data["not_after"]),
                issuer=str(data["issuer"]),
                signature=str(signature),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProofError(f"grant field is malformed: {exc}") from None

    def sign(self, private_key: str) -> Grant:
        """Sign the grant, making this key the issuer. Validates scope first."""
        self.to_scope()
        body = replace(self, issuer=public_key(private_key)).body()
        return replace(
            self, issuer=body["issuer"], signature=sign(body, private_key)
        )

    def verify(
        self, *, trusted_issuer: str | None = None, now: float | None = None
    ) -> tuple[bool, str]:
        """(True, '') when the grant is intact, in scope shape and current."""
        if not self.signature:
            return False, "grant is not signed"
        if not verify_signature(self.body(), self.signature, self.issuer):
            return (
                False,
                "grant signature does not verify (the document was altered, or "
                "it was signed by a different key than the issuer field names)",
            )
        if trusted_issuer and self.issuer != trusted_issuer:
            return (
                False,
                f"grant was signed by {fingerprint(self.issuer)}, not the pinned "
                f"issuer {fingerprint(trusted_issuer)}",
            )
        if self.not_after <= self.not_before:
            return False, "grant validity window is empty"
        try:
            self.to_scope()
        except ValueError as exc:
            return False, f"grant scope is invalid: {exc}"
        if now is not None:
            return self.is_active(now)
        return True, ""

    def is_active(self, now: float | None = None) -> tuple[bool, str]:
        moment = time.time() if now is None else now
        if moment < self.not_before:
            return False, f"grant is not effective until {_iso(self.not_before)}"
        if moment >= self.not_after:
            return False, f"grant expired at {_iso(self.not_after)}"
        return True, ""

    def to_scope(self) -> Scope:
        """The gate snapshot this grant authorizes (raises ValueError if broken)."""
        return Scope(
            program=self.program,
            authorized_by=self.authorized_by,
            authorization_ref=self.authorization_ref,
            include=self.include,
            exclude=self.exclude,
            authorized_networks=self.authorized_networks,
            allowed_ports=self.allowed_ports,
            allow_broad_networks=self.allow_broad_networks,
        )


def new_grant(
    *,
    program: str,
    authorized_by: str,
    authorization_ref: str,
    include: list[str] | tuple[str, ...],
    exclude: list[str] | tuple[str, ...] = (),
    authorized_networks: list[str] | tuple[str, ...] = (),
    allowed_ports: list[int] | tuple[int, ...] = (),
    allow_broad_networks: bool = False,
    days: float = 30.0,
    grant_id: str = "",
    now: float | None = None,
) -> Grant:
    """An unsigned grant effective now for ``days``; call :meth:`Grant.sign`."""
    moment = time.time() if now is None else now
    return Grant(
        grant_id=grant_id or f"gr_{secrets.token_hex(8)}",
        program=program.strip(),
        authorized_by=authorized_by.strip(),
        authorization_ref=authorization_ref.strip(),
        include=tuple(include),
        exclude=tuple(exclude),
        authorized_networks=tuple(authorized_networks),
        allowed_ports=tuple(allowed_ports),
        allow_broad_networks=bool(allow_broad_networks),
        not_before=moment,
        not_after=moment + float(days) * 86400,
    )


def load_grant(path: str | Path) -> Grant:
    try:
        data = json.loads(Path(path).expanduser().read_text())
    except json.JSONDecodeError as exc:
        raise ProofError(f"{path} is not valid JSON: {exc}") from None
    return Grant.from_dict(data)


# -- receipts ----------------------------------------------------------------

_RECEIPT_FIELDS = (
    "seq",
    "grant_id",
    "grant_digest",
    "actor",
    "url",
    "method",
    "decision",
    "reason",
    "timestamp",
    "previous",
)


@dataclass(frozen=True)
class Receipt:
    """One signed gate decision, chained to the receipt before it."""

    seq: int
    grant_id: str
    grant_digest: str
    actor: str
    url: str
    method: str
    decision: str
    reason: str
    timestamp: float
    previous: str
    hash: str
    signature: str

    def body(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "grant_id": self.grant_id,
            "grant_digest": self.grant_digest,
            "actor": self.actor,
            "url": self.url,
            "method": self.method,
            "decision": self.decision,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "previous": self.previous,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "hash": self.hash, "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Any) -> Receipt:
        if not isinstance(data, dict):
            raise ProofError("receipt must be a JSON object")
        unknown = sorted(set(data) - set(_RECEIPT_FIELDS) - {"hash", "signature"})
        if unknown:
            raise ProofError(f"receipt has unknown field(s): {', '.join(unknown)}")
        try:
            return cls(
                seq=int(data["seq"]),
                grant_id=str(data["grant_id"]),
                grant_digest=str(data["grant_digest"]),
                actor=str(data["actor"]),
                url=str(data["url"]),
                method=str(data["method"]),
                decision=str(data["decision"]),
                reason=str(data["reason"]),
                timestamp=float(data["timestamp"]),
                previous=str(data["previous"]),
                hash=str(data["hash"]),
                signature=str(data["signature"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProofError(f"receipt field is malformed: {exc}") from None

    def signature_ok(self, gate_public_key: str) -> bool:
        return verify_signature({"hash": self.hash}, self.signature, gate_public_key)


def _verify_chain(receipts: list[Receipt], gate_public_key: str) -> str:
    """'' when the chain is intact, else the first problem found."""
    expected_previous, expected_seq = GENESIS, 1
    for receipt in receipts:
        if receipt.seq != expected_seq:
            return (
                f"receipt sequence broken: expected {expected_seq}, "
                f"found {receipt.seq}"
            )
        if receipt.previous != expected_previous:
            return f"receipt {receipt.seq} does not commit to the previous receipt"
        if digest(receipt.body()) != receipt.hash:
            return f"receipt {receipt.seq} hash does not match its contents"
        if not receipt.signature_ok(gate_public_key):
            return f"receipt {receipt.seq} signature does not verify"
        expected_previous, expected_seq = receipt.hash, expected_seq + 1
    return ""


class Ledger:
    """The gate's receipt log: in memory, optionally appended to JSONL."""

    def __init__(
        self, *, signing_key: str = "", actor: str = "", path: str | Path | None = None
    ) -> None:
        self._key = signing_key
        self.actor = actor
        self.path = Path(path).expanduser() if path else None
        self.header: dict[str, Any] = {}
        self._receipts: list[Receipt] = []
        self._lock = threading.Lock()
        if self.path and self.path.exists() and self.path.stat().st_size:
            self._load()

    @property
    def receipts(self) -> list[Receipt]:
        return list(self._receipts)

    @property
    def gate_public_key(self) -> str:
        if self._key:
            return public_key(self._key)
        return str(self.header.get("gate_public_key", ""))

    @classmethod
    def open(cls, path: str | Path) -> Ledger:
        """Read an existing ledger without a signing key (verification only)."""
        ledger = cls(path=path)
        if not ledger.header:
            raise ProofError(f"{path} is not a Strix Proof ledger")
        return ledger

    def _load(self) -> None:
        assert self.path is not None
        try:
            rows = [
                json.loads(line)
                for line in self.path.read_text().splitlines()
                if line.strip()
            ]
        except json.JSONDecodeError as exc:
            raise ProofError(f"{self.path} is not valid JSONL: {exc}") from None
        if not rows or rows[0].get("type") != LEDGER_TYPE:
            raise ProofError(f"{self.path} does not start with a Strix Proof ledger header")
        self.header = rows[0]
        self._receipts = [Receipt.from_dict(row) for row in rows[1:]]

    def ensure_header(self, grant: Grant) -> None:
        """Create the ledger header, or refuse a ledger belonging to another grant."""
        grant_digest = digest(grant.body())
        if self.header:
            if (
                self.header.get("grant_id") != grant.grant_id
                or self.header.get("grant_digest") != grant_digest
            ):
                raise ProofError(
                    f"ledger {self.path} belongs to grant "
                    f"{self.header.get('grant_id')}, not {grant.grant_id}"
                )
            if self.gate_public_key != self.header.get("gate_public_key"):
                raise ProofError(
                    f"ledger {self.path} was written by gate key "
                    f"{self.header.get('gate_public_key')}, not {self.gate_public_key}"
                )
            return
        self.header = {
            "version": VERSION,
            "type": LEDGER_TYPE,
            "grant_id": grant.grant_id,
            "grant_digest": grant_digest,
            "gate_public_key": self.gate_public_key,
            "actor": self.actor,
            "created_at": time.time(),
        }
        if self.path:
            self._write(self.header)

    def _write(self, row: dict[str, Any]) -> None:
        assert self.path is not None
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    def record(
        self,
        grant: Grant,
        *,
        url: str,
        method: str,
        decision: str,
        reason: str,
        now: float | None = None,
    ) -> Receipt:
        if not self._key:
            raise ProofError("this ledger is read-only: no gate signing key")
        if not self.header:
            raise ProofError("call ensure_header() before recording")
        if decision not in ("allow", "deny"):
            raise ProofError(f"decision {decision!r} must be 'allow' or 'deny'")
        with self._lock:
            body: dict[str, Any] = {
                "seq": self._receipts[-1].seq + 1 if self._receipts else 1,
                "grant_id": grant.grant_id,
                "grant_digest": digest(grant.body()),
                "actor": self.actor,
                "url": url,
                "method": method[:16],
                "decision": decision,
                "reason": reason,
                "timestamp": time.time() if now is None else now,
                "previous": self._receipts[-1].hash if self._receipts else GENESIS,
            }
            receipt = Receipt(
                **body,
                hash=digest(body),
                signature=sign({"hash": digest(body)}, self._key),
            )
            self._receipts.append(receipt)
            if self.path:
                self._write(receipt.to_dict())
            return receipt

    def verify(self) -> tuple[bool, str]:
        problem = _verify_chain(self._receipts, self.gate_public_key)
        return (False, problem) if problem else (True, "")


# -- gate --------------------------------------------------------------------


class Gate:
    """Enforces one signed grant and receipts every decision it makes."""

    def __init__(
        self,
        grant: Grant,
        *,
        signing_key: str = "",
        actor: str = "agent",
        ledger_path: str | Path | None = None,
        trusted_issuer: str | None = None,
        now: float | None = None,
    ) -> None:
        ok, reason = grant.verify(trusted_issuer=trusted_issuer)
        if not ok:
            raise ProofError(reason)
        active, reason = grant.is_active(now)
        if not active:
            raise ProofError(reason)
        self.grant = grant
        self.scope = grant.to_scope()
        self._ledger = Ledger(
            signing_key=signing_key or new_keypair()[0],
            actor=actor,
            path=ledger_path,
        )
        self._ledger.ensure_header(grant)

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    def authorize(
        self, url: str, method: str = "GET", *, now: float | None = None
    ) -> Receipt:
        """Decide one action and receipt it. Never raises for a denied action."""
        active, reason = self.grant.is_active(now)
        if not active:
            return self._ledger.record(
                self.grant, url=url, method=method, decision="deny", reason=reason, now=now
            )
        denial, reason, _destination = self.scope.destination(url)
        return self._ledger.record(
            self.grant,
            url=url,
            method=method,
            decision="deny" if denial else "allow",
            reason=f"{denial}: {reason}" if denial else "",
            now=now,
        )

    @contextmanager
    def observe(self) -> Iterator[Gate]:
        """Receipt every :mod:`strix.core.scope` decision made in this block.

        This is how a Strix scan under a grant produces evidence: the adapters
        keep using the same gate, and each decision it takes is recorded here.
        """
        from strix.core.scope import reset_observer, set_observer

        token = set_observer(self._observed)
        try:
            yield self
        finally:
            reset_observer(token)

    def _observed(self, url: str, denial: str, reason: str) -> None:
        self._ledger.record(
            self.grant,
            url=url,
            method="",
            decision="deny" if denial else "allow",
            reason=f"{denial}: {reason}" if denial else "",
        )


# -- proof pack --------------------------------------------------------------


def build_pack(grant: Grant, ledger: Ledger, *, issued_at: float | None = None) -> dict:
    """Bundle a grant and its receipts. Refuses a ledger with a broken chain."""
    ok, reason = ledger.verify()
    if not ok:
        raise ProofError(f"refusing to build a proof from a broken ledger: {reason}")
    receipts = ledger.receipts
    allowed = [r for r in receipts if r.decision == "allow"]
    denied = [r for r in receipts if r.decision == "deny"]
    hosts = sorted({urlparse(r.url).hostname or "" for r in receipts})
    return {
        "version": VERSION,
        "issued_at": time.time() if issued_at is None else issued_at,
        "grant": grant.to_dict(),
        "grant_digest": digest(grant.body()),
        "gate": {
            "public_key": ledger.gate_public_key,
            "fingerprint": fingerprint(ledger.gate_public_key),
            "actor": ledger.header.get("actor", ""),
        },
        "receipts": [r.to_dict() for r in receipts],
        "summary": {
            "allowed": len(allowed),
            "denied": len(denied),
            "hosts": hosts,
            "first": receipts[0].timestamp if receipts else None,
            "last": receipts[-1].timestamp if receipts else None,
            "chain_head": receipts[-1].hash if receipts else GENESIS,
        },
    }


def verify_pack(
    pack: Any,
    *,
    trusted_issuer: str | None = None,
    trusted_gate: str | None = None,
) -> dict:
    """Check a proof pack offline. Returns a report; never raises for bad input."""
    errors: list[str] = []
    checks = {
        "grant_signature": False,
        "issuer_trusted": False,
        "chain": False,
        "scope_compliance": False,
        "gate_key": False,
    }
    summary: dict[str, Any] = {}

    if not isinstance(pack, dict):
        return {
            "ok": False,
            "checks": checks,
            "errors": ["proof pack must be a JSON object"],
            "summary": summary,
        }
    if pack.get("version") != VERSION:
        errors.append(
            f"unsupported proof version {pack.get('version')!r} (expected {VERSION})"
        )
    try:
        grant = Grant.from_dict(pack.get("grant"))
    except ProofError as exc:
        return {
            "ok": False,
            "checks": checks,
            "errors": [*errors, f"grant: {exc}"],
            "summary": summary,
        }

    def _report() -> dict:
        return {
            "ok": not errors,
            "checks": checks,
            "errors": errors,
            "summary": summary,
        }

    # 1. The authorization itself.
    grant_ok, reason = grant.verify(trusted_issuer=trusted_issuer)
    checks["grant_signature"] = grant_ok
    checks["issuer_trusted"] = bool(trusted_issuer) and grant.issuer == trusted_issuer
    if not grant_ok:
        errors.append(f"grant: {reason}")
        return _report()

    # 2. The gate that took the decisions.
    gate = pack.get("gate") or {}
    gate_key = str(gate.get("public_key", ""))
    checks["gate_key"] = bool(gate_key) and (
        not trusted_gate or gate_key == trusted_gate
    )
    if trusted_gate and gate_key != trusted_gate:
        errors.append(
            f"proof gate key {fingerprint(gate_key) if gate_key else '(missing)'} "
            f"is not the pinned gate {fingerprint(trusted_gate)}"
        )
        return _report()

    # 3. Receipts: structure, hash chain, gate signatures.
    receipts: list[Receipt] = []
    try:
        for row in pack.get("receipts") or []:
            receipts.append(Receipt.from_dict(row))
    except (ProofError, TypeError) as exc:
        errors.append(f"receipts: {exc}")
        return _report()
    problem = _verify_chain(receipts, gate_key)
    checks["chain"] = not problem
    if problem:
        errors.append(f"receipts: {problem}")
        return _report()

    # 4. Every allowed action must be inside the grant, at a moment it covered.
    scope = grant.to_scope()
    grant_digest = digest(grant.body())
    allowed = denied = 0
    scope_errors = 0
    for receipt in receipts:
        if receipt.grant_id != grant.grant_id:
            errors.append(
                f"receipt {receipt.seq} cites grant {receipt.grant_id}, not {grant.grant_id}"
            )
            scope_errors += 1
        if receipt.grant_digest != grant_digest:
            errors.append(f"receipt {receipt.seq} cites a different grant document")
            scope_errors += 1
        if receipt.decision == "allow":
            allowed += 1
            denial, why = scope.gate(receipt.url)
            if denial:
                errors.append(
                    f"receipt {receipt.seq} allowed {receipt.url!r}, which the grant "
                    f"does not cover: {why}"
                )
                scope_errors += 1
            if not grant.not_before <= receipt.timestamp < grant.not_after:
                errors.append(
                    f"receipt {receipt.seq} was recorded at "
                    f"{_iso(receipt.timestamp)}, outside the grant window "
                    f"{_iso(grant.not_before)}..{_iso(grant.not_after)}"
                )
                scope_errors += 1
        elif receipt.decision == "deny":
            denied += 1
        else:
            errors.append(
                f"receipt {receipt.seq} has decision {receipt.decision!r} "
                "(expected allow or deny)"
            )
            scope_errors += 1
    checks["scope_compliance"] = scope_errors == 0

    # 5. The claimed summary must be the receipts' own arithmetic.
    claimed = pack.get("summary") or {}
    chain_head = receipts[-1].hash if receipts else GENESIS
    if claimed.get("allowed") != allowed or claimed.get("denied") != denied:
        errors.append("summary counts do not match the receipts")
    if claimed.get("chain_head") != chain_head:
        errors.append("summary chain head does not match the receipts")
    if claimed.get("hosts") is not None and claimed.get("hosts") != sorted(
        {urlparse(r.url).hostname or "" for r in receipts}
    ):
        errors.append("summary hosts do not match the receipts")

    summary = {
        "grant_id": grant.grant_id,
        "program": grant.program,
        "authorized_by": grant.authorized_by,
        "authorization_ref": grant.authorization_ref,
        "issuer": grant.issuer,
        "issuer_fingerprint": fingerprint(grant.issuer),
        "gate_fingerprint": fingerprint(gate_key) if gate_key else "",
        "actor": str(gate.get("actor", "")),
        "allowed": allowed,
        "denied": denied,
        "first": receipts[0].timestamp if receipts else None,
        "last": receipts[-1].timestamp if receipts else None,
        "window": [_iso(grant.not_before), _iso(grant.not_after)],
    }
    return _report()


# -- HTTP gate ---------------------------------------------------------------


def serve(
    gate: Gate,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    token: str = "",
) -> None:
    """Serve the gate over HTTP until interrupted.

    Binds to loopback by default. Exposing it on another address requires a
    bearer token, because an open gate authorizes actions on the asset owner's
    behalf.
    """
    if host not in ("127.0.0.1", "::1", "localhost") and not token:
        raise ProofError(
            f"refusing to serve the gate on {host} without a bearer token; "
            "pass --token or set STRIX_PROOF_TOKEN"
        )
    grant = gate.grant

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            if not token:
                return True
            provided = self.headers.get("Authorization", "")
            return hmac.compare_digest(provided, f"Bearer {token}")

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            if self.path == "/health":
                return self._send(
                    200,
                    {
                        "status": "ok",
                        "grant_id": grant.grant_id,
                        "receipts": len(gate.ledger.receipts),
                    },
                )
            if self.path == "/v1/grant":
                return self._send(200, grant.to_dict())
            if self.path == "/v1/receipts":
                return self._send(
                    200, {"receipts": [r.to_dict() for r in gate.ledger.receipts]}
                )
            if self.path == "/v1/proof":
                return self._send(200, build_pack(grant, gate.ledger))
            return self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802 (http.server API)
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            if self.path != "/v1/authorize":
                return self._send(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._send(413, {"error": "request body too large"})
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                return self._send(400, {"error": "body must be JSON"})
            if not isinstance(payload, dict) or not isinstance(payload.get("url"), str):
                return self._send(400, {"error": 'body must be {"url": "https://..."}'})
            receipt = gate.authorize(
                payload["url"], str(payload.get("method") or "GET").upper()
            )
            return self._send(
                200 if receipt.decision == "allow" else 403,
                {
                    "decision": receipt.decision,
                    "reason": receipt.reason,
                    "receipt": receipt.to_dict(),
                },
            )

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer((host, port), Handler)
    log.info("strix gate serving grant %s on %s:%d", grant.grant_id, host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()

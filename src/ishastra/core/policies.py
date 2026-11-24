"""Engagement authorization policies: one authorization boundary per customer
engagement, so one tenant's assessment is never judged against another's.

:class:`EngagementPolicy` is the frozen record -- who authorized it, what it
covers, for whom, until when, which version, still active.
:class:`PolicyRegistry` creates, versions and revokes them with every change in
SQLite; scope fields are validated by building the very :class:`Scope`
snapshot that will enforce them. :func:`validate_job_binding` is the
execution-time check: a worker refuses a job whose policy has since been
revoked, expired, or was never the tenant's to use.

The binding is enforced at submission (403 against that policy), in the
persisted job record (policy id + version), again at execution, and at every
connection through the bound snapshot. Policy mutations are administrator
operations -- gated and audited by the API layer.
"""

from __future__ import annotations

import asyncio
import re
import secrets
import threading
import time
from dataclasses import dataclass, replace
from functools import wraps
from typing import Any

from ishastra.core import store
from ishastra.core.locks import _ReentrantAsyncLock, async_locked
from ishastra.core.scope import Scope

TENANT_ID = re.compile(r"[A-Za-z0-9_.-]{1,64}")
POLICY_STATUSES = ("active", "revoked")


class PolicyError(ValueError):
    """The policy record is unusable; nothing was created or changed."""


def _now() -> float:
    return time.time()


def new_policy_id() -> str:
    return f"pol_{secrets.token_hex(6)}"


@dataclass(frozen=True)
class EngagementPolicy:
    """One customer engagement's authorization, versioned and revocable."""

    policy_id: str
    tenant_id: str
    program: str
    authorized_by: str
    authorization_ref: str
    include: tuple[str, ...]
    exclude: tuple[str, ...] = ()
    authorized_networks: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = ()
    allowed_asns: tuple[int, ...] = ()
    allowed_countries: tuple[str, ...] = ()
    allow_broad_networks: bool = False
    rate_limit_rps: int = 0
    status: str = "active"
    version: int = 1
    created_at: float = 0.0
    updated_at: float = 0.0
    effective_at: float | None = None
    expires_at: float | None = None
    created_by: str = ""

    def __post_init__(self) -> None:
        missing = [
            name
            for name in (
                "policy_id",
                "tenant_id",
                "program",
                "authorized_by",
                "authorization_ref",
            )
            if not str(getattr(self, name, "") or "").strip()
        ]
        if missing:
            raise PolicyError(f"policy record incomplete: missing {', '.join(missing)}")
        if not TENANT_ID.fullmatch(self.tenant_id):
            raise PolicyError(f"tenant_id {self.tenant_id!r} is not a valid tenant id")
        if self.status not in POLICY_STATUSES:
            raise PolicyError(f"status {self.status!r} must be one of {POLICY_STATUSES}")
        if self.version < 1:
            raise PolicyError("version must be a positive integer")
        if (
            self.effective_at is not None
            and self.expires_at is not None
            and float(self.effective_at) >= float(self.expires_at)
        ):
            raise PolicyError("effective_at must be earlier than expires_at")
        if (
            not isinstance(self.rate_limit_rps, int)
            or isinstance(self.rate_limit_rps, bool)
            or self.rate_limit_rps < 0
            or self.rate_limit_rps > 1000
        ):
            raise PolicyError("rate_limit_rps must be an integer from 0 to 1000")

    def is_valid(self, *, now: float | None = None) -> tuple[bool, str]:
        """(True, '') when the policy may be used at ``now``, else (False, why)."""
        moment = _now() if now is None else now
        if self.status != "active":
            return False, f"authorization policy {self.policy_id} is {self.status}"
        if self.effective_at is not None and moment < float(self.effective_at):
            return False, (
                f"authorization policy {self.policy_id} is not yet effective (from {self.effective_at})"
            )
        if self.expires_at is not None and moment >= float(self.expires_at):
            return (
                False,
                f"authorization policy {self.policy_id} expired at {self.expires_at}",
            )
        return True, ""

    def lifecycle_state(self, *, now: float | None = None) -> str:
        """One word for the lifecycle view: draft, active, revoked or expired."""
        moment = _now() if now is None else now
        if self.status == "revoked":
            return "revoked"
        if self.is_valid(now=moment)[0]:
            return "active"
        if self.expires_at is not None and moment >= float(self.expires_at):
            return "expired"
        return "draft"

    def to_scope(self) -> Scope:
        """A validated gate snapshot of this policy (raises ValueError if broken)."""
        return Scope(
            program=self.program,
            authorized_by=self.authorized_by,
            authorization_ref=self.authorization_ref,
            include=self.include,
            exclude=self.exclude,
            authorized_networks=self.authorized_networks,
            allowed_ports=self.allowed_ports,
            allowed_asns=self.allowed_asns,
            allowed_countries=self.allowed_countries,
            policy_id=self.policy_id,
            policy_version=self.version,
            tenant_id=self.tenant_id,
            allow_broad_networks=self.allow_broad_networks,
            rules_of_engagement={"rate_limit_rps": self.rate_limit_rps} if self.rate_limit_rps else {},
        )

    def to_dict(self, *, include_hosts: bool = False) -> dict[str, Any]:
        """Safe projection for API responses. Host lists only when asked."""
        data: dict[str, Any] = {
            "policy_id": self.policy_id,
            "tenant_id": self.tenant_id,
            "program": self.program,
            "authorized_by": self.authorized_by,
            "authorization_ref": self.authorization_ref,
            "status": self.status,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "effective_at": self.effective_at,
            "expires_at": self.expires_at,
            "created_by": self.created_by,
            "allow_broad_networks": self.allow_broad_networks,
            "rate_limit_rps": self.rate_limit_rps,
            "allowed_ports": list(self.allowed_ports),
            "allowed_asns": list(self.allowed_asns),
            "allowed_countries": list(self.allowed_countries),
        }
        if include_hosts:
            data["include"] = list(self.include)
            data["exclude"] = list(self.exclude)
            data["authorized_networks"] = list(self.authorized_networks)
        return data

    def to_row(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "tenant_id": self.tenant_id,
            "program": self.program,
            "authorized_by": self.authorized_by,
            "authorization_ref": self.authorization_ref,
            "include": list(self.include),
            "exclude": list(self.exclude),
            "authorized_networks": list(self.authorized_networks),
            "allowed_ports": list(self.allowed_ports),
            "allowed_asns": list(self.allowed_asns),
            "allowed_countries": list(self.allowed_countries),
            "allow_broad_networks": self.allow_broad_networks,
            "rate_limit_rps": self.rate_limit_rps,
            "status": self.status,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "effective_at": self.effective_at,
            "expires_at": self.expires_at,
            "created_by": self.created_by,
        }

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> EngagementPolicy:
        return cls(
            policy_id=row["policy_id"],
            tenant_id=row["tenant_id"],
            program=row["program"],
            authorized_by=row["authorized_by"],
            authorization_ref=row["authorization_ref"],
            include=tuple(row["include"]),
            exclude=tuple(row["exclude"]),
            authorized_networks=tuple(row["authorized_networks"]),
            allowed_ports=tuple(row["allowed_ports"]),
            allowed_asns=tuple(row.get("allowed_asns") or ()),
            allowed_countries=tuple(row.get("allowed_countries") or ()),
            allow_broad_networks=bool(row["allow_broad_networks"]),
            rate_limit_rps=int(row.get("rate_limit_rps") or 0),
            status=row["status"],
            version=int(row["version"]),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            effective_at=row["effective_at"],
            expires_at=row["expires_at"],
            created_by=row.get("created_by", ""),
        )


def _registry_locked(method):
    """Serialize one registry operation; RLock permits nested helper calls."""

    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapped


class PolicyRegistry:
    """Thread-safe, SQLite-backed registry of engagement policies."""

    def __init__(self) -> None:
        self._policies: dict[str, EngagementPolicy] = {}
        self._loaded = False
        self._lock = threading.RLock()
        self._async_lock: _ReentrantAsyncLock | None = None

    def _get_async_lock(self) -> _ReentrantAsyncLock:
        """Get or create the async lock in the current event loop."""

        if self._async_lock is not None:
            return self._async_lock

        with self._lock:
            if self._async_lock is None:
                self._async_lock = _ReentrantAsyncLock()
            return self._async_lock

    @async_locked
    async def load_async(self) -> int:
        """Replace the in-memory view with what the database holds (startup)."""
        rows = await store.load_policies()
        self._policies = {row["policy_id"]: EngagementPolicy.from_row(row) for row in rows}
        self._loaded = True
        return len(self._policies)

    @_registry_locked
    def load(self) -> int:
        """Sync wrapper for load_async (for non-async callers)."""
        return asyncio.run(self.load_async())

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    async def _ensure_loaded_async(self) -> None:
        if not self._loaded:
            await self.load_async()

    @async_locked
    async def create_async(
        self,
        *,
        tenant_id: str,
        program: str,
        authorized_by: str,
        authorization_ref: str,
        include: list[str],
        exclude: list[str] | None = None,
        authorized_networks: list[str] | None = None,
        allowed_ports: list[int] | None = None,
        allowed_asns: list[int] | None = None,
        allowed_countries: list[str] | None = None,
        allow_broad_networks: bool = False,
        rate_limit_rps: int = 0,
        effective_at: float | None = None,
        expires_at: float | None = None,
        created_by: str = "",
        policy_id: str | None = None,
    ) -> EngagementPolicy:
        """Validate and persist a new policy. Scope fields are checked by
        building the gate snapshot, so an unparsable host or a dangerously
        broad CIDR is refused here, before any assessment can cite it."""
        await self._ensure_loaded_async()
        moment = _now()
        chosen_id = policy_id or new_policy_id()
        if chosen_id in self._policies:
            raise PolicyError(f"policy {chosen_id} already exists")
        policy = EngagementPolicy(
            policy_id=chosen_id,
            tenant_id=tenant_id.strip(),
            program=program.strip(),
            authorized_by=authorized_by.strip(),
            authorization_ref=authorization_ref.strip(),
            include=tuple(include),
            exclude=tuple(exclude or ()),
            authorized_networks=tuple(authorized_networks or ()),
            allowed_ports=tuple(allowed_ports or ()),
            allowed_asns=tuple(allowed_asns or ()),
            allowed_countries=tuple(allowed_countries or ()),
            allow_broad_networks=bool(allow_broad_networks),
            rate_limit_rps=rate_limit_rps,
            status="active",
            version=1,
            created_at=moment,
            updated_at=moment,
            effective_at=effective_at,
            expires_at=expires_at,
            created_by=created_by.strip(),
        )
        try:
            policy.to_scope()
        except ValueError as exc:
            raise PolicyError(str(exc)) from exc

        if policy.expires_at is not None and float(policy.expires_at) <= moment:
            raise PolicyError("expires_at must be in the future")
        await store.save_policy(policy.to_row())
        self._policies[policy.policy_id] = policy
        return policy

    @_registry_locked
    def create(
        self,
        *,
        tenant_id: str,
        program: str,
        authorized_by: str,
        authorization_ref: str,
        include: list[str],
        exclude: list[str] | None = None,
        authorized_networks: list[str] | None = None,
        allowed_ports: list[int] | None = None,
        allowed_asns: list[int] | None = None,
        allowed_countries: list[str] | None = None,
        allow_broad_networks: bool = False,
        rate_limit_rps: int = 0,
        effective_at: float | None = None,
        expires_at: float | None = None,
        created_by: str = "",
        policy_id: str | None = None,
    ) -> EngagementPolicy:
        """Sync wrapper for create_async (for non-async callers)."""
        return asyncio.run(
            self.create_async(
                tenant_id=tenant_id,
                program=program,
                authorized_by=authorized_by,
                authorization_ref=authorization_ref,
                include=include,
                exclude=exclude,
                authorized_networks=authorized_networks,
                allowed_ports=allowed_ports,
                allowed_asns=allowed_asns,
                allowed_countries=allowed_countries,
                allow_broad_networks=allow_broad_networks,
                rate_limit_rps=rate_limit_rps,
                effective_at=effective_at,
                expires_at=expires_at,
                created_by=created_by,
                policy_id=policy_id,
            )
        )

    @async_locked
    async def update_async(self, policy_id: str, **changes: Any) -> EngagementPolicy:
        """Apply field changes as a new version. Status changes go via revoke()."""
        await self._ensure_loaded_async()
        current = self._policies.get(policy_id)
        if current is None:
            raise PolicyError(f"unknown policy {policy_id}")
        if "status" in changes and changes["status"] != current.status:
            raise PolicyError("status changes must go through revoke()")
        allowed = {
            "program",
            "authorized_by",
            "authorization_ref",
            "include",
            "exclude",
            "authorized_networks",
            "allowed_ports",
            "allowed_asns",
            "allowed_countries",
            "allow_broad_networks",
            "rate_limit_rps",
            "effective_at",
            "expires_at",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise PolicyError(f"cannot update field(s): {', '.join(sorted(unknown))}")
        for field in (
            "include",
            "exclude",
            "authorized_networks",
            "allowed_ports",
            "allowed_asns",
            "allowed_countries",
        ):
            if field in changes:
                changes[field] = tuple(changes[field])
        updated = replace(current, version=current.version + 1, updated_at=_now(), **changes)
        try:
            updated.to_scope()
        except ValueError as exc:
            raise PolicyError(str(exc)) from exc
        if updated.expires_at is not None and float(updated.expires_at) <= _now():
            raise PolicyError("expires_at must be in the future")
        await store.save_policy(updated.to_row())
        self._policies[policy_id] = updated
        return updated

    @_registry_locked
    def update(self, policy_id: str, **changes: Any) -> EngagementPolicy:
        """Sync wrapper for update_async (for non-async callers)."""
        return asyncio.run(self.update_async(policy_id, **changes))

    @async_locked
    async def revoke_async(self, policy_id: str, *, now: float | None = None) -> EngagementPolicy:
        """Revoke: no new submission, no worker start, queued/running jobs cancelled."""
        await self._ensure_loaded_async()
        current = self._policies.get(policy_id)
        if current is None:
            raise PolicyError(f"unknown policy {policy_id}")
        revoked = replace(current, status="revoked", version=current.version + 1, updated_at=_now())
        await store.save_policy(revoked.to_row())
        self._policies[policy_id] = revoked
        return revoked

    @_registry_locked
    def revoke(self, policy_id: str, *, now: float | None = None) -> EngagementPolicy:
        """Sync wrapper for revoke_async (for non-async callers)."""
        return asyncio.run(self.revoke_async(policy_id, now=now))

    @_registry_locked
    def get(self, policy_id: str) -> EngagementPolicy | None:
        self._ensure_loaded()
        return self._policies.get(policy_id)

    @async_locked
    async def get_async(self, policy_id: str) -> EngagementPolicy | None:
        await self._ensure_loaded_async()
        return self._policies.get(policy_id)

    @_registry_locked
    def list(self, tenant_id: str | None = None) -> list[EngagementPolicy]:
        self._ensure_loaded()
        policies = sorted(self._policies.values(), key=lambda p: (p.tenant_id, p.created_at))
        if tenant_id is None:
            return policies
        return [p for p in policies if p.tenant_id == tenant_id]

    @async_locked
    async def list_async(self, tenant_id: str | None = None) -> list[EngagementPolicy]:  # type: ignore[valid-type]
        await self._ensure_loaded_async()
        policies = sorted(self._policies.values(), key=lambda p: (p.tenant_id, p.created_at))
        if tenant_id is None:
            return policies
        return [p for p in policies if p.tenant_id == tenant_id]

    @_registry_locked
    def resolve(
        self, tenant_id: str, policy_id: str | None = None, *, now: float | None = None
    ) -> tuple[EngagementPolicy | None, str]:
        """The policy a tenant may assess under right now, or the refusal reason.

        With ``policy_id``: that exact policy must belong to the tenant and be
        valid. Without: the tenant's newest valid active policy wins (zero
        configuration for the common single-engagement tenant).
        """
        self._ensure_loaded()
        if policy_id:
            policy = self._policies.get(policy_id)
            if policy is None or policy.tenant_id != tenant_id:
                return None, "no such authorization policy for this tenant"
            valid, reason = policy.is_valid(now=now)
            return (policy, "") if valid else (None, reason)
        candidates = [p for p in self._policies.values() if p.tenant_id == tenant_id]
        if not candidates:
            return None, f"no authorization policy exists for tenant {tenant_id}"
        for policy in sorted(candidates, key=lambda p: p.created_at, reverse=True):
            valid, reason = policy.is_valid(now=now)
            if valid:
                return policy, ""
        return None, reason or "no usable authorization policy for this tenant"

    @async_locked
    async def resolve_async(
        self, tenant_id: str, policy_id: str | None = None, *, now: float | None = None
    ) -> tuple[EngagementPolicy | None, str]:
        """Async version of resolve."""
        await self._ensure_loaded_async()
        if policy_id:
            policy = self._policies.get(policy_id)
            if policy is None or policy.tenant_id != tenant_id:
                return None, "no such authorization policy for this tenant"
            valid, reason = policy.is_valid(now=now)
            return (policy, "") if valid else (None, reason)
        candidates = [p for p in self._policies.values() if p.tenant_id == tenant_id]
        if not candidates:
            return None, f"no authorization policy exists for tenant {tenant_id}"
        for policy in sorted(candidates, key=lambda p: p.created_at, reverse=True):
            valid, reason = policy.is_valid(now=now)
            if valid:
                return policy, ""
        return None, reason or "no usable authorization policy for this tenant"


registry = PolicyRegistry()


def tenant_scope_snapshot(
    tenant_id: str,
    policy_id: str | None = None,
    *,
    now: float | None = None,
    parent_scope: Scope | None = None,
) -> tuple[Scope | None, str]:
    """(validated gate snapshot, '') or (None, refusal reason) for a tenant.

    ``parent_scope`` is the organization default this engagement must stay
    inside; the snapshot can only narrow, never widen, that policy.
    """
    policy, reason = registry.resolve(tenant_id, policy_id, now=now)
    if policy is None:
        return None, reason
    try:
        scope = policy.to_scope()
        if parent_scope is not None:
            scope = scope.inherited_from(parent_scope)
        return scope, ""
    except ValueError as exc:
        return None, f"authorization policy {policy.policy_id} is invalid: {exc}"


async def tenant_scope_snapshot_async(
    tenant_id: str,
    policy_id: str | None = None,
    *,
    now: float | None = None,
    parent_scope: Scope | None = None,
) -> tuple[Scope | None, str]:
    """Async version of tenant_scope_snapshot."""
    policy, reason = await registry.resolve_async(tenant_id, policy_id, now=now)
    if policy is None:
        return None, reason
    try:
        scope = policy.to_scope()
        if parent_scope is not None:
            scope = scope.inherited_from(parent_scope)
        return scope, ""
    except ValueError as exc:
        return None, f"authorization policy {policy.policy_id} is invalid: {exc}"


def validate_job_binding(job: Any) -> str:
    """Refusal reason for running ``job`` now, or '' when its policy still holds.

    Called when a worker dequeues the job (and at each adapter boundary through
    the bound snapshot) so authorization withdrawn after submission stops the
    work that is no longer authorized. Jobs without a policy binding run under
    the global single-organization mode and are not checked here.
    """
    policy_id = (getattr(job, "policy", None) or {}).get("policy_id")
    if not policy_id:
        return ""
    policy = registry.get(policy_id)
    if policy is None:
        return f"authorization policy {policy_id} no longer exists"
    if policy.tenant_id != getattr(job, "actor", ""):
        return f"authorization policy {policy_id} does not belong to this tenant"
    valid, reason = policy.is_valid()
    if not valid:
        return reason
    bound_version = (getattr(job, "policy", None) or {}).get("policy_version")
    if (
        not isinstance(bound_version, int)
        or isinstance(bound_version, bool)
        or bound_version != policy.version
    ):
        return (
            f"authorization policy {policy_id} changed after this job was queued "
            f"(bound version {bound_version}, current version {policy.version})"
        )
    return ""

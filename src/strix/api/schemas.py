"""Request and response bodies."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class Page[T](BaseModel):
    """Paginated response envelope."""

    items: list[T]
    total: int
    page: int
    page_size: int
    has_next: bool


class AssessRequest(BaseModel):
    target: str = Field(..., description="Authorized http(s) target")
    profile: str = Field(
        default="web", description="web | web-deep | api | api-deep | network | agent"
    )
    timeout: float = Field(
        default=120.0, ge=5.0, le=900.0, description="Overall job deadline in seconds"
    )
    wait: bool = Field(
        default=False,
        description="Run inline and return the finished job (200). "
        "Default queues the job and returns 202 with a job id.",
    )
    policy_id: str | None = Field(
        default=None,
        max_length=64,
        description="Pin a specific engagement policy (managed mode). Omitted: "
        "the tenant's newest valid policy is used.",
    )
    hybrid_components: HybridComponents | None = Field(
        default=None,
        description="Required for hybrid assessments: {native: true, strix: true}. "
        "Omitting it keeps the request in legacy single-engine mode.",
    )


class FindingStatusUpdate(BaseModel):
    """One audited lifecycle transition for a finding."""

    status: Literal[
        "new",
        "triaged",
        "in_progress",
        "fix_verified",
        "closed",
        "reopened",
        "deferred",
    ]
    note: str = Field(
        default="",
        max_length=1000,
        description="Optional audit note; credential-shaped values are redacted.",
    )


class AssessResponse(BaseModel):
    """Assessment creation response (queued or inline)."""

    id: str
    target: str
    profile: str
    actor: str
    policy: dict[str, Any]
    state: str
    started_at: float | None
    finished_at: float | None
    runs: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    error: str
    attempts: int
    worker: str
    idempotency_key: str | None
    coverage: dict[str, Any]
    verdict: str
    poll_url: str
    cancel_url: str
    sarif_url: str
    report_url: str
    audit_chain_hash: str
    deduplicated: bool = False


class JobSummaryResponse(BaseModel):
    """Lightweight job summary for list views."""

    id: str
    target: str
    profile: str
    actor: str
    state: str
    started_at: float | None
    finished_at: float | None
    verdict: str
    findings_count: int
    poll_url: str
    cancel_url: str
    sarif_url: str
    report_url: str
    audit_chain_hash: str


class ProbeRequest(BaseModel):
    url: str = Field(..., description="HTTP/HTTPS endpoint URL to probe")
    timeout: float = Field(default=6.0, ge=0.5, le=30.0)

    # Validation is intentionally permissive here; the probe endpoint's
    # scope gate handles malformed URLs by returning a "blocked" response
    # rather than a 422 validation error. This ensures consistent error
    # handling across all malformed input types.


class ReportRequest(BaseModel):
    target: str = Field(
        ..., description="Previously assessed target inside the authorized scope"
    )


RESERVED_TENANTS = frozenset({"system"})  # owns the monitor's jobs; never a customer


class APIKeyCreateRequest(BaseModel):
    tenant: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    tier: str = "free"
    ttl_days: int | None = Field(
        default=None,
        ge=1,
        le=3650,
        description="Key lifetime in days (1..3650). Omitted or null: the key "
        "does not expire on its own.",
    )
    project: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9_.-]+$",
        description="Project scope for this key (optional; if set, key only works for this project)",
    )

    @field_validator("tenant")
    @classmethod
    def _not_reserved(cls, value: str) -> str:
        if value.lower() in RESERVED_TENANTS:
            raise ValueError("tenant name is reserved")
        return value


class WebhookSinkRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    url: str = Field(..., min_length=1, max_length=2048)

    @field_validator("name")
    @classmethod
    def _clean_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("sink name cannot be empty")
        return value


class MonitorConfig(BaseModel):
    interval_seconds: int = Field(default=300, ge=30, le=3600)
    targets: list[str] = Field(default_factory=list, max_length=500)
    replace: bool = Field(
        default=False,
        description="Monitor exactly these targets (removing others) instead of adding to the list",
    )


def _host_entry(value: str) -> str:
    value = value.strip().lower().strip(".")
    if not value:
        raise ValueError("host entry is empty")
    return value


class PolicyUpdateRequest(BaseModel):
    """Partial policy update; each mutation creates a new policy version."""

    program: str | None = Field(default=None, min_length=1, max_length=256)
    authorized_by: str | None = Field(default=None, min_length=1, max_length=256)
    authorization_ref: str | None = Field(default=None, min_length=1, max_length=256)
    include: list[str] | None = Field(default=None, min_length=1, max_length=100)
    exclude: list[str] | None = Field(default=None, max_length=100)
    authorized_networks: list[str] | None = Field(default=None, max_length=50)
    allowed_ports: list[int] | None = Field(default=None, max_length=100)
    allow_broad_networks: bool | None = None
    ttl_seconds: int | None = Field(
        default=None,
        ge=0,
        le=366 * 86400,
        description="New lifetime from now; 0 or null clears expiry; omitted preserves it.",
    )
    effective_in_seconds: int | None = Field(
        default=None,
        ge=0,
        le=366 * 86400,
        description="Delay before effectiveness; 0 is immediate; null clears the delay.",
    )

    @field_validator("include", "exclude")
    @classmethod
    def _clean_hosts(cls, value: list[str] | None) -> list[str] | None:
        return [_host_entry(item) for item in value] if value is not None else None

    @field_validator("authorized_networks")
    @classmethod
    def _clean_networks(cls, value: list[str] | None) -> list[str] | None:
        return [item.strip() for item in value] if value is not None else None


class HybridComponents(BaseModel):
    native: bool = Field(
        default=False, description="Run native Strix scanners in this assessment."
    )
    strix: bool = Field(
        default=False, description="Run the Strix autonomous engine in this assessment."
    )


class PolicyCreateRequest(BaseModel):
    """An administrator authorizing one engagement for one tenant.

    Creating a policy is a trusted administrative act: only administrators
    reach this endpoint, and every creation is audited and sealed in the chain.
    Customers cannot authorize themselves.
    """

    tenant: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    program: str = Field(..., min_length=1, max_length=256)
    authorized_by: str = Field(..., min_length=1, max_length=256)
    authorization_ref: str = Field(..., min_length=1, max_length=256)
    include: list[str] = Field(..., min_length=1, max_length=100)
    exclude: list[str] = Field(default_factory=list, max_length=100)
    authorized_networks: list[str] = Field(default_factory=list, max_length=50)
    allowed_ports: list[int] = Field(default_factory=list, max_length=100)
    allow_broad_networks: bool = False
    ttl_seconds: int | None = Field(
        default=None,
        ge=60,
        le=366 * 86400,
        description="Policy lifetime from now (60s..366d). Omitted: no expiry.",
    )
    effective_in_seconds: int | None = Field(
        default=None,
        ge=0,
        le=366 * 86400,
        description="Delay before the policy becomes effective. Omitted: immediate.",
    )

    @field_validator("include", "exclude")
    @classmethod
    def _clean_hosts(cls, value: list[str]) -> list[str]:
        return [_host_entry(item) for item in value]

    @field_validator("authorized_networks")
    @classmethod
    def _clean_networks(cls, value: list[str]) -> list[str]:
        return [item.strip() for item in value]

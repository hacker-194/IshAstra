"""Request and response bodies."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

# Canonical SCIM models live in strix.core.scim; re-export them for the API so
# request/response types and persistence share validation and conversion methods.
from strix.core.scim import (
    SCIMEmail as SCIMEmail,
)
from strix.core.scim import (
    SCIMError as SCIMError,
)
from strix.core.scim import (
    SCIMGroup as SCIMGroup,
)
from strix.core.scim import (
    SCIMGroupRef as SCIMGroupRef,
)
from strix.core.scim import (
    SCIMListResponse as SCIMListResponse,
)
from strix.core.scim import (
    SCIMMeta as SCIMMeta,
)
from strix.core.scim import (
    SCIMName as SCIMName,
)
from strix.core.scim import (
    SCIMResourceType as SCIMResourceType,
)
from strix.core.scim import (
    SCIMResourceTypesResponse as SCIMResourceTypesResponse,
)
from strix.core.scim import (
    SCIMSchema as SCIMSchema,
)
from strix.core.scim import (
    SCIMSchemasResponse as SCIMSchemasResponse,
)
from strix.core.scim import (
    SCIMServiceProviderConfig as SCIMServiceProviderConfig,
)
from strix.core.scim import (
    SCIMUser as SCIMUser,
)


class Page[T](BaseModel):
    """Paginated response envelope."""

    items: list[T]
    total: int
    page: int
    page_size: int
    has_next: bool


class AuthConfig(BaseModel):
    """Authentication configuration for an assessment."""

    type: str = Field(..., description="Auth type: token | session | form_login | multi_step")
    # Token auth
    bearer: str | None = Field(default=None, description="Bearer token for Authorization header")
    api_key: str | None = Field(default=None, description="API key value")
    api_key_header: str | None = Field(default="X-API-Key", description="Header name for API key")
    custom_headers: dict[str, str] | None = Field(default=None, description="Additional custom headers")
    # Session auth
    cookies: dict[str, str] | None = Field(default=None, description="Session cookies as name:value pairs")
    # Form login auth
    login_url: str | None = Field(default=None, description="Login form URL")
    username: str | None = Field(default=None, description="Username for form login")
    password: str | None = Field(default=None, description="Password for form login")
    username_field: str | None = Field(default="username", description="Username field name")
    password_field: str | None = Field(default="password", description="Password field name")
    csrf_field: str | None = Field(default=None, description="CSRF token field name")
    extra_fields: dict[str, str] | None = Field(default=None, description="Extra hidden form fields")
    # Multi-step auth
    steps: list[AuthConfig] | None = Field(default=None, description="Chained auth steps")
    # Common
    principal_id: str | None = Field(default=None, description="Unique identifier for this auth config")


class AssessRequest(BaseModel):
    target: str = Field(..., description="Authorized http(s) target")
    profile: str = Field(default="web", description="web | web-deep | api | api-deep | network | agent")
    timeout: float = Field(default=120.0, ge=5.0, le=900.0, description="Overall job deadline in seconds")
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
    auth: AuthConfig | None = Field(
        default=None,
        description="Per-assessment authentication configuration. "
        "Supports token, session, form_login, and multi_step types. "
        "Credentials are encrypted at rest.",
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
    target: str = Field(..., description="Previously assessed target inside the authorized scope")


RESERVED_TENANTS = frozenset({"system"})  # owns the monitor's jobs; never a customer


class APIKeyCreateRequest(BaseModel):
    tenant: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    tier: str = "standard"
    scope: Literal["read", "write"] = Field(
        default="write",
        description="read: safe methods only; write: manage jobs, findings and keys.",
    )
    scope_type: Literal["tenant", "project"] = Field(
        default="tenant",
        description="tenant: access to all projects in tenant; project: restricted to specific project",
    )
    project_id: str | None = Field(
        default=None,
        max_length=64,
        pattern=r"^[A-Za-z0-9_.-]+$",
        description="Project ID (required when scope_type is 'project')",
    )
    allowed_projects: list[str] | None = Field(
        default=None,
        max_length=50,
        description="Additional projects this key can access (for project-scoped keys)",
    )
    resource_filters: dict[str, Any] | None = Field(
        default=None,
        description="Resource-level filters (e.g., {'asset_types': ['web', 'api'], 'tags': ['production']})",
    )
    ttl_days: int | None = Field(
        default=None,
        ge=1,
        le=3650,
        description="Key lifetime in days (1..3650). Omitted or null: the key does not expire on its own.",
    )
    include_hosts: str | None = Field(
        default=None,
        description=(
            "Comma-separated list of hosts this key is allowed to scan "
            "(subset of engagement policy include hosts)."
        ),
    )

    @field_validator("tenant")
    @classmethod
    def _not_reserved(cls, value: str) -> str:
        if value.lower() in RESERVED_TENANTS:
            raise ValueError("tenant name is reserved")
        return value

    @field_validator("project_id")
    @classmethod
    def _require_project_for_project_scope(cls, value: str | None, info) -> str | None:
        if info.data.get("scope_type") == "project" and not value:
            raise ValueError("project_id is required when scope_type is 'project'")
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
    allowed_asns: list[int] | None = Field(default=None, max_length=100)
    allowed_countries: list[str] | None = Field(default=None, max_length=250)
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

    @field_validator("allowed_countries")
    @classmethod
    def _clean_countries(cls, value: list[str] | None) -> list[str] | None:
        return [item.strip().upper() for item in value] if value is not None else None


class HybridComponents(BaseModel):
    native: bool = Field(default=False, description="Run native Strix scanners in this assessment.")
    strix: bool = Field(default=False, description="Run the Strix autonomous engine in this assessment.")


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
    allowed_asns: list[int] = Field(default_factory=list, max_length=100)
    allowed_countries: list[str] = Field(default_factory=list, max_length=250)
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

    @field_validator("allowed_countries")
    @classmethod
    def _clean_countries(cls, value: list[str]) -> list[str]:
        return [item.strip().upper() for item in value]


class ScheduleCreateRequest(BaseModel):
    """Create a recurring assessment schedule."""

    target: str = Field(..., description="Authorized http(s) target")
    cron_expression: str = Field(..., description="Standard cron expression (e.g., '0 2 * * *')")
    timezone: str = Field(default="UTC", description="IANA timezone (e.g., 'America/New_York')")
    profile: str = Field(default="web", description="web | web-deep | api | api-deep | network | agent")
    policy_id: str | None = Field(default=None, max_length=64, description="Pin a specific engagement policy")
    max_concurrent: int = Field(default=1, ge=1, le=10, description="Maximum concurrent runs")
    catch_up: bool = Field(default=True, description="Run missed executions on scheduler restart")


class ScheduleUpdateRequest(BaseModel):
    """Update an existing schedule."""

    cron_expression: str | None = Field(default=None, description="Standard cron expression")
    timezone: str | None = Field(default=None, description="IANA timezone")
    profile: str | None = Field(default=None, description="Assessment profile")
    state: str | None = Field(default=None, description="active | paused | disabled")
    policy_id: str | None = Field(default=None, max_length=64, description="Pin a specific engagement policy")
    max_concurrent: int | None = Field(default=None, ge=1, le=10)
    catch_up: bool | None = None
    enabled: bool | None = None


class ScheduleResponse(BaseModel):
    """Schedule response."""

    id: str
    target: str
    cron_expression: str
    timezone: str
    profile: str
    state: str
    policy_id: str | None
    created_at: float
    updated_at: float
    last_run: float | None
    next_run: float | None
    run_count: int
    max_concurrent: int
    catch_up: bool
    enabled: bool


class ScheduleRunResponse(BaseModel):
    """Manual schedule run response."""

    schedule_id: str
    job_id: str
    target: str
    started_at: float
    finished_at: float
    state: str
    findings_count: int
    new_high_severity: int
    error: str
    alert_emitted: bool


class SchedulerStatusResponse(BaseModel):
    """Scheduler status response."""

    running: bool
    total_schedules: int
    active_schedules: int
    paused_schedules: int


class FindingRemediationUpdate(BaseModel):
    """Ownership, deadline and time-boxed risk acceptance for one finding."""

    owner: str = Field(default="", max_length=128)
    due_at: float | None = Field(default=None, description="Unix timestamp for the remediation deadline")
    exception_until: float | None = Field(
        default=None, description="Unix timestamp until which a risk exception applies"
    )
    exception_reason: str = Field(default="", max_length=1000)
    exception_approved_by: str = Field(default="", max_length=128)


class UserCreateRequest(BaseModel):
    """A tenant member with a role and their own API key."""

    display_name: str = Field(min_length=1, max_length=128)
    role: Literal["admin", "analyst", "viewer"] = "analyst"
    ttl_days: int | None = Field(default=None, ge=1, le=3650)
    tenant: str | None = Field(default=None, max_length=128)


class FindingExceptionRequest(BaseModel):
    """Request a risk acceptance; only an administrator can approve it."""

    until: float = Field(description="Unix timestamp when the exception expires")
    reason: str = Field(min_length=1, max_length=1000)


class FindingExceptionDecision(BaseModel):
    """Approve or reject a pending risk acceptance."""

    approve: bool
    note: str = Field(default="", max_length=1000)


class FindingResolutionVerify(BaseModel):
    """A later job used as coverage-backed evidence that a finding is absent."""

    job_id: str = Field(min_length=1, max_length=128)


class AssetUpdate(BaseModel):
    """Operator-maintained asset metadata; inventory facts stay derived."""

    owner: str | None = Field(default=None, max_length=128)
    criticality: Literal["low", "medium", "high", "critical"] | None = None


class OrganizationCreateRequest(BaseModel):
    """Create a new organization."""

    name: str = Field(..., min_length=1, max_length=128)
    slug: str | None = Field(default=None, max_length=64, pattern=r"^[a-z0-9-]+$")
    tier: str = Field(default="standard", description="standard | elevated | unlimited")
    settings: dict[str, Any] | None = Field(
        default=None,
        description="Organization settings: billing_email, support_email, custom_domain, sso_config",
    )


class OrganizationUpdateRequest(BaseModel):
    """Update an organization."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    slug: str | None = Field(default=None, max_length=64, pattern=r"^[a-z0-9-]+$")
    tier: str | None = Field(default=None, description="standard | elevated | unlimited")
    settings: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Organization settings (merged with existing): billing_email, support_email, "
            "custom_domain, sso_config"
        ),
    )


class OrganizationResponse(BaseModel):
    """Organization response."""

    org_id: str
    name: str
    slug: str
    tier: str
    settings: dict[str, Any]
    billing_email: str | None = None
    support_email: str | None = None
    custom_domain: str | None = None
    sso_config: dict[str, Any] = Field(default_factory=dict)
    created_at: float
    updated_at: float


class TeamCreateRequest(BaseModel):
    """Create a new team within an organization."""

    name: str = Field(..., min_length=1, max_length=128)
    slug: str | None = Field(default=None, max_length=64, pattern=r"^[a-z0-9-]+$")
    role_mappings: dict[str, str] | None = Field(
        default=None, description="Role to permission preset mapping"
    )


class TeamUpdateRequest(BaseModel):
    """Update a team."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    slug: str | None = Field(default=None, max_length=64, pattern=r"^[a-z0-9-]+$")
    role_mappings: dict[str, str] | None = Field(default=None)


class TeamResponse(BaseModel):
    """Team response."""

    team_id: str
    org_id: str
    name: str
    slug: str
    role_mappings: dict[str, str]
    created_at: float


class MembershipCreateRequest(BaseModel):
    """Add a member to an organization."""

    user_id: str = Field(..., min_length=1, max_length=128, description="User identifier")
    role: str = Field(
        default="org_member", description="org_admin | team_lead | org_member | team_member | viewer"
    )
    team_id: str | None = Field(default=None, description="Optional team to add member to")
    status: str = Field(default="active", description="active | pending | suspended | removed")


class MembershipUpdateRequest(BaseModel):
    """Update a member's role or status."""

    role: str | None = Field(
        default=None, description="org_admin | team_lead | org_member | team_member | viewer"
    )
    status: str | None = Field(default=None, description="active | pending | suspended | removed")


class MembershipResponse(BaseModel):
    """Membership response."""

    membership_id: str
    org_id: str
    team_id: str | None
    user_id: str
    role: str
    status: str
    joined_at: float


# SCIM 2.0 Schemas


class SCIMTokenCreateRequest(BaseModel):
    """Request to create a SCIM token."""

    name: str
    ttl_days: int | None = None


class SCIMTokenResponse(BaseModel):
    """SCIM token response."""

    token: str
    token_hash: str
    name: str
    tenant_id: str
    org_id: str | None
    active: bool
    created_at: float
    expires_at: float | None


# SCIM Patch Operations


class SCIMOperation(BaseModel):
    """SCIM PATCH operation."""

    op: Literal["add", "remove", "replace"]
    path: str | None = None
    value: Any | None = None


class SCIMPatchRequest(BaseModel):
    """SCIM PATCH request."""

    schemas: list[str] = Field(default_factory=lambda: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"])
    Operations: list[SCIMOperation]


# Resolve forward references for recursive AuthConfig
AuthConfig.model_rebuild()


# =============================================================================
# Pricing Tier Models
# =============================================================================


class PricingTierEnum(str, Enum):
    """Pricing tier enumeration for API."""

    FREE = "free"
    STARTER = "starter"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class TierLimitsModel(BaseModel):
    """Resource limits for a pricing tier."""

    assessments_per_month: int = Field(..., description="Assessments per month (0 = unlimited)")
    max_concurrent_assessments: int = Field(..., description="Maximum concurrent assessments")
    max_users: int = Field(..., description="Maximum users (0 = unlimited)")
    retention_days: int = Field(..., description="Data retention in days (0 = unlimited)")
    api_rate_limit_rpm: int = Field(..., description="API rate limit (requests per minute)")
    max_projects: int = Field(..., description="Maximum projects (0 = unlimited)")
    max_webhooks: int = Field(..., description="Maximum webhook sinks (0 = unlimited)")
    max_schedules: int = Field(..., description="Maximum scheduled assessments (0 = unlimited)")
    max_finding_records: int = Field(..., description="Maximum finding records retained (0 = unlimited)")


class FeatureFlagsModel(BaseModel):
    """Feature flags for a pricing tier."""

    # Assessment features
    web_assessment: bool = True
    api_assessment: bool = True
    network_assessment: bool = True
    agent_assessment: bool = False
    full_web_profile: bool = False
    full_api_profile: bool = False

    # Authentication & SSO
    oidc_sso: bool = False
    saml_sso: bool = False
    scim_provisioning: bool = False

    # Organization features
    multi_tenant: bool = False
    org_hierarchy: bool = False
    teams_rbac: bool = False
    custom_roles: bool = False

    # Reporting & export
    sarif_export: bool = True
    html_report: bool = True
    pdf_report: bool = False
    custom_reports: bool = False
    compliance_reports: bool = False

    # Integrations
    webhook_delivery: bool = True
    github_integration: bool = False
    gitlab_integration: bool = False
    jira_integration: bool = False
    slack_integration: bool = False

    # Advanced features
    finding_deduplication: bool = True
    finding_trends: bool = False
    verified_resolution: bool = False
    risk_acceptance_workflow: bool = False
    asset_inventory: bool = True
    custom_policies: bool = False
    api_key_scoping: bool = False

    # MSSP features
    mssp_partner_portal: bool = False
    multi_customer_management: bool = False
    white_label_reports: bool = False
    dedicated_support: bool = False


class TierInfoModel(BaseModel):
    """Complete tier information for API responses."""

    tier: PricingTierEnum
    name: str
    description: str
    limits: TierLimitsModel
    features: FeatureFlagsModel
    monthly_price_usd: float
    annual_price_usd: float


class TierUpgradeRequest(BaseModel):
    """Request to upgrade/downgrade tier."""

    tier: PricingTierEnum = Field(..., description="Target tier")
    billing_cycle: Literal["monthly", "annual"] = Field(default="monthly", description="Billing cycle")


class TierUpgradeResponse(BaseModel):
    """Response for tier upgrade/downgrade."""

    previous_tier: PricingTierEnum
    new_tier: PricingTierEnum
    effective_date: float
    billing_cycle: str
    prorated: bool = False


class UsageReportModel(BaseModel):
    """Usage report for a tenant."""

    tenant_id: str
    current_tier: PricingTierEnum
    period_start: float
    period_end: float
    assessments_used: int
    assessments_limit: int
    concurrent_assessments: int
    concurrent_limit: int
    users_count: int
    users_limit: int
    api_calls_used: int
    api_calls_limit: int
    findings_count: int
    findings_limit: int
    retention_days_used: int
    retention_days_limit: int
    projects_count: int
    projects_limit: int
    webhooks_count: int
    webhooks_limit: int
    schedules_count: int
    schedules_limit: int
    overages: dict[str, int] = Field(default_factory=dict)


# =============================================================================
# MSSP Models
# =============================================================================


class MSSPTierEnum(str, Enum):
    """MSSP partner tier enumeration."""

    REGISTERED = "registered"
    AUTHORIZED = "authorized"
    PREMIER = "premier"


class MSSPPartnerStatusEnum(str, Enum):
    """MSSP partner status enumeration."""

    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"


class MSSPCustomerStatusEnum(str, Enum):
    """MSSP customer status enumeration."""

    ACTIVE = "active"
    TRIAL = "trial"
    SUSPENDED = "suspended"
    CHURNED = "churned"


class MSSPTierLimitsModel(BaseModel):
    """Resource limits for an MSSP tier."""

    max_customers: int
    max_total_assessments_per_month: int
    max_total_concurrent_assessments: int
    can_resell: bool
    white_label_reports: bool
    custom_branding: bool
    dedicated_support: bool
    portal_api_access: bool
    revenue_share_pct: float


class MSSPPartnerCreateRequest(BaseModel):
    """Request to create an MSSP partner."""

    name: str = Field(..., min_length=1, max_length=128)
    contact_email: str = Field(..., min_length=1, max_length=256)
    company_website: str | None = Field(default=None, max_length=512)
    tier: MSSPTierEnum = Field(default=MSSPTierEnum.REGISTERED)
    settings: dict[str, Any] | None = None


class MSSPPartnerUpdateRequest(BaseModel):
    """Request to update an MSSP partner."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    tier: MSSPTierEnum | None = None
    status: MSSPPartnerStatusEnum | None = None
    contact_email: str | None = Field(default=None, min_length=1, max_length=256)
    company_website: str | None = Field(default=None, max_length=512)
    settings: dict[str, Any] | None = None


class MSSPPartnerResponse(BaseModel):
    """MSSP partner response."""

    partner_id: str
    name: str
    slug: str
    tier: MSSPTierEnum
    status: MSSPPartnerStatusEnum
    contact_email: str
    company_website: str | None
    settings: dict[str, Any]
    created_at: float
    updated_at: float
    approved_at: float | None = None
    approved_by: str | None = None
    limits: MSSPTierLimitsModel | None = None


class MSSPCustomerCreateRequest(BaseModel):
    """Request to add a customer to an MSSP."""

    tenant_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(..., min_length=1, max_length=128)
    tier: PricingTierEnum = Field(default=PricingTierEnum.FREE)
    billing_contact_email: str | None = Field(default=None, max_length=256)
    technical_contact_email: str | None = Field(default=None, max_length=256)
    settings: dict[str, Any] | None = None
    trial_days: int = Field(default=30, ge=0, le=365)


class MSSPCustomerUpdateRequest(BaseModel):
    """Request to update an MSSP customer."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    status: MSSPCustomerStatusEnum | None = None
    tier: PricingTierEnum | None = None
    billing_contact_email: str | None = Field(default=None, max_length=256)
    technical_contact_email: str | None = Field(default=None, max_length=256)
    settings: dict[str, Any] | None = None
    contract_ends_at: float | None = None


class MSSPCustomerResponse(BaseModel):
    """MSSP customer response."""

    customer_id: str
    partner_id: str
    tenant_id: str
    name: str
    status: MSSPCustomerStatusEnum
    tier: PricingTierEnum
    billing_contact_email: str | None
    technical_contact_email: str | None
    settings: dict[str, Any]
    created_at: float
    updated_at: float
    trial_ends_at: float | None = None
    contract_ends_at: float | None = None
    effective_limits: dict[str, Any] | None = None


class MSSPInvitationCreateRequest(BaseModel):
    """Request to create an MSSP customer invitation."""

    email: str = Field(..., min_length=1, max_length=256)
    customer_name: str = Field(..., min_length=1, max_length=128)
    tier: PricingTierEnum = Field(default=PricingTierEnum.FREE)
    expires_in_days: int = Field(default=7, ge=1, le=90)


class MSSPInvitationResponse(BaseModel):
    """MSSP invitation response."""

    invitation_id: str
    partner_id: str
    email: str
    customer_name: str
    tier: PricingTierEnum
    status: str
    expires_at: float
    created_at: float
    accepted_at: float | None = None


class MSSPUsageRecordResponse(BaseModel):
    """MSSP usage record response."""

    record_id: str
    partner_id: str
    customer_id: str
    period_start: float
    period_end: float
    assessments_run: int
    assessments_succeeded: int
    findings_generated: int
    api_calls: int
    retention_days_used: int
    created_at: float


class MSSPUsageSummaryResponse(BaseModel):
    """MSSP usage summary for a partner."""

    partner_id: str
    period_start: float
    period_end: float
    total_assessments: int
    total_succeeded: int
    total_findings: int
    total_api_calls: int
    total_retention_days: int
    active_customers: int


class MSSPPartnerUsageReportRequest(BaseModel):
    """Request for partner usage report."""

    period_start: float = Field(..., description="Unix timestamp for period start")
    period_end: float = Field(..., description="Unix timestamp for period end")
    customer_id: str | None = Field(default=None, description="Optional specific customer")

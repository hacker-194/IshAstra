"""MSSP (Managed Security Service Provider) partner program models.

This module provides data models for MSSP partnerships, customer management,
and billing integration points for future premium features.

All features remain Apache-2.0-licensed and open-source. No payment processing —
just the data models and API structure.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ishastra.core import store
from ishastra.core.pricing import PricingTier, get_tier_features, get_tier_limits


class MSSPTier(str, Enum):
    """MSSP partner tiers."""

    REGISTERED = "registered"
    AUTHORIZED = "authorized"
    PREMIER = "premier"


class MSSPPartnerStatus(str, Enum):
    """MSSP partner status."""

    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"


class CustomerStatus(str, Enum):
    """Customer status under an MSSP."""

    ACTIVE = "active"
    TRIAL = "trial"
    SUSPENDED = "suspended"
    CHURNED = "churned"


MSSP_TIER_ORDER = {
    MSSPTier.REGISTERED: 0,
    MSSPTier.AUTHORIZED: 1,
    MSSPTier.PREMIER: 2,
}


@dataclass(frozen=True)
class MSSPTierLimits:
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


MSSP_TIER_LIMITS: dict[MSSPTier, MSSPTierLimits] = {
    MSSPTier.REGISTERED: MSSPTierLimits(
        max_customers=5,
        max_total_assessments_per_month=500,
        max_total_concurrent_assessments=5,
        can_resell=False,
        white_label_reports=False,
        custom_branding=False,
        dedicated_support=False,
        portal_api_access=True,
        revenue_share_pct=0.0,
    ),
    MSSPTier.AUTHORIZED: MSSPTierLimits(
        max_customers=50,
        max_total_assessments_per_month=5000,
        max_total_concurrent_assessments=20,
        can_resell=True,
        white_label_reports=True,
        custom_branding=True,
        dedicated_support=False,
        portal_api_access=True,
        revenue_share_pct=10.0,
    ),
    MSSPTier.PREMIER: MSSPTierLimits(
        max_customers=0,
        max_total_assessments_per_month=0,
        max_total_concurrent_assessments=0,
        can_resell=True,
        white_label_reports=True,
        custom_branding=True,
        dedicated_support=True,
        portal_api_access=True,
        revenue_share_pct=20.0,
    ),
}


@dataclass(frozen=True)
class MSSPPartner:
    """An MSSP partner organization."""

    partner_id: str
    name: str
    slug: str
    tier: MSSPTier
    status: MSSPPartnerStatus
    admin_key_hash: str
    contact_email: str
    company_website: str | None
    settings: dict[str, Any]
    created_at: float
    updated_at: float
    approved_at: float | None = None
    approved_by: str | None = None

    @classmethod
    def from_row(cls, row: Any) -> MSSPPartner:
        return cls(
            partner_id=row["partner_id"],
            name=row["name"],
            slug=row["slug"],
            tier=MSSPTier(row["tier"]),
            status=MSSPPartnerStatus(row["status"]),
            admin_key_hash=row["admin_key_hash"],
            contact_email=row["contact_email"],
            company_website=row["company_website"] if row["company_website"] else None,
            settings=json.loads(row["settings"]) if row["settings"] else {},
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            approved_at=row["approved_at"] if row["approved_at"] else None,
            approved_by=row["approved_by"] if row["approved_by"] else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "partner_id": self.partner_id,
            "name": self.name,
            "slug": self.slug,
            "tier": self.tier.value,
            "status": self.status.value,
            "contact_email": self.contact_email,
            "company_website": self.company_website,
            "settings": self.settings,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "approved_at": self.approved_at,
            "approved_by": self.approved_by,
        }


@dataclass(frozen=True)
class MSSPCustomer:
    """A customer managed by an MSSP partner."""

    customer_id: str
    partner_id: str
    tenant_id: str
    name: str
    status: CustomerStatus
    tier: PricingTier
    billing_contact_email: str | None
    technical_contact_email: str | None
    settings: dict[str, Any]
    created_at: float
    updated_at: float
    trial_ends_at: float | None = None
    contract_ends_at: float | None = None

    @classmethod
    def from_row(cls, row: Any) -> MSSPCustomer:
        return cls(
            customer_id=row["customer_id"],
            partner_id=row["partner_id"],
            tenant_id=row["tenant_id"],
            name=row["name"],
            status=CustomerStatus(row["status"]),
            tier=PricingTier(row["tier"]),
            billing_contact_email=row["billing_contact_email"] if row["billing_contact_email"] else None,
            technical_contact_email=row["technical_contact_email"]
            if row["technical_contact_email"]
            else None,
            settings=json.loads(row["settings"]) if row["settings"] else {},
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            trial_ends_at=row["trial_ends_at"] if row["trial_ends_at"] else None,
            contract_ends_at=row["contract_ends_at"] if row["contract_ends_at"] else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "customer_id": self.customer_id,
            "partner_id": self.partner_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "status": self.status.value,
            "tier": self.tier.value,
            "billing_contact_email": self.billing_contact_email,
            "technical_contact_email": self.technical_contact_email,
            "settings": self.settings,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "trial_ends_at": self.trial_ends_at,
            "contract_ends_at": self.contract_ends_at,
        }


@dataclass(frozen=True)
class MSSPUsageRecord:
    """Usage tracking for MSSP billing."""

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

    @classmethod
    def from_row(cls, row: Any) -> MSSPUsageRecord:
        return cls(
            record_id=row["record_id"],
            partner_id=row["partner_id"],
            customer_id=row["customer_id"],
            period_start=row["period_start"],
            period_end=row["period_end"],
            assessments_run=row["assessments_run"],
            assessments_succeeded=row["assessments_succeeded"],
            findings_generated=row["findings_generated"],
            api_calls=row["api_calls"],
            retention_days_used=row["retention_days_used"],
            created_at=row["created_at"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "partner_id": self.partner_id,
            "customer_id": self.customer_id,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "assessments_run": self.assessments_run,
            "assessments_succeeded": self.assessments_succeeded,
            "findings_generated": self.findings_generated,
            "api_calls": self.api_calls,
            "retention_days_used": self.retention_days_used,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class MSSPPartnerInvitation:
    """Invitation for a customer to join an MSSP."""

    invitation_id: str
    partner_id: str
    email: str
    customer_name: str
    tier: PricingTier
    status: str
    token: str
    expires_at: float
    created_at: float
    accepted_at: float | None = None

    @classmethod
    def from_row(cls, row: Any) -> MSSPPartnerInvitation:
        return cls(
            invitation_id=row["invitation_id"],
            partner_id=row["partner_id"],
            email=row["email"],
            customer_name=row["customer_name"],
            tier=PricingTier(row["tier"]),
            status=row["status"],
            token=row["token"],
            expires_at=row["expires_at"],
            created_at=row["created_at"],
            accepted_at=row["accepted_at"] if row["accepted_at"] else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "invitation_id": self.invitation_id,
            "partner_id": self.partner_id,
            "email": self.email,
            "customer_name": self.customer_name,
            "tier": self.tier.value,
            "status": self.status,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
            "accepted_at": self.accepted_at,
        }


MIGRATIONS_MSSP: list[tuple[int, str]] = [
    (
        30,
        """
    -- Migration 30: MSSP Partners table
    CREATE TABLE IF NOT EXISTS mssp_partners (
        partner_id         TEXT PRIMARY KEY,
        name               TEXT NOT NULL,
        slug               TEXT NOT NULL UNIQUE,
        tier               TEXT NOT NULL,
        status             TEXT NOT NULL DEFAULT 'pending',
        admin_key_hash     TEXT NOT NULL UNIQUE,
        contact_email      TEXT NOT NULL,
        company_website    TEXT,
        settings           TEXT NOT NULL DEFAULT '{}',
        created_at         REAL NOT NULL,
        updated_at         REAL NOT NULL,
        approved_at        REAL,
        approved_by        TEXT
    );
    CREATE INDEX IF NOT EXISTS mssp_partners_by_slug ON mssp_partners (slug);
    CREATE INDEX IF NOT EXISTS mssp_partners_by_status ON mssp_partners (status);
    """,
    ),
    (
        31,
        """
    -- Migration 31: MSSP Customers table
    CREATE TABLE IF NOT EXISTS mssp_customers (
        customer_id              TEXT PRIMARY KEY,
        partner_id               TEXT NOT NULL REFERENCES mssp_partners (partner_id) ON DELETE CASCADE,
        tenant_id                TEXT NOT NULL UNIQUE,
        name                     TEXT NOT NULL,
        status                   TEXT NOT NULL DEFAULT 'trial',
        tier                     TEXT NOT NULL DEFAULT 'free',
        billing_contact_email    TEXT,
        technical_contact_email  TEXT,
        settings                 TEXT NOT NULL DEFAULT '{}',
        created_at               REAL NOT NULL,
        updated_at               REAL NOT NULL,
        trial_ends_at            REAL,
        contract_ends_at         REAL
    );
    CREATE INDEX IF NOT EXISTS mssp_customers_by_partner ON mssp_customers (partner_id);
    CREATE INDEX IF NOT EXISTS mssp_customers_by_tenant ON mssp_customers (tenant_id);
    CREATE INDEX IF NOT EXISTS mssp_customers_by_status ON mssp_customers (status);
    """,
    ),
    (
        32,
        """
    -- Migration 32: MSSP Usage Records table
    CREATE TABLE IF NOT EXISTS mssp_usage_records (
        record_id              TEXT PRIMARY KEY,
        partner_id             TEXT NOT NULL REFERENCES mssp_partners (partner_id) ON DELETE CASCADE,
        customer_id            TEXT NOT NULL REFERENCES mssp_customers (customer_id) ON DELETE CASCADE,
        period_start           REAL NOT NULL,
        period_end             REAL NOT NULL,
        assessments_run        INTEGER NOT NULL DEFAULT 0,
        assessments_succeeded  INTEGER NOT NULL DEFAULT 0,
        findings_generated     INTEGER NOT NULL DEFAULT 0,
        api_calls              INTEGER NOT NULL DEFAULT 0,
        retention_days_used    INTEGER NOT NULL DEFAULT 0,
        created_at             REAL NOT NULL,
        UNIQUE(partner_id, customer_id, period_start)
    );
    CREATE INDEX IF NOT EXISTS mssp_usage_by_partner_period
        ON mssp_usage_records (partner_id, period_start);
    CREATE INDEX IF NOT EXISTS mssp_usage_by_customer_period
        ON mssp_usage_records (customer_id, period_start);
    """,
    ),
    (
        33,
        """
    -- Migration 33: MSSP Partner Invitations table
    CREATE TABLE IF NOT EXISTS mssp_invitations (
        invitation_id    TEXT PRIMARY KEY,
        partner_id       TEXT NOT NULL REFERENCES mssp_partners (partner_id) ON DELETE CASCADE,
        email            TEXT NOT NULL,
        customer_name    TEXT NOT NULL,
        tier             TEXT NOT NULL DEFAULT 'free',
        status           TEXT NOT NULL DEFAULT 'pending',
        token            TEXT NOT NULL UNIQUE,
        expires_at       REAL NOT NULL,
        created_at       REAL NOT NULL,
        accepted_at      REAL
    );
    CREATE INDEX IF NOT EXISTS mssp_invitations_by_partner ON mssp_invitations (partner_id);
    CREATE INDEX IF NOT EXISTS mssp_invitations_by_token ON mssp_invitations (token);
    CREATE INDEX IF NOT EXISTS mssp_invitations_by_email ON mssp_invitations (email);
    """,
    ),
]


MIGRATIONS_MSSP_PG: list[tuple[int, str]] = [
    (
        30,
        """
    CREATE TABLE IF NOT EXISTS mssp_partners (
        partner_id         TEXT PRIMARY KEY,
        name               TEXT NOT NULL,
        slug               TEXT NOT NULL UNIQUE,
        tier               TEXT NOT NULL,
        status             TEXT NOT NULL DEFAULT 'pending',
        admin_key_hash     TEXT NOT NULL UNIQUE,
        contact_email      TEXT NOT NULL,
        company_website    TEXT,
        settings           TEXT NOT NULL DEFAULT '{}',
        created_at         DOUBLE PRECISION NOT NULL,
        updated_at         DOUBLE PRECISION NOT NULL,
        approved_at        DOUBLE PRECISION,
        approved_by        TEXT
    );
    CREATE INDEX IF NOT EXISTS mssp_partners_by_slug ON mssp_partners (slug);
    CREATE INDEX IF NOT EXISTS mssp_partners_by_status ON mssp_partners (status);
    """,
    ),
    (
        31,
        """
    CREATE TABLE IF NOT EXISTS mssp_customers (
        customer_id              TEXT PRIMARY KEY,
        partner_id               TEXT NOT NULL REFERENCES mssp_partners (partner_id) ON DELETE CASCADE,
        tenant_id                TEXT NOT NULL UNIQUE,
        name                     TEXT NOT NULL,
        status                   TEXT NOT NULL DEFAULT 'trial',
        tier                     TEXT NOT NULL DEFAULT 'free',
        billing_contact_email    TEXT,
        technical_contact_email  TEXT,
        settings                 TEXT NOT NULL DEFAULT '{}',
        created_at               DOUBLE PRECISION NOT NULL,
        updated_at               DOUBLE PRECISION NOT NULL,
        trial_ends_at            DOUBLE PRECISION,
        contract_ends_at         DOUBLE PRECISION
    );
    CREATE INDEX IF NOT EXISTS mssp_customers_by_partner ON mssp_customers (partner_id);
    CREATE INDEX IF NOT EXISTS mssp_customers_by_tenant ON mssp_customers (tenant_id);
    CREATE INDEX IF NOT EXISTS mssp_customers_by_status ON mssp_customers (status);
    """,
    ),
    (
        32,
        """
    CREATE TABLE IF NOT EXISTS mssp_usage_records (
        record_id              TEXT PRIMARY KEY,
        partner_id             TEXT NOT NULL REFERENCES mssp_partners (partner_id) ON DELETE CASCADE,
        customer_id            TEXT NOT NULL REFERENCES mssp_customers (customer_id) ON DELETE CASCADE,
        period_start           DOUBLE PRECISION NOT NULL,
        period_end             DOUBLE PRECISION NOT NULL,
        assessments_run        INTEGER NOT NULL DEFAULT 0,
        assessments_succeeded  INTEGER NOT NULL DEFAULT 0,
        findings_generated     INTEGER NOT NULL DEFAULT 0,
        api_calls              INTEGER NOT NULL DEFAULT 0,
        retention_days_used    INTEGER NOT NULL DEFAULT 0,
        created_at             DOUBLE PRECISION NOT NULL,
        UNIQUE(partner_id, customer_id, period_start)
    );
    CREATE INDEX IF NOT EXISTS mssp_usage_by_partner_period
        ON mssp_usage_records (partner_id, period_start);
    CREATE INDEX IF NOT EXISTS mssp_usage_by_customer_period
        ON mssp_usage_records (customer_id, period_start);
    """,
    ),
    (
        33,
        """
    CREATE TABLE IF NOT EXISTS mssp_invitations (
        invitation_id    TEXT PRIMARY KEY,
        partner_id       TEXT NOT NULL REFERENCES mssp_partners (partner_id) ON DELETE CASCADE,
        email            TEXT NOT NULL,
        customer_name    TEXT NOT NULL,
        tier             TEXT NOT NULL DEFAULT 'free',
        status           TEXT NOT NULL DEFAULT 'pending',
        token            TEXT NOT NULL UNIQUE,
        expires_at       DOUBLE PRECISION NOT NULL,
        created_at       DOUBLE PRECISION NOT NULL,
        accepted_at      DOUBLE PRECISION
    );
    CREATE INDEX IF NOT EXISTS mssp_invitations_by_partner ON mssp_invitations (partner_id);
    CREATE INDEX IF NOT EXISTS mssp_invitations_by_token ON mssp_invitations (token);
    CREATE INDEX IF NOT EXISTS mssp_invitations_by_email ON mssp_invitations (email);
    """,
    ),
]


def _slugify(value: str) -> str:
    """Convert a string to a URL-safe slug."""
    import re

    slug = value.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[-\s]+", "-", slug)
    return slug[:64]


def _generate_id(prefix: str) -> str:
    """Generate a prefixed random ID."""
    return f"{prefix}_{secrets.token_hex(8)}"


def _hash_key(raw_key: str) -> str:
    import hashlib

    return hashlib.sha256(raw_key.encode()).hexdigest()


async def create_partner(
    *,
    name: str,
    contact_email: str,
    company_website: str | None = None,
    tier: MSSPTier = MSSPTier.REGISTERED,
    settings: dict[str, Any] | None = None,
    admin_key: str | None = None,
) -> tuple[str, str]:
    """Create a new MSSP partner.

    Returns (partner_id, raw_admin_key). The raw key is shown only once.
    """
    if tier not in MSSP_TIER_ORDER:
        raise ValueError(f"Invalid MSSP tier. Must be one of: {list(MSSP_TIER_ORDER)}")

    final_slug = _slugify(name)
    if len(final_slug) > 64:
        raise ValueError("Slug too long (max 64 characters)")

    partner_id = _generate_id("mssp")
    raw_admin_key = admin_key or f"strix_mssp_{secrets.token_urlsafe(32)}"
    admin_key_hash = _hash_key(raw_admin_key)
    now = time.time()
    settings_json = json.dumps(settings or {})

    db = await store.get_database()
    async with db.transaction() as conn:
        existing = await store._fetchone(conn, "SELECT 1 FROM mssp_partners WHERE slug = ?", final_slug)
        if existing:
            raise ValueError(f"Partner with slug '{final_slug}' already exists")

        await store._execute(
            conn,
            """INSERT INTO mssp_partners
               (partner_id, name, slug, tier, status, admin_key_hash, contact_email,
                company_website, settings, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            partner_id,
            name,
            final_slug,
            tier.value,
            MSSPPartnerStatus.PENDING.value,
            admin_key_hash,
            contact_email,
            company_website,
            settings_json,
            now,
            now,
        )

    return partner_id, raw_admin_key


async def get_partner(partner_id: str) -> MSSPPartner | None:
    """Load an MSSP partner by ID."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT * FROM mssp_partners WHERE partner_id = ?", partner_id)
    if row is None:
        return None
    return MSSPPartner.from_row(row)


async def validate_partner_admin_key(api_key: str) -> MSSPPartner | None:
    """Validate an MSSP partner admin key and return the partner."""
    if not api_key:
        return None
    digest = _hash_key(api_key)
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(
            conn,
            "SELECT * FROM mssp_partners WHERE admin_key_hash = ?",
            digest,
        )
    if row is None:
        return None
    if not secrets.compare_digest(digest, row["admin_key_hash"]):
        return None
    return MSSPPartner.from_row(row)


async def list_partners(
    *,
    status: MSSPPartnerStatus | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[MSSPPartner]:
    """List MSSP partners."""
    db = await store.get_database()
    async with db.transaction() as conn:
        if status:
            rows = await store._fetchall(
                conn,
                "SELECT * FROM mssp_partners WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                status.value,
                limit,
                offset,
            )
        else:
            rows = await store._fetchall(
                conn,
                "SELECT * FROM mssp_partners ORDER BY created_at DESC LIMIT ? OFFSET ?",
                limit,
                offset,
            )
    return [MSSPPartner.from_row(row) for row in rows]


async def update_partner(
    partner_id: str,
    *,
    name: str | None = None,
    slug: str | None = None,
    tier: MSSPTier | None = None,
    status: MSSPPartnerStatus | None = None,
    contact_email: str | None = None,
    company_website: str | None = None,
    settings: dict[str, Any] | None = None,
    approved_by: str | None = None,
) -> MSSPPartner | None:
    """Update an MSSP partner."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT * FROM mssp_partners WHERE partner_id = ?", partner_id)
        if row is None:
            return None

        updates: list[str] = []
        params: list[Any] = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if slug is not None:
            if len(slug) > 64:
                raise ValueError("Slug too long (max 64 characters)")
            existing = await store._fetchone(
                conn, "SELECT 1 FROM mssp_partners WHERE slug = ? AND partner_id != ?", slug, partner_id
            )
            if existing:
                raise ValueError(f"Partner with slug '{slug}' already exists")
            updates.append("slug = ?")
            params.append(slug)
        if tier is not None:
            if tier not in MSSP_TIER_ORDER:
                raise ValueError(f"Invalid tier. Must be one of: {list(MSSP_TIER_ORDER)}")
            updates.append("tier = ?")
            params.append(tier.value)
        if status is not None:
            if status not in MSSPPartnerStatus:
                raise ValueError(f"Invalid status. Must be one of: {list(MSSPPartnerStatus)}")
            updates.append("status = ?")
            params.append(status.value)
            if status == MSSPPartnerStatus.ACTIVE and row["approved_at"] is None:
                updates.append("approved_at = ?")
                params.append(time.time())
                if approved_by:
                    updates.append("approved_by = ?")
                    params.append(approved_by)
        if contact_email is not None:
            updates.append("contact_email = ?")
            params.append(contact_email)
        if company_website is not None:
            updates.append("company_website = ?")
            params.append(company_website)
        if settings is not None:
            updates.append("settings = ?")
            params.append(json.dumps(settings))

        if not updates:
            return MSSPPartner.from_row(row)

        updates.append("updated_at = ?")
        params.append(time.time())
        params.append(partner_id)

        await store._execute(
            conn, f"UPDATE mssp_partners SET {', '.join(updates)} WHERE partner_id = ?", *params
        )

        updated = await store._fetchone(conn, "SELECT * FROM mssp_partners WHERE partner_id = ?", partner_id)
    return MSSPPartner.from_row(updated) if updated else None


async def rotate_partner_admin_key(partner_id: str) -> str:
    """Rotate the MSSP partner admin key. Returns new raw key."""
    raw_key = f"strix_mssp_{secrets.token_urlsafe(32)}"
    key_hash = _hash_key(raw_key)
    now = time.time()

    db = await store.get_database()
    async with db.transaction() as conn:
        cursor = await store._execute(
            conn,
            "UPDATE mssp_partners SET admin_key_hash = ?, updated_at = ? WHERE partner_id = ?",
            key_hash,
            now,
            partner_id,
        )
    if cursor.rowcount == 0:
        raise ValueError(f"Partner {partner_id} not found")

    return raw_key


async def delete_partner(partner_id: str) -> bool:
    """Delete an MSSP partner (cascades to customers)."""
    db = await store.get_database()
    async with db.transaction() as conn:
        cursor = await store._execute(conn, "DELETE FROM mssp_partners WHERE partner_id = ?", partner_id)
    return cursor.rowcount > 0


async def add_customer(
    *,
    partner_id: str,
    tenant_id: str,
    name: str,
    tier: PricingTier = PricingTier.FREE,
    billing_contact_email: str | None = None,
    technical_contact_email: str | None = None,
    settings: dict[str, Any] | None = None,
    trial_days: int = 30,
) -> MSSPCustomer:
    """Add a customer to an MSSP partner."""
    partner = await get_partner(partner_id)
    if partner is None:
        raise ValueError(f"Partner {partner_id} not found")

    limits = MSSP_TIER_LIMITS[partner.tier]
    if limits.max_customers > 0:
        current_count = await count_partner_customers(partner_id)
        if current_count >= limits.max_customers:
            raise ValueError(f"Partner has reached maximum customer limit ({limits.max_customers})")

    customer_id = _generate_id("cust")
    now = time.time()
    trial_ends_at = now + (trial_days * 86400) if trial_days > 0 else None
    settings_json = json.dumps(settings or {})

    db = await store.get_database()
    async with db.transaction() as conn:
        existing = await store._fetchone(conn, "SELECT 1 FROM mssp_customers WHERE tenant_id = ?", tenant_id)
        if existing:
            raise ValueError(f"Tenant {tenant_id} is already associated with a partner")

        await store._execute(
            conn,
            """INSERT INTO mssp_customers
               (customer_id, partner_id, tenant_id, name, status, tier,
                billing_contact_email, technical_contact_email, settings,
                created_at, updated_at, trial_ends_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            customer_id,
            partner_id,
            tenant_id,
            name,
            CustomerStatus.TRIAL.value if trial_days > 0 else CustomerStatus.ACTIVE.value,
            tier.value,
            billing_contact_email,
            technical_contact_email,
            settings_json,
            now,
            now,
            trial_ends_at,
        )

    return MSSPCustomer(
        customer_id=customer_id,
        partner_id=partner_id,
        tenant_id=tenant_id,
        name=name,
        status=CustomerStatus.TRIAL if trial_days > 0 else CustomerStatus.ACTIVE,
        tier=tier,
        billing_contact_email=billing_contact_email,
        technical_contact_email=technical_contact_email,
        settings=settings or {},
        created_at=now,
        updated_at=now,
        trial_ends_at=trial_ends_at,
    )


async def get_customer(customer_id: str) -> MSSPCustomer | None:
    """Load a customer by ID."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT * FROM mssp_customers WHERE customer_id = ?", customer_id)
    if row is None:
        return None
    return MSSPCustomer.from_row(row)


async def list_partner_customers(
    partner_id: str,
    *,
    status: CustomerStatus | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[MSSPCustomer]:
    """List customers for a partner."""
    db = await store.get_database()
    async with db.transaction() as conn:
        if status:
            rows = await store._fetchall(
                conn,
                "SELECT * FROM mssp_customers WHERE partner_id = ? AND status = ? "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                partner_id,
                status.value,
                limit,
                offset,
            )
        else:
            rows = await store._fetchall(
                conn,
                "SELECT * FROM mssp_customers WHERE partner_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                partner_id,
                limit,
                offset,
            )
    return [MSSPCustomer.from_row(row) for row in rows]


async def count_partner_customers(partner_id: str) -> int:
    """Count total customers for a partner."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(
            conn, "SELECT COUNT(*) as cnt FROM mssp_customers WHERE partner_id = ?", partner_id
        )
    return row["cnt"] if row else 0


async def update_customer(
    customer_id: str,
    *,
    name: str | None = None,
    status: CustomerStatus | None = None,
    tier: PricingTier | None = None,
    billing_contact_email: str | None = None,
    technical_contact_email: str | None = None,
    settings: dict[str, Any] | None = None,
    contract_ends_at: float | None = None,
) -> MSSPCustomer | None:
    """Update a customer."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT * FROM mssp_customers WHERE customer_id = ?", customer_id)
        if row is None:
            return None

        changed_tier = tier is not None and tier != PricingTier(row["tier"])
        partner = await get_partner(row["partner_id"]) if changed_tier else None

        if (
            partner is not None
            and partner.tier == MSSPTier.REGISTERED
            and tier in (PricingTier.PRO, PricingTier.ENTERPRISE)
        ):
            raise ValueError(f"Registered partners cannot have {tier.value} customers")

        updates: list[str] = []
        params: list[Any] = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if status is not None:
            updates.append("status = ?")
            params.append(status.value)
        if tier is not None:
            updates.append("tier = ?")
            params.append(tier.value)
        if billing_contact_email is not None:
            updates.append("billing_contact_email = ?")
            params.append(billing_contact_email)
        if technical_contact_email is not None:
            updates.append("technical_contact_email = ?")
            params.append(technical_contact_email)
        if settings is not None:
            updates.append("settings = ?")
            params.append(json.dumps(settings))
        if contract_ends_at is not None:
            updates.append("contract_ends_at = ?")
            params.append(contract_ends_at)

        if not updates:
            return MSSPCustomer.from_row(row)

        updates.append("updated_at = ?")
        params.append(time.time())
        params.append(customer_id)

        await store._execute(
            conn, f"UPDATE mssp_customers SET {', '.join(updates)} WHERE customer_id = ?", *params
        )

        updated = await store._fetchone(
            conn, "SELECT * FROM mssp_customers WHERE customer_id = ?", customer_id
        )
    return MSSPCustomer.from_row(updated) if updated else None


async def record_usage(
    *,
    partner_id: str,
    customer_id: str,
    period_start: float,
    period_end: float,
    assessments_run: int = 0,
    assessments_succeeded: int = 0,
    findings_generated: int = 0,
    api_calls: int = 0,
    retention_days_used: int = 0,
) -> MSSPUsageRecord:
    """Record usage for a customer in a period (upsert)."""
    record_id = _generate_id("usage")
    now = time.time()

    db = await store.get_database()
    async with db.transaction() as conn:
        cursor = await store._execute(
            conn,
            """UPDATE mssp_usage_records
               SET assessments_run = assessments_run + ?,
                   assessments_succeeded = assessments_succeeded + ?,
                   findings_generated = findings_generated + ?,
                   api_calls = api_calls + ?,
                   retention_days_used = retention_days_used + ?,
                   created_at = ?
               WHERE partner_id = ? AND customer_id = ? AND period_start = ?""",
            assessments_run,
            assessments_succeeded,
            findings_generated,
            api_calls,
            retention_days_used,
            now,
            partner_id,
            customer_id,
            period_start,
        )

        if cursor.rowcount == 0:
            await store._execute(
                conn,
                """INSERT INTO mssp_usage_records
                   (record_id, partner_id, customer_id, period_start, period_end,
                    assessments_run, assessments_succeeded, findings_generated,
                    api_calls, retention_days_used, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                record_id,
                partner_id,
                customer_id,
                period_start,
                period_end,
                assessments_run,
                assessments_succeeded,
                findings_generated,
                api_calls,
                retention_days_used,
                now,
            )

    return MSSPUsageRecord(
        record_id=record_id,
        partner_id=partner_id,
        customer_id=customer_id,
        period_start=period_start,
        period_end=period_end,
        assessments_run=assessments_run,
        assessments_succeeded=assessments_succeeded,
        findings_generated=findings_generated,
        api_calls=api_calls,
        retention_days_used=retention_days_used,
        created_at=now,
    )


async def get_usage_records(
    partner_id: str,
    *,
    customer_id: str | None = None,
    period_start: float | None = None,
    period_end: float | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[MSSPUsageRecord]:
    """Get usage records for a partner."""
    db = await store.get_database()
    async with db.transaction() as conn:
        query = "SELECT * FROM mssp_usage_records WHERE partner_id = ?"
        params: list[Any] = [partner_id]

        if customer_id:
            query += " AND customer_id = ?"
            params.append(customer_id)
        if period_start:
            query += " AND period_start >= ?"
            params.append(period_start)
        if period_end:
            query += " AND period_end <= ?"
            params.append(period_end)

        query += " ORDER BY period_start DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = await store._fetchall(conn, query, *params)
    return [MSSPUsageRecord.from_row(row) for row in rows]


async def get_partner_usage_summary(
    partner_id: str,
    period_start: float,
    period_end: float,
) -> dict[str, Any]:
    """Get aggregated usage summary for a partner over a period."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(
            conn,
            """SELECT
                SUM(assessments_run) as total_assessments,
                SUM(assessments_succeeded) as total_succeeded,
                SUM(findings_generated) as total_findings,
                SUM(api_calls) as total_api_calls,
                SUM(retention_days_used) as total_retention_days,
                COUNT(DISTINCT customer_id) as active_customers
               FROM mssp_usage_records
               WHERE partner_id = ? AND period_start >= ? AND period_end <= ?""",
            partner_id,
            period_start,
            period_end,
        )
    if row is None:
        return {
            "total_assessments": 0,
            "total_succeeded": 0,
            "total_findings": 0,
            "total_api_calls": 0,
            "total_retention_days": 0,
            "active_customers": 0,
        }
    return {
        "total_assessments": row["total_assessments"] or 0,
        "total_succeeded": row["total_succeeded"] or 0,
        "total_findings": row["total_findings"] or 0,
        "total_api_calls": row["total_api_calls"] or 0,
        "total_retention_days": row["total_retention_days"] or 0,
        "active_customers": row["active_customers"] or 0,
    }


async def create_invitation(
    *,
    partner_id: str,
    email: str,
    customer_name: str,
    tier: PricingTier = PricingTier.FREE,
    expires_in_days: int = 7,
) -> MSSPPartnerInvitation:
    """Create an invitation for a customer to join an MSSP."""
    partner = await get_partner(partner_id)
    if partner is None:
        raise ValueError(f"Partner {partner_id} not found")

    invitation_id = _generate_id("inv")
    token = secrets.token_urlsafe(32)
    now = time.time()
    expires_at = now + (expires_in_days * 86400)

    db = await store.get_database()
    async with db.transaction() as conn:
        await store._execute(
            conn,
            """INSERT INTO mssp_invitations
               (invitation_id, partner_id, email, customer_name, tier, status,
                token, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            invitation_id,
            partner_id,
            email,
            customer_name,
            tier.value,
            "pending",
            token,
            expires_at,
            now,
        )

    return MSSPPartnerInvitation(
        invitation_id=invitation_id,
        partner_id=partner_id,
        email=email,
        customer_name=customer_name,
        tier=tier,
        status="pending",
        token=token,
        expires_at=expires_at,
        created_at=now,
    )


async def get_invitation_by_token(token: str) -> MSSPPartnerInvitation | None:
    """Get an invitation by token."""
    db = await store.get_database()
    async with db.transaction() as conn:
        row = await store._fetchone(conn, "SELECT * FROM mssp_invitations WHERE token = ?", token)
    if row is None:
        return None
    return MSSPPartnerInvitation.from_row(row)


async def accept_invitation(token: str, tenant_id: str) -> MSSPCustomer:
    """Accept an invitation and create the customer."""
    invitation = await get_invitation_by_token(token)
    if invitation is None:
        raise ValueError("Invalid or expired invitation")

    if invitation.status != "pending":
        raise ValueError(f"Invitation is {invitation.status}")

    if time.time() > invitation.expires_at:
        await update_invitation_status(invitation.invitation_id, "expired")
        raise ValueError("Invitation has expired")

    customer = await add_customer(
        partner_id=invitation.partner_id,
        tenant_id=tenant_id,
        name=invitation.customer_name,
        tier=invitation.tier,
    )

    await update_invitation_status(invitation.invitation_id, "accepted")

    return customer


async def update_invitation_status(invitation_id: str, status: str) -> bool:
    """Update invitation status."""
    valid_statuses = {"pending", "accepted", "expired", "revoked"}
    if status not in valid_statuses:
        raise ValueError(f"Invalid status. Must be one of: {valid_statuses}")

    db = await store.get_database()
    async with db.transaction() as conn:
        updates = ["status = ?"]
        params: list[str | float] = [status]
        if status == "accepted":
            updates.append("accepted_at = ?")
            params.append(time.time())
        params.append(invitation_id)
        cursor = await store._execute(
            conn, f"UPDATE mssp_invitations SET {', '.join(updates)} WHERE invitation_id = ?", *params
        )
    return cursor.rowcount > 0


async def list_partner_invitations(
    partner_id: str,
    *,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[MSSPPartnerInvitation]:
    """List invitations for a partner."""
    db = await store.get_database()
    async with db.transaction() as conn:
        if status:
            rows = await store._fetchall(
                conn,
                "SELECT * FROM mssp_invitations WHERE partner_id = ? AND status = ? "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                partner_id,
                status,
                limit,
                offset,
            )
        else:
            rows = await store._fetchall(
                conn,
                "SELECT * FROM mssp_invitations WHERE partner_id = ? "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                partner_id,
                limit,
                offset,
            )
    return [MSSPPartnerInvitation.from_row(row) for row in rows]


def get_mssp_tier_limits(tier: MSSPTier) -> MSSPTierLimits:
    """Get limits for an MSSP tier."""
    return MSSP_TIER_LIMITS.get(tier, MSSP_TIER_LIMITS[MSSPTier.REGISTERED])


def get_customer_effective_limits(customer: MSSPCustomer, partner: MSSPPartner) -> dict[str, Any]:
    """Get effective limits for a customer (minimum of customer tier and partner tier)."""
    customer_limits = get_tier_limits(customer.tier)
    customer_features = get_tier_features(customer.tier)

    return {
        "customer_tier": customer.tier.value,
        "partner_tier": partner.tier.value,
        "assessments_per_month": customer_limits.assessments_per_month,
        "max_concurrent_assessments": customer_limits.max_concurrent_assessments,
        "max_users": customer_limits.max_users,
        "retention_days": customer_limits.retention_days,
        "api_rate_limit_rpm": customer_limits.api_rate_limit_rpm,
        "max_projects": customer_limits.max_projects,
        "max_webhooks": customer_limits.max_webhooks,
        "max_schedules": customer_limits.max_schedules,
        "max_finding_records": customer_limits.max_finding_records,
        "features": dict(customer_features.__dict__),
    }

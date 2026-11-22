# Consent Policy

**Version**: 1.0  
**Status**: Draft — not yet implemented  
**Scope**: Ishastra assessment platform — governs how consent is recorded, enforced, and audited for all data processing activities during authorized security assessments.

> **Supersedes**: No prior consent policy document exists. This is the first version.
> **Linked from**: Will be referenced from `docs/security-review.md` (review checklist), `docs/deployment.md` (configuration), `README.md` (compliance section), and `src/ishastra/core/scope_schema.json` (RoE data_handling).
> **User instruction**: "proceed with Workstream E: consent-policy.md draft"

---

## 1. Purpose

This policy defines the machine-readable consent framework for Ishastra. It ensures that:

- Every data processing action during an assessment has a **verifiable consent record** tied to a specific scope document
- Consent is **purpose-bound**: data collected for one assessment purpose cannot be repurposed without new consent
- **Retention**, **revocation**, **transparency**, and **portability** are enforceable at the API and storage layers
- **Human review triggers** are explicit and auditable
- All consent decisions produce an **immutable audit trail** with schema versioning

This policy extends the existing **Rules of Engagement (RoE)** `data_handling` object and the **Scope Document v2** schema.

---

## 2. Core Principles

| Principle | Enforcement |
|-----------|-------------|
| **Explicit consent** | No data processing without a `ConsentRecord` linked to a valid Scope Document |
| **Purpose binding** | Each `ConsentRecord` declares `purpose` (enumerated); re-use requires new consent |
| **Data minimization** | Adapters must request only the fields declared in `purpose` |
| **Retention enforcement** | Automated deletion at `retention_days` expiry; no silent extensions |
| **Revocation propagation** | Revocation cascades to all derived artifacts (findings, evidence, reports) within 24h |
| **Transparency** | Data subjects can query what was collected, why, and by whom via API |
| **Portability** | Machine-readable export (JSON Lines + schema) on demand |
| **Human review** | Defined triggers escalate to authorized reviewers before irreversible actions |

---

## 3. Consent Record Schema

### 3.1 JSON Schema (v1)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://ishastra.dev/schemas/consent-record/v1",
  "title": "Ishastra Consent Record",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "consent_id",
    "scope_id",
    "subject",
    "purpose",
    "granted_at",
    "granted_by",
    "retention_days",
    "status"
  ],
  "properties": {
    "version": {
      "const": 1,
      "description": "Schema version. Increment on breaking changes."
    },
    "consent_id": {
      "type": "string",
      "format": "uuid",
      "description": "Globally unique consent record identifier"
    },
    "scope_id": {
      "type": "string",
      "format": "uuid",
      "description": "Reference to the Scope Document authorizing this assessment"
    },
    "subject": {
      "type": "object",
      "additionalProperties": false,
      "required": ["type", "identifier"],
      "properties": {
        "type": {
          "type": "string",
          "enum": ["organization", "system", "data_subject", "tenant"],
          "description": "Category of the consent subject"
        },
        "identifier": {
          "type": "string",
          "maxLength": 256,
          "description": "Stable identifier (org UUID, system FQDN, data subject hash, tenant ID)"
        },
        "metadata": {
          "type": "object",
          "maxProperties": 20,
          "additionalProperties": { "type": "string", "maxLength": 1024 },
          "description": "Optional context (e.g., department, data classification)"
        }
      }
    },
    "purpose": {
      "type": "array",
      "minItems": 1,
      "maxItems": 10,
      "uniqueItems": true,
      "items": {
        "type": "string",
        "enum": [
          "vulnerability_assessment",
          "penetration_testing",
          "compliance_evidence",
          "threat_modeling",
          "architecture_review",
          "incident_response_support",
          "red_team_exercise",
          "supply_chain_assessment"
        ]
      },
      "description": "Explicit purposes this consent covers. Repurposing requires new consent."
    },
    "data_categories": {
      "type": "array",
      "minItems": 1,
      "maxItems": 20,
      "uniqueItems": true,
      "items": {
        "type": "string",
        "enum": [
          "network_topology",
          "service_enumeration",
          "vulnerability_findings",
          "credential_material",
          "pii",
          "authentication_logs",
          "configuration_data",
          "source_code",
          "business_logic",
          "user_behavior",
          "encrypted_traffic_metadata"
        ]
      },
      "description": "Categories of data this consent authorizes collecting/processing"
    },
    "granted_at": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp when consent was granted (with timezone)"
    },
    "granted_by": {
      "type": "object",
      "additionalProperties": false,
      "required": ["type", "identifier"],
      "properties": {
        "type": {
          "type": "string",
          "enum": ["authorized_representative", "automated_policy", "data_subject", "legal_hold"],
          "description": "Who/what granted this consent"
        },
        "identifier": {
          "type": "string",
          "maxLength": 256,
          "description": "Identity of the grantor (user ID, policy ID, system reference)"
        },
        "authorization_ref": {
          "type": "string",
          "maxLength": 256,
          "description": "External reference (contract, ticket, legal order)"
        }
      }
    },
    "retention_days": {
      "type": "integer",
      "minimum": 1,
      "maximum": 3650,
      "description": "Days after granted_at when data must be deleted. Mirrors RoE.data_handling.evidence_retention_days"
    },
    "expires_at": {
      "type": "string",
      "format": "date-time",
      "description": "Calculated expiry (granted_at + retention_days). Stored for query efficiency."
    },
    "status": {
      "type": "string",
      "enum": ["active", "revoked", "expired", "superseded"],
      "default": "active",
      "description": "Current lifecycle state"
    },
    "revoked_at": {
      "type": ["string", "null"],
      "format": "date-time",
      "description": "Timestamp of revocation, null if not revoked"
    },
    "revoked_by": {
      "type": ["object", "null"],
      "additionalProperties": false,
      "properties": {
        "type": { "type": "string", "enum": ["authorized_representative", "data_subject", "automated_policy", "legal_hold"] },
        "identifier": { "type": "string", "maxLength": 256 },
        "reason": { "type": "string", "maxLength": 1024 }
      },
      "description": "Revocation actor and reason"
    },
    "superseded_by": {
      "type": ["string", "null"],
      "format": "uuid",
      "description": "Consent ID that replaced this one (for amendments)"
    },
    "conditions": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "testing_hours": { "type": "string", "maxLength": 256 },
        "rate_limit_rps": { "type": "integer", "minimum": 0, "maximum": 1000 },
        "prohibited_techniques": { "type": "array", "items": { "type": "string" }, "maxItems": 100 },
        "required_notifications": { "type": "array", "items": { "type": "string" }, "maxItems": 20 },
        "geographic_restrictions": { "type": "array", "items": { "type": "string", "pattern": "^[A-Z]{2}$" }, "maxItems": 50 },
        "approved_adapters": { "type": "array", "items": { "type": "string" }, "maxItems": 20 }
      },
      "description": "Operational constraints derived from RoE and Scope Document"
    },
    "signature": {
      "type": "object",
      "additionalProperties": false,
      "required": ["alg", "kid", "sig"],
      "properties": {
        "alg": { "const": "Ed25519" },
        "kid": { "type": "string", "maxLength": 128 },
        "sig": { "type": "string", "minLength": 1, "maxLength": 256 }
      },
      "description": "Ed25519 signature over canonical JSON of all other fields"
    }
  }
}
```

### 3.2 Canonical Serialization

For signing and hashing, consent records use **canonical JSON** (RFC 8785):

```python
import json

def canonical_json(obj: dict) -> bytes:
    return json.dumps(
        obj,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False
    ).encode("utf-8")
```

The `signature.sig` is `Ed25519(private_key, canonical_json(record_without_signature))`.

---

## 4. Lifecycle

```
┌─────────────┐     GRANT      ┌─────────────┐     REVOKE      ┌─────────────┐
│   DRAFT     │ ─────────────► │   ACTIVE    │ ──────────────► │  REVOKED    │
└─────────────┘                └─────────────┘                 └─────────────┘
                                     │                               ▲
                                     │ EXPIRE                        │
                                     ▼                               │
                              ┌─────────────┐                        │
                              │   EXPIRED   │ ──────────────────────┘
                              └─────────────┘
                                     │
                                     │ SUPERSEDE (amendment)
                                     ▼
                              ┌─────────────┐
                              │ SUPERSEDED  │
                              └─────────────┘
```

### 4.1 State Transitions

| From | To | Trigger | Actor |
|------|-----|---------|-------|
| `DRAFT` | `ACTIVE` | Signed by authorized grantor | `granted_by` |
| `ACTIVE` | `REVOKED` | Explicit revocation API call | `revoked_by` |
| `ACTIVE` | `EXPIRED` | `now > expires_at` (cron) | Automated |
| `ACTIVE` | `SUPERSEDED` | New consent with `supersedes` field | `granted_by` |
| `REVOKED` | — | Terminal | — |
| `EXPIRED` | — | Terminal | — |
| `SUPERSEDED` | — | Terminal | — |

**No backward transitions.** Once revoked/expired/superseded, a consent record is immutable.

---

## 5. Purpose Binding Enforcement

### 5.1 Adapter-Level Enforcement

Every adapter **must** declare its purpose(s) at registration:

```python
class BaseAdapter:
    # Required: list of purposes this adapter serves
    purposes: tuple[str, ...] = ("vulnerability_assessment",)
    
    # Required: data categories this adapter produces
    data_categories: tuple[str, ...] = ("vulnerability_findings",)
    
    async def run(self) -> AsyncIterator[Finding]:
        # 1. Verify active consent exists for ALL declared purposes
        consent = await self._verify_consent(self.config.target)
        
        # 2. Verify data_categories are subset of consent.data_categories
        for cat in self.data_categories:
            if cat not in consent.data_categories:
                raise ConsentViolation(f"Adapter produces {cat} not covered by consent")
        
        # 3. Proceed with Scope Gate authorization
        dest = await self._authorize_connection(self.config.target)
        ...
```

### 5.2 Finding Tagging

Every `Finding` carries the `consent_id` and `purpose` that authorized it:

```json
{
  "id": "NUCLEI-CVE-2024-1234",
  "consent_id": "550e8400-e29b-41d4-a716-446655440000",
  "purpose": "vulnerability_assessment",
  "data_category": "vulnerability_findings",
  ...
}
```

### 5.3 Query-Time Enforcement

API endpoints that return findings/evidence **must** filter by the caller's consent scope:

```python
async def list_findings(consent_id: str, ...) -> list[Finding]:
    # Only return findings whose consent_id matches or is covered by caller's consent
    consent = await get_consent_record(consent_id)
    return await store.query_findings(
        consent_ids=[consent_id] + get_superseded_chain(consent_id)
    )
```

---

## 6. Retention Enforcement

### 6.1 Automated Deletion

A daily cron job (`consent_retention_enforcer`) executes:

```sql
-- Find expired active consents
UPDATE consent_records
SET status = 'expired'
WHERE status = 'active' AND expires_at < NOW();

-- Hard-delete data associated with expired/revoked consents
-- (cascades via foreign keys with ON DELETE CASCADE)
DELETE FROM findings WHERE consent_id IN (SELECT consent_id FROM consent_records WHERE status IN ('expired', 'revoked'));
DELETE FROM evidence_packs WHERE consent_id IN (...);
DELETE FROM audit_logs WHERE consent_id IN (...);
DELETE FROM consent_records WHERE status IN ('expired', 'revoked') AND deleted_at < NOW() - INTERVAL '30 days';
```

### 6.2 Grace Period

- **30-day soft delete window**: Expired/revoked records retained for audit recovery
- **Legal hold**: `granted_by.type = "legal_hold"` disables auto-expiry; manual review required

### 6.3 Retention Configuration

Mirrors `RoE.data_handling.evidence_retention_days` (1–3650 days). Default: **90 days** for assessments, **365 days** for compliance evidence.

---

## 7. Revocation Propagation

### 7.1 Immediate Effects (within 1 minute)

When `POST /api/v1/consent/{consent_id}/revoke` succeeds:

1. Consent record `status` → `revoked`, `revoked_at` = now
2. All **running assessments** bound to this consent receive `SIGTERM`
3. Queue entries for this consent are **cancelled** (not requeued)
4. New assessment submissions with this `consent_id` are **rejected** (403)

### 7.2 Cascading Deletion (within 24 hours)

The retention enforcer deletes:

| Resource | Action |
|----------|--------|
| `Finding` rows | Hard delete (cascade) |
| `EvidencePack` objects | Hard delete from object storage |
| `AssessmentReport` | Hard delete |
| `AuditLog` entries | **Retained** (immutable audit trail) but marked `consent_revoked=true` |
| `ConsentRecord` | Hard delete after 30-day grace period |

### 7.3 Notification

`required_notifications` from RoE determines who is informed:

```python
async def notify_revocation(consent: ConsentRecord, revoked_by: dict):
    for channel in consent.conditions.required_notifications:
        if channel == "email":
            await send_email(consent.granted_by.identifier, ...)
        elif channel == "webhook":
            await post_webhook(consent.metadata.get("webhook_url"), ...)
        elif channel == "siem":
            await forward_to_siem(ConsentRevokedEvent(consent, revoked_by))
```

---

## 8. Transparency API

### 8.1 Data Subject Access Request (DSAR)

```http
GET /api/v1/consent/transparency?subject_type=organization&subject_id=org-123
Authorization: Bearer <key_with_consent_read_scope>
```

**Response**:

```json
{
  "subject": { "type": "organization", "identifier": "org-123" },
  "active_consents": [
    {
      "consent_id": "550e8400-e29b-41d4-a716-446655440000",
      "scope_id": "scope-abc",
      "purpose": ["vulnerability_assessment"],
      "data_categories": ["network_topology", "vulnerability_findings"],
      "granted_at": "2026-01-15T09:00:00Z",
      "expires_at": "2026-04-15T09:00:00Z",
      "status": "active",
      "assessments_run": 3,
      "findings_count": 47
    }
  ],
  "revoked_consents": [
    {
      "consent_id": "550e8400-e29b-41d4-a716-446655440001",
      "revoked_at": "2026-02-01T12:00:00Z",
      "revoked_by": { "type": "authorized_representative", "identifier": "ciso@org.com" },
      "reason": "Engagement completed early"
    }
  ],
  "data_processed_summary": {
    "total_findings": 47,
    "by_category": {
      "vulnerability_findings": 32,
      "network_topology": 15
    },
    "adapters_used": ["nmap", "nuclei", "nikto"]
  }
}
```

### 8.2 Consent Record Lookup

```http
GET /api/v1/consent/{consent_id}
Authorization: Bearer <key_with_consent_read_scope>
```

Returns the full consent record (minus private key material).

---

## 9. Portability (Data Export)

### 9.1 Export Request

```http
POST /api/v1/consent/{consent_id}/export
Authorization: Bearer <key_with_consent_export_scope>
Content-Type: application/json

{
  "format": "jsonl",           // "jsonl" | "csv" | "sarif"
  "include": ["findings", "evidence", "audit_logs", "reports"],
  "encryption": {
    "algorithm": "age",
    "recipient": "age1..."
  }
}
```

### 9.2 Export Format (JSON Lines)

Each line is a self-contained JSON object with schema version:

```jsonl
{"schema": "https://ishastra.dev/schemas/export/finding/v1", "type": "finding", "consent_id": "...", "data": {...}}
{"schema": "https://ishastra.dev/schemas/export/evidence/v1", "type": "evidence", "consent_id": "...", "data": {...}}
{"schema": "https://ishastra.dev/schemas/export/audit_log/v1", "type": "audit_log", "consent_id": "...", "data": {...}}
```

### 9.3 Export Delivery

- **Async**: Returns `export_id`; status at `GET /api/v1/exports/{export_id}`
- **Signed URL**: Pre-signed object storage URL (expires 24h)
- **Encryption**: Optional age/PGP encryption for recipient

---

## 10. Human Review Triggers

The following events **require human approval** before proceeding:

| Trigger | Required Reviewer | Timeout | Auto-Decision on Timeout |
|---------|-------------------|---------|--------------------------|
| New consent for `credential_material` or `pii` data category | Authorized representative (CISO/legal) | 72h | **Deny** |
| Consent with `retention_days > 365` | Authorized representative + DPO | 72h | **Deny** |
| Revocation of consent with active assessments | Assessment lead + authorized representative | 24h | **Allow revocation, cancel assessments** |
| Export request for `credential_material` | Authorized representative | 24h | **Deny** |
| Superseding consent that expands `purpose` or `data_categories` | Authorized representative | 72h | **Deny** |
| `legal_hold` grant type | Legal counsel | None (manual) | **Block until reviewed** |

### 10.1 Review Workflow

```python
class ConsentReview:
    consent_id: str
    trigger: str
    requested_by: str
    requested_at: datetime
    status: Literal["pending", "approved", "denied", "expired"]
    reviewer: str | None
    decided_at: datetime | None
    decision_reason: str
```

API:
- `POST /api/v1/consent/reviews` — create review request
- `GET /api/v1/consent/reviews?status=pending` — list pending
- `POST /api/v1/consent/reviews/{review_id}/decide` — approve/deny

---

## 11. Audit Log Format

Every consent-relevant action produces an **immutable audit log entry**.

### 11.1 Schema (v1)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://ishastra.dev/schemas/consent-audit/v1",
  "title": "Consent Audit Log Entry",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version", "event_id", "timestamp", "event_type",
    "consent_id", "actor", "decision"
  ],
  "properties": {
    "version": { "const": 1 },
    "event_id": { "type": "string", "format": "uuid" },
    "timestamp": { "type": "string", "format": "date-time" },
    "event_type": {
      "type": "string",
      "enum": [
        "consent_granted",
        "consent_revoked",
        "consent_expired",
        "consent_superseded",
        "consent_amended",
        "data_accessed",
        "data_exported",
        "data_deleted",
        "review_requested",
        "review_decided",
        "retention_enforced",
        "violation_detected"
      ]
    },
    "consent_id": { "type": "string", "format": "uuid" },
    "scope_id": { "type": "string", "format": "uuid" },
    "actor": {
      "type": "object",
      "additionalProperties": false,
      "required": ["type", "identifier"],
      "properties": {
        "type": { "type": "string", "enum": ["user", "system", "automated_policy", "external"] },
        "identifier": { "type": "string", "maxLength": 256 },
        "ip_address": { "type": "string", "format": "ipv4" },
        "user_agent": { "type": "string", "maxLength": 512 }
      }
    },
    "decision": {
      "type": "string",
      "enum": ["allow", "deny", "revoke", "expire", "supersede", "approve", "reject"]
    },
    "reason": { "type": "string", "maxLength": 2048 },
    "before_state": { "type": "object" },
    "after_state": { "type": "object" },
    "correlation_id": { "type": "string", "format": "uuid" },
    "signature": {
      "type": "object",
      "additionalProperties": false,
      "required": ["alg", "kid", "sig"],
      "properties": {
        "alg": { "const": "Ed25519" },
        "kid": { "type": "string", "maxLength": 128 },
        "sig": { "type": "string", "minLength": 1, "maxLength": 256 }
      }
    }
  }
}
```

### 11.2 Integrity

- Each entry signed with **Ed25519** (same key hierarchy as Scope Document signatures)
- Entries appended to **append-only log** (WAL in PostgreSQL / immutable object storage)
- **Merkle tree** root published hourly to transparency log (optional, for high-assurance deployments)
- Log entries **never modified or deleted** — retention follows `retention_days` of associated consent

---

## 12. Schema Versioning

| Version | Date | Changes | Migration |
|---------|------|---------|-----------|
| 1 | 2026-01 | Initial release | — |
| 2 | TBD | Add `legal_basis` field (GDPR Art. 6), `cross_border_transfer` flag | Upcast v1 → v2 with defaults |

### 12.1 Versioning Rules

- **Schema version** in `version` field (integer, monotonic)
- **Breaking changes** = new major version (new `$id` URI)
- **Non-breaking** = same version, optional fields only
- **Migration**: Upcast on read; write always uses latest version
- **Compatibility**: Readers accept `version <= CURRENT_VERSION`

### 12.2 Version Negotiation

```http
GET /api/v1/consent/{consent_id}
Accept: application/json; version=1
```

Response includes `version` field; client handles upcast.

---

## 13. Integration Points

| Component | Integration |
|-----------|-------------|
| **Scope Document v2** | `rules_of_engagement.data_handling` → `ConsentRecord.conditions` + `retention_days` |
| **Assessment Queue** | Job payload includes `consent_id`; workers validate before execution |
| **Adapters** | Declare `purposes` + `data_categories`; gate checks consent before running |
| **Findings Store** | Every finding tagged with `consent_id`, `purpose`, `data_category` |
| **Evidence Packs** | Include consent metadata; retention tied to consent expiry |
| **Audit Log** | All consent events logged with Ed25519 signatures |
| **SIEM/Webhooks** | `required_notifications` drives revocation/violation alerts |
| **Break-glass** | Emergency access creates `ConsentRecord` with `granted_by.type="legal_hold"` |

---

## 14. Implementation Checklist

### 14.1 Database Schema (PostgreSQL)

- [ ] `consent_records` table (JSONB + generated columns for query)
- [ ] `consent_reviews` table
- [ ] `consent_exports` table
- [ ] Foreign keys from `findings`, `evidence_packs`, `assessments` → `consent_records`
- [ ] Indexes on `subject_*`, `scope_id`, `status`, `expires_at`

### 14.2 API Endpoints

- [ ] `POST /api/v1/consent` — create (draft)
- [ ] `POST /api/v1/consent/{id}/sign` — sign & activate
- [ ] `POST /api/v1/consent/{id}/revoke` — revoke
- [ ] `POST /api/v1/consent/{id}/supersede` — create replacement
- [ ] `GET /api/v1/consent/{id}` — fetch
- [ ] `GET /api/v1/consent/transparency` — DSAR
- [ ] `POST /api/v1/consent/{id}/export` — portability
- [ ] `POST /api/v1/consent/reviews` — human review
- [ ] `GET /api/v1/consent/audit` — audit log query

### 14.3 Background Jobs

- [ ] `consent_retention_enforcer` (daily cron)
- [ ] `consent_revocation_propagator` (event-driven, <1 min)
- [ ] `consent_expiry_notifier` (7d, 1d before expiry)

### 14.4 Adapter Updates

- [ ] Add `purposes` + `data_categories` to all built-in adapters
- [ ] Add consent verification to `BaseAdapter.run()`
- [ ] Tag findings with `consent_id`, `purpose`, `data_category`

### 14.5 Testing

- [ ] Unit tests: schema validation, state transitions, signature verification
- [ ] Integration tests: grant→assess→revoke→delete flow
- [ ] Adversarial tests: purpose bypass, revocation race, export without consent
- [ ] Load test: 10k concurrent consent records, 100k findings

---

## 15. Open Questions

| Question | Status |
|----------|--------|
| Should `ConsentRecord` support **delegated consent** (sub-contractors)? | TBD |
| **Cross-tenant consent** for MSSP scenarios? | TBD |
| **Automated consent** from policy-as-code (OPA/Rego)? | TBD |
| **Consent chaining** for multi-phase assessments? | TBD |
| **Key rotation** for audit log signatures? | TBD |

---

## 16. References

- [Scope Document Schema v2](https://github.com/hacker-194/IshAstra/blob/master/src/ishastra/core/scope_schema.json) — `rules_of_engagement.data_handling`
- [Scope Gate Concepts](scope-gate/concepts.md) — Layer 1/2/3 authorization
- [Ishastra Proof](architecture/proof-chain.md) — Ed25519 signing, audit chain
- [GDPR Article 6](https://gdpr.eu/article-6-lawfulness/) — Lawful basis for processing
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) — CA-2, CA-6, CA-7, AU-2, AU-3, AU-6, AU-12, SC-28
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) — A.5.10, A.5.12, A.5.13, A.8.10, A.8.11

---

*End of Consent Policy v1.0 Draft*
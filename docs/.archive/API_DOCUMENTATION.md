# Ishastra API Documentation

**Version:** 3.5.0  
**Base URL:** `http://localhost:8000/api` (default)  
**Authentication:** API Key (Bearer Token)  
**Content-Type:** `application/json`

---

## Table of Contents

1. [Authentication](#authentication)
2. [OpenAPI Schema & Swagger UI](#openapi-schema--swagger-ui)
3. [System Endpoints](#system-endpoints)
4. [Assessment Endpoints](#assessment-endpoints)
5. [Cross-Job Finding Records](#cross-job-finding-records)
6. [Monitoring Endpoints](#monitoring-endpoints)
7. [Policy Management Endpoints](#policy-management-endpoints)
8. [Tenant & API Key Management](#tenant--api-key-management)
9. [Scheduler Endpoints](#scheduler-endpoints)
10. [Probe Endpoint](#probe-endpoint)
11. [Proof Verification](#proof-verification)
12. [Rate Limiting](#rate-limiting)
13. [Error Responses](#error-responses)
14. [Example Requests](#example-requests)

---

## Authentication

All authenticated endpoints require an API key passed in the `Authorization` header:

```http
Authorization: Bearer <your-api-key>
```

### Getting an API Key

1. **Administrator creates a key for a tenant:**
   ```http
   POST /api/keys/create
   Authorization: Bearer <admin-api-key>
   Content-Type: application/json

   {
     "tenant": "acme-corp",
     "tier": "unlimited",
     "ttl_days": 365
   }
   ```

2. **Response includes the raw key (shown only once):**
   ```json
   {
     "created_by": "admin",
     "tenant": "acme-corp",
     "tier": "unlimited",
     "api_key": "sk_live_abc123...",
     "expires_at": "2025-12-31T23:59:59Z",
     "warning": "Store this key securely — it is shown only once."
   }
   ```

### Key Tiers

| Tier | General requests/min | Assessment submissions/min |
|------|----------------------|----------------------------|
| `standard` | 5 | 5 |
| `elevated` | 60 | 20 |
| `unlimited` | 300 | 60 |

The tier controls rate limits only. All profiles, scheduling, webhooks,
policies and every other feature are identical and MIT-licensed; they are not
gated by tier. These names are not prices or paid plans.

---

## OpenAPI Schema & Swagger UI

The API provides interactive documentation via Swagger UI and ReDoc:

- **Swagger UI:** `GET /docs` - Interactive API explorer with try-it-out functionality
- **ReDoc:** `GET /redoc` - Clean, responsive API reference
- **OpenAPI JSON:** `GET /openapi.json` - Machine-readable schema

These endpoints are publicly accessible (no authentication required).

### Enabling in Production

The docs are enabled by default. To disable in production, set environment variable:
```bash
ISHASTRA_DISABLE_DOCS=1
```

---

## System Endpoints

### Health Check
```http
GET /api/health
```
**Authentication:** None (public)

**Response:**
```json
{
  "status": "healthy",
  "service": "ishastra",
  "version": "3.5.0",
  "uptime_seconds": 12345.6
}
```

---

### Readiness Check
```http
GET /api/ready
```
**Authentication:** None (public)

**Response:**
```json
{
  "ready": true,
  "database": true,
  "audit_chain": true,
  "monitoring": true,
  "scope_configured": true,
  "scope_mode": "managed"
}
```

---

### Platform Overview
```http
GET /api/overview
Authorization: Bearer <api-key>
```

**Response:**
```json
{
  "tenant_id": "acme-corp",
  "tier": "unlimited",
  "total_jobs": 150,
  "total_findings": 1234,
  "targets": ["https://example.com", "https://api.example.com"],
  "total_targets": 2,
  "audit_events": 45
}
```

---

### Adapter Inventory
```http
GET /api/adapters
Authorization: Bearer <api-key>
```

**Response:**
```json
{
  "profiles": {
    "web": ["http-headers", "tls", "crawl", "forms", "cookies", "js-render"],
    "web-deep": ["http-headers", "tls", "crawl", "forms", "cookies", "js-render", "sqli", "xss", "ssrf"],
    "api": ["openapi", "graphql", "rest"],
    "api-deep": ["openapi", "graphql", "rest", "auth-bypass", "rate-limit", "idor"],
    "network": ["port-scan", "service-detect", "ssl-scan"],
    "agent": ["llm-recon", "llm-exploit"]
  },
  "adapters": [
    {
      "name": "http-headers",
      "description": "Security header analysis",
      "categories": ["info"],
      "requires": [],
      "available": true
    }
  ]
}
```

---

### Audit Trail
```http
GET /api/audit?limit=100
Authorization: Bearer <api-key>
```

**Query Parameters:**
- `limit` (optional): Number of entries to return (1-500, default: 100)

**Response:**
```json
{
  "tenant_id": "acme-corp",
  "total_records": 245,
  "returned": 100,
  "audit_logs": [
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "event": "assessment_queued",
      "job": "job_abc123",
      "target": "https://example.com",
      "profile": "web"
    }
  ]
}
```

---

### Audit Chain Verification
```http
GET /api/audit/verify
Authorization: Bearer <api-key>
```

**Response (Tenant):**
```json
{
  "valid": true,
  "scope": "tenant",
  "detail": "integrity verified"
}
```

**Response (Admin):**
```json
{
  "valid": true,
  "scope": "platform",
  "detail": "integrity verified",
  "entries": 15420
}
```

---

### Current Scope / Authorization
```http
GET /api/scope
Authorization: Bearer <api-key>
```

**Response (Managed Mode - Tenant Policy):**
```json
{
  "configured": true,
  "mode": "managed",
  "tenant_id": "acme-corp",
  "policy": {
    "policy_id": "pol_abc123",
    "tenant_id": "acme-corp",
    "program": "Acme Corp Bug Bounty",
    "authorized_by": "Security Team",
    "authorization_ref": "BB-2024-001",
    "version": 1,
    "status": "active",
    "include": ["example.com", "api.example.com"],
    "exclude": ["staging.example.com"],
    "authorized_networks": ["10.0.0.0/8"],
    "allowed_ports": [80, 443, 8080, 8443],
    "allow_broad_networks": false,
    "effective_at": 1705312800,
    "expires_at": 1736848800,
    "created_by": "admin",
    "created_at": 1705312800
  }
}
```

**Response (Global Mode):**
```json
{
  "configured": true,
  "mode": "global",
  "source": "/etc/ishastra/scope.json",
  "program": "Internal Security Program",
  "authorized_by": "CISO",
  "authorization_ref": "SEC-2024-001",
  "include": ["*.example.com"],
  "exclude": [],
  "authorized_networks": ["10.0.0.0/8"],
  "allowed_ports": [80, 443],
  "allow_broad_networks": false,
  "auth_principals": ["user1", "user2"]
}
```

---

## Assessment Endpoints

### Create Assessment
```http
POST /api/assess
Authorization: Bearer <api-key>
Content-Type: application/json
Idempotency-Key: <optional-unique-key>
```

**Request Body:**
```json
{
  "target": "https://example.com",
  "profile": "web",
  "timeout": 120.0,
  "wait": false,
  "policy_id": "pol_abc123",
  "hybrid_components": {
    "native": true,
    "ishastra": true
  },
  "auth": {
    "type": "token",
    "bearer": "eyJhbGciOiJIUzI1NiIs...",
    "principal_id": "api-user-1"
  }
}
```

**Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | Yes | Authorized HTTP/HTTPS target URL |
| `profile` | string | No | `web`, `web-deep`, `api`, `api-deep`, `network`, `agent` (default: `web`) |
| `timeout` | number | No | Job deadline in seconds (5-900, default: 120) |
| `wait` | boolean | No | Run inline and return finished job (default: false, returns 202) |
| `policy_id` | string | No | Pin specific engagement policy (managed mode) |
| `hybrid_components` | object | No | `{native: true, ishastra: true}` for hybrid mode |
| `auth` | object | No | Per-assessment authentication config |

**Authentication Config Types:**

1. **Token Auth:**
   ```json
   {
     "type": "token",
     "bearer": "eyJhbGciOiJIUzI1NiIs...",
     "api_key": "sk_live_...",
     "api_key_header": "X-API-Key",
     "custom_headers": {"X-Custom": "value"},
     "principal_id": "auth-1"
   }
   ```

2. **Session Auth:**
   ```json
   {
     "type": "session",
     "cookies": {"sessionid": "abc123", "csrftoken": "xyz789"},
     "principal_id": "auth-2"
   }
   ```

3. **Form Login:**
   ```json
   {
     "type": "form_login",
     "login_url": "https://example.com/login",
     "username": "testuser",
     "password": "secret",
     "username_field": "username",
     "password_field": "password",
     "csrf_field": "csrf_token",
     "extra_fields": {"remember_me": "true"},
     "principal_id": "auth-3"
   }
   ```

4. **Multi-Step:**
   ```json
   {
     "type": "multi_step",
     "steps": [
       {"type": "token", "bearer": "token1"},
       {"type": "form_login", "login_url": "https://example.com/2fa", "username": "user", "password": "pass"}
     ],
     "principal_id": "auth-4"
   }
   ```

**Response (Queued - 202):**
```json
{
  "id": "job_abc123def456",
  "target": "https://example.com",
  "profile": "web",
  "actor": "acme-corp",
  "policy": {...},
  "state": "queued",
  "started_at": null,
  "finished_at": null,
  "runs": [],
  "findings": [],
  "error": "",
  "attempts": 0,
  "worker": "",
  "idempotency_key": "optional-key",
  "coverage": {},
  "verdict": "pending",
  "poll_url": "/api/assess/job_abc123def456",
  "cancel_url": "/api/assess/job_abc123def456/cancel",
  "sarif_url": "/api/assess/job_abc123def456/sarif",
  "report_url": "/api/assess/job_abc123def456/report.html",
  "audit_chain_hash": "sha256:abc123...",
  "deduplicated": false
}
```

**Response (Inline - 200 when `wait=true`):**
Same structure but with `state: "completed"`, populated `findings`, `runs`, `coverage`, `verdict`.

---

### List Assessments
```http
GET /api/assess?page=1&page_size=20
Authorization: Bearer <api-key>
```

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Items per page, 1-100 (default: 20)

**Response:**
```json
{
  "items": [
    {
      "id": "job_abc123",
      "target": "https://example.com",
      "profile": "web",
      "actor": "acme-corp",
      "state": "completed",
      "started_at": 1705312800.0,
      "finished_at": 1705312860.0,
      "verdict": "pass",
      "findings_count": 5,
      "poll_url": "/api/assess/job_abc123",
      "cancel_url": "/api/assess/job_abc123/cancel",
      "sarif_url": "/api/assess/job_abc123/sarif",
      "report_url": "/api/assess/job_abc123/report.html",
      "audit_chain_hash": ""
    }
  ],
  "total": 150,
  "page": 1,
  "page_size": 20,
  "has_next": true
}
```

---

### Get Assessment Details
```http
GET /api/assess/{job_id}
Authorization: Bearer <api-key>
```

**Response:**
```json
{
  "id": "job_abc123",
  "target": "https://example.com",
  "profile": "web",
  "actor": "acme-corp",
  "policy": {...},
  "state": "completed",
  "started_at": 1705312800.0,
  "finished_at": 1705312860.0,
  "runs": [
    {
      "adapter": "http-headers",
      "state": "ok",
      "started_at": 1705312800.0,
      "finished_at": 1705312805.0,
      "findings": [],
      "error": null
    }
  ],
  "findings": [
    {
      "fingerprint": "a1b2c3d4e5f6...",
      "category": "Missing Security Header",
      "severity": "low",
      "title": "Missing X-Frame-Options Header",
      "description": "The response lacks an X-Frame-Options header...",
      "location": "https://example.com/",
      "evidence": {"header": "X-Frame-Options", "expected": "DENY or SAMEORIGIN"},
      "status": "new",
      "created_at": 1705312805.0
    }
  ],
  "error": "",
  "attempts": 1,
  "worker": "worker-1",
  "idempotency_key": "optional-key",
  "coverage": {"http-headers": {"pages": 1, "findings": 1}},
  "verdict": "pass",
  "poll_url": "/api/assess/job_abc123",
  "cancel_url": "/api/assess/job_abc123/cancel",
  "sarif_url": "/api/assess/job_abc123/sarif",
  "report_url": "/api/assess/job_abc123/report.html",
  "audit_chain_hash": "sha256:abc123...",
  "deduplicated": false
}
```

---

### Get SARIF Export
```http
GET /api/assess/{job_id}/sarif
Authorization: Bearer <api-key>
```

**Response:** `application/sarif+json`
```json
{
  "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Ishastra",
          "version": "3.5.0",
          "informationUri": "https://ishastra.example.com"
        }
      },
      "results": [
        {
          "ruleId": "missing-x-frame-options",
          "level": "warning",
          "message": {"text": "Missing X-Frame-Options Header"},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "https://example.com/"}
              }
            }
          ],
          "fingerprints": {"sha256": "a1b2c3d4e5f6..."}
        }
      ]
    }
  ]
}
```

---

### Update Finding Status
```http
PATCH /api/assess/{job_id}/findings/{fingerprint}
Authorization: Bearer <api-key>
Content-Type: application/json
```

**Request Body:**
```json
{
  "status": "triaged",
  "note": "False positive - header present in CSP"
}
```

**Valid Statuses:** `new`, `triaged`, `in_progress`, `fix_verified`, `closed`, `reopened`, `deferred`

**Lifecycle Rules:**
- Cannot skip from `new` directly to `closed`
- Cannot reopen a `closed` finding
- Each transition is audited

**Response:**
```json
{
  "fingerprint": "a1b2c3d4e5f6...",
  "category": "Missing Security Header",
  "severity": "low",
  "title": "Missing X-Frame-Options Header",
  "description": "...",
  "location": "https://example.com/",
  "evidence": {...},
  "status": "triaged",
  "note": "False positive - header present in CSP",
  "updated_at": 1705313000.0,
  "updated_by": "acme-corp"
}
```

---

## Cross-Job Finding Records

A finding fingerprint (`asset + category + location`) is stable across jobs.
These endpoints aggregate the tenant's per-job finding rows into one record per
fingerprint. The record owns remediation metadata and an optional
coverage-checked resolution. A missing fingerprint alone is never treated as
proof of resolution.

### List Finding Records
```http
GET /api/findings?page=1&page_size=50
Authorization: Bearer <api-key>
```

**Query Parameters:** `page` (default 1), `page_size` (1-200, default 50).

**Response:**
```json
{
  "items": [
    {
      "fingerprint": "a1b2c3d4e5f6...",
      "asset": "https://example.com/",
      "category": "missing_csp",
      "title": "Missing CSP",
      "severity": "low",
      "confidence": "high",
      "verification": "observed",
      "status": "new",
      "detector": "http-headers",
      "location": "/",
      "first_seen": 1705312800.0,
      "last_seen": 1707991200.0,
      "occurrence_count": 2,
      "last_job": {
        "id": "job_def456",
        "target": "https://example.com/",
        "state": "completed",
        "verdict": "findings",
        "created_at": 1707991200.0,
        "finished_at": 1707991210.0
      }
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 50,
  "has_next": false
}
```

Fields other than the aggregate timestamps/count describe the latest occurrence.
Each item also includes `remediation` (`owner`, `due_at`, exception fields) and
`resolution` (`state`, `resolved_at`, `job_id`, `evidence`).

### Finding Trends
```http
GET /api/findings/trends?start=1704067200&end=1706745600&bucket=day
Authorization: Bearer <api-key>
```

`start` and `end` are inclusive Unix timestamps; the default is the last 30
days. `bucket` is `day`, `week` or `month`; the maximum range is 366 days.

**Response:**
```json
{
  "start": 1704067200.0,
  "end": 1706745600.0,
  "bucket": "day",
  "buckets": [
    {
      "bucket": "2024-01-01",
      "observations": 4,
      "unique_findings": 3,
      "new_findings": 2,
      "resolved_findings": 0,
      "severity": {"critical": 0, "high": 1, "medium": 2, "low": 1, "info": 0}
    }
  ]
}
```

### Get Finding Record
```http
GET /api/findings/{fingerprint}
Authorization: Bearer <api-key>
```

Same fields as a list item plus `history`, ordered oldest to newest. Each history
entry is one job occurrence:

```json
{
  "job_id": "job_abc123",
  "target": "https://example.com/",
  "job_state": "completed",
  "job_verdict": "findings",
  "job_created_at": 1705312800.0,
  "job_finished_at": 1705312810.0,
  "seen_at": 1705312810.0,
  "status": "new",
  "severity": "low",
  "confidence": "high",
  "verification": "observed",
  "title": "Missing CSP",
  "detector": "http-headers"
}
```

A malformed fingerprint returns `422`; an unknown fingerprint returns `404`.

### Update Finding Remediation
```http
PATCH /api/findings/{fingerprint}/remediation
Authorization: Bearer <api-key>
Content-Type: application/json
```

Same body and validation as the per-assessment remediation endpoint. The tenant
record is updated, so the owner/deadline survives future jobs. The legacy
per-assessment endpoint mirrors into the same record.

### Request a Risk Exception
```http
POST /api/findings/{fingerprint}/exception
Authorization: Bearer <api-key>
Content-Type: application/json

{"until": 1735689600.0, "reason": "Compensating control approved by owner"}
```

Creates a `pending` exception. A request does not suppress the finding; an
administrator must decide it. Expired pending/approved exceptions report
`state: "expired"` on reads.

### Decide a Risk Exception
```http
POST /api/findings/{fingerprint}/exception/decision
Authorization: Bearer <api-key>  (administrator)
Content-Type: application/json

{"approve": true, "note": "Accepted for 30 days"}
```

Only a `pending` exception can be decided. Repeating a decision returns `409`.
The request and decision are audited and sealed.

### Verify Finding Resolution
```http
POST /api/findings/{fingerprint}/resolve
Authorization: Bearer <api-key>
Content-Type: application/json

{"job_id": "job_def456"}
```

The verification job must:

- belong to the same tenant and target the same asset;
- be newer than the finding's last occurrence and not be an occurrence itself;
- be `completed`;
- contain no finding with this fingerprint;
- have an `ok` run for every detector that observed the fingerprint.

Any missing detector run is a `409`: partial coverage is not resolution evidence.
Success stores `resolution.state = "resolved"`, the verifying job, timestamp and
coverage evidence. A later occurrence automatically reopens the record.

---

### Cancel Assessment
```http
POST /api/assess/{job_id}/cancel
Authorization: Bearer <api-key>
```

**Response:**
```json
{
  "id": "job_abc123",
  "state": "cancelling",
  "detail": "cancellation signalled; poll the job for its final state"
}
```

---

### Retry Assessment
```http
POST /api/assess/{job_id}/retry
Authorization: Bearer <api-key>
```

**Response (202):**
```json
{
  "id": "job_def456",
  "target": "https://example.com",
  "profile": "web",
  "actor": "acme-corp",
  "policy": {...},
  "state": "queued",
  "poll_url": "/api/assess/job_def456",
  "cancel_url": "/api/assess/job_def456/cancel",
  "retry_of": "job_abc123"
}
```

---

### AI Triage (Advisory)
```http
POST /api/assess/{job_id}/triage
Authorization: Bearer <api-key>
```

**Response:**
```json
{
  "job_id": "job_abc123",
  "findings_count": 5,
  "ai_enriched": true,
  "provider": "openai-gpt4",
  "triage": [
    {
      "fingerprint": "a1b2c3d4e5f6...",
      "priority": "high",
      "rationale": "This finding indicates a potential clickjacking vulnerability...",
      "next_steps": ["Verify CSP frame-ancestors directive", "Add X-Frame-Options header"]
    }
  ]
}
```

---

### HTML Report
```http
GET /api/assess/{job_id}/report.html
Authorization: Bearer <api-key>
```

**Response:** `text/html` - Self-contained HTML report with evidence, findings, and integrity verification.

---

### PDF Report
```http
GET /api/assess/{job_id}/report.pdf
Authorization: Bearer <api-key>
```

**Response:** `application/pdf` - Professional PDF report generated via WeasyPrint.

---

### Evidence Report (JSON)
```http
POST /api/report
Authorization: Bearer <api-key>
Content-Type: application/json
```

**Request Body:**
```json
{
  "target": "https://example.com"
}
```

**Response:**
```json
{
  "program": "Acme Corp Bug Bounty",
  "authorized_by": "Security Team",
  "authorization_ref": "BB-2024-001",
  "scope_include": ["example.com", "api.example.com"],
  "authorization_metadata_available": true,
  "policy_id": "pol_abc123",
  "policy_version": 1,
  "target": "https://example.com",
  "job_id": "job_abc123",
  "generated_at": "2024-01-15T10:35:00Z",
  "state": "completed",
  "verdict": "pass",
  "coverage": {"http-headers": {"pages": 1, "findings": 1}},
  "severity_counts": {"critical": 0, "high": 0, "medium": 2, "low": 3, "info": 1},
  "findings": [...],
  "summary": "6 finding(s) on https://example.com under Acme Corp Bug Bounty [BB-2024-001]; job job_abc123 completed",
  "integrity": {
    "chain_valid": true,
    "chain_hash": "sha256:abc123..."
  }
}
```

---

## Monitoring Endpoints

### Monitor Status
```http
GET /api/monitor/status
Authorization: Bearer <api-key>
```

**Response (Admin):**
```json
{
  "scope": "platform",
  "tenant_id": "admin",
  "running": true,
  "interval_seconds": 300,
  "targets": ["https://example.com", "https://api.example.com"],
  "total_schedules": 10,
  "active_schedules": 8,
  "last_run": 1705312800,
  "jobs": 1500,
  "findings": 12000
}
```

**Response (Tenant):**
```json
{
  "scope": "tenant",
  "tenant_id": "acme-corp",
  "running": true,
  "jobs": 150,
  "findings": 1234
}
```

---

### Configure Monitor (Admin Only)
```http
POST /api/monitor/configure
Authorization: Bearer <admin-api-key>
Content-Type: application/json
```

**Request Body:**
```json
{
  "interval_seconds": 300,
  "targets": ["https://example.com", "https://api.example.com"],
  "replace": false
}
```

**Response:**
```json
{
  "interval_seconds": 300,
  "monitored_targets": ["https://example.com", "https://api.example.com"],
  "running": true
}
```

---

### Add Webhook Sink (Admin Only)
```http
POST /api/alerts/webhook
Authorization: Bearer <admin-api-key>
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "slack-alerts",
  "url": "https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>"
}
```

**Response:**
```json
{
  "sink_name": "slack-alerts",
  "added": true
}
```

**Webhook Payload Format:**
```json
{
  "event": "assessment_completed",
  "timestamp": "2024-01-15T10:35:00Z",
  "job_id": "job_abc123",
  "target": "https://example.com",
  "profile": "web-deep",
  "verdict": "fail",
  "severity_counts": {"critical": 1, "high": 2, "medium": 3, "low": 1, "info": 0},
  "findings": [
    {
      "fingerprint": "a1b2c3d4e5f6...",
      "category": "SQL Injection",
      "severity": "critical",
      "title": "SQL Injection in Search Parameter",
      "location": "https://example.com/search?q=test"
    }
  ],
  "report_url": "https://ishastra.example.com/api/assess/job_abc123/report.html"
}
```

---

## Policy Management Endpoints (Admin Only)

### List Policies
```http
GET /api/policies
Authorization: Bearer <admin-api-key>
```

**Response:**
```json
{
  "count": 5,
  "mode": "managed",
  "policies": [
    {
      "policy_id": "pol_abc123",
      "tenant_id": "acme-corp",
      "program": "Acme Corp Bug Bounty",
      "authorized_by": "Security Team",
      "authorization_ref": "BB-2024-001",
      "version": 1,
      "status": "active",
      "include": ["example.com", "api.example.com"],
      "exclude": ["staging.example.com"],
      "authorized_networks": ["10.0.0.0/8"],
      "allowed_ports": [80, 443, 8080, 8443],
      "allow_broad_networks": false,
      "effective_at": 1705312800,
      "expires_at": 1736848800,
      "created_by": "admin",
      "created_at": 1705312800
    }
  ]
}
```

---

### Create Policy
```http
POST /api/policies
Authorization: Bearer <admin-api-key>
Content-Type: application/json
```

**Request Body:**
```json
{
  "tenant": "acme-corp",
  "program": "Acme Corp Bug Bounty",
  "authorized_by": "Security Team",
  "authorization_ref": "BB-2024-001",
  "include": ["example.com", "api.example.com"],
  "exclude": ["staging.example.com"],
  "authorized_networks": ["10.0.0.0/8"],
  "allowed_ports": [80, 443, 8080, 8443],
  "allow_broad_networks": false,
  "ttl_seconds": 31536000,
  "effective_in_seconds": 0
}
```

**Response:**
```json
{
  "policy_id": "pol_abc123",
  "tenant_id": "acme-corp",
  "program": "Acme Corp Bug Bounty",
  "authorized_by": "Security Team",
  "authorization_ref": "BB-2024-001",
  "version": 1,
  "status": "active",
  "include": ["example.com", "api.example.com"],
  "exclude": ["staging.example.com"],
  "authorized_networks": ["10.0.0.0/8"],
  "allowed_ports": [80, 443, 8080, 8443],
  "allow_broad_networks": false,
  "effective_at": 1705312800,
  "expires_at": 1736848800,
  "created_by": "admin",
  "created_at": 1705312800
}
```

---

### Update Policy
```http
PATCH /api/policies/{policy_id}
Authorization: Bearer <admin-api-key>
Content-Type: application/json
```

**Request Body:**
```json
{
  "include": ["example.com", "api.example.com", "new.example.com"],
  "ttl_seconds": 63072000
}
```

**Response:**
```json
{
  "policy_id": "pol_abc123",
  "tenant_id": "acme-corp",
  "program": "Acme Corp Bug Bounty",
  "authorized_by": "Security Team",
  "authorization_ref": "BB-2024-001",
  "version": 2,
  "status": "active",
  "include": ["example.com", "api.example.com", "new.example.com"],
  "exclude": ["staging.example.com"],
  "authorized_networks": ["10.0.0.0/8"],
  "allowed_ports": [80, 443, 8080, 8443],
  "allow_broad_networks": false,
  "effective_at": 1705312800,
  "expires_at": 1768384800,
  "created_by": "admin",
  "created_at": 1705312800,
  "cancelled_jobs": 3
}
```

---

### Revoke Policy
```http
POST /api/policies/{policy_id}/revoke
Authorization: Bearer <admin-api-key>
```

**Response:**
```json
{
  "policy_id": "pol_abc123",
  "status": "revoked",
  "version": 2,
  "cancelled_jobs": 5
}
```

---

### Get Policy
```http
GET /api/policies/{policy_id}
Authorization: Bearer <admin-api-key>
```

**Response:** Same as create response.

---

## Tenant & API Key Management

### List Tenants (Admin sees all, Tenant sees own)
```http
GET /api/tenants
Authorization: Bearer <api-key>
```

**Response:**
```json
{
  "requesting_tenant": "acme-corp",
  "tiers": ["standard", "elevated", "unlimited"],
  "tenants": {
    "acme-corp": {"tier": "unlimited", "active": true, "admin": false, "scope": "write"}
  }
}
```

---

### Create API Key (Admin or Tenant Owner)
```http
POST /api/keys/create
Authorization: Bearer <api-key>
Content-Type: application/json
```

**Request Body:**
```json
{
  "tenant": "acme-corp",
  "tier": "unlimited",
  "scope": "read",
  "ttl_days": 365
}
```

**Response:**
```json
{
  "created_by": "admin",
  "tenant": "acme-corp",
  "tier": "unlimited",
  "scope": "read",
  "api_key": "sk_live_abc123...",
  "expires_at": "2025-01-15T10:30:00Z",
  "warning": "Store this key securely — it is shown only once."
}
```

---

### Rotate API Key
```http
POST /api/keys/rotate/{tenant_id}?ttl_days=365
Authorization: Bearer <api-key>
```

**Response:**
```json
{
  "rotated_tenant": "acme-corp",
  "rotated_by": "admin",
  "scope": "write",
  "api_key": "sk_live_newkey...",
  "expires_at": "2025-01-15T10:30:00Z",
  "warning": "Store this key securely — it is shown only once. The previous key is no longer valid."
}
```

---

### Get Key Status
```http
GET /api/keys/status
Authorization: Bearer <api-key>
```

**Response:**
```json
{
  "tenant_id": "acme-corp",
  "tier": "unlimited",
  "active": true,
  "admin": false,
  "scope": "write",
  "expires_at": "2025-01-15T10:30:00Z",
  "created_at": "2024-01-15T10:30:00Z",
  "last_used_at": "2024-01-14T15:20:00Z"
}
```

---

### Revoke API Key
```http
POST /api/keys/revoke/{tenant_id}
Authorization: Bearer <api-key>
```

**Response:**
```json
{
  "revoked_tenant": "acme-corp",
  "revoked_by": "admin"
}
```

---

### List Tenant Users (Tenant Admin)
```http
GET /api/users
Authorization: Bearer <tenant-admin-key>
```

Returns member IDs, display names, roles, scopes and active state. Secrets are
never returned.

### Create Tenant User (Tenant Admin)
```http
POST /api/users
Authorization: Bearer <tenant-admin-key>
Content-Type: application/json

{"display_name": "Alice", "role": "analyst", "ttl_days": 365}
```

Roles are `admin`, `analyst` and `viewer`. Viewers receive read-only keys;
analysts and admins receive write keys. The response includes the member
`user_id` and a one-time `api_key`.

### Revoke Tenant User (Tenant Admin)
```http
POST /api/users/{user_id}/revoke
Authorization: Bearer <tenant-admin-key>
```

Revokes that member's key only; the legacy tenant key and other members are
unaffected.

---

## Scheduler Endpoints (Admin Only)

### List Schedules
```http
GET /api/schedules?page=1&page_size=20&state=active
Authorization: Bearer <admin-api-key>
```

**Response:**
```json
{
  "items": [
    {
      "id": "sched_abc123",
      "target": "https://example.com",
      "cron_expression": "0 2 * * *",
      "timezone": "UTC",
      "profile": "web-deep",
      "state": "active",
      "policy_id": "pol_abc123",
      "created_at": 1705312800,
      "updated_at": 1705312800,
      "last_run": 1705399200,
      "next_run": 1705485600,
      "run_count": 45,
      "max_concurrent": 1,
      "catch_up": true,
      "enabled": true
    }
  ],
  "total": 10,
  "page": 1,
  "page_size": 20,
  "has_next": false
}
```

---

### List Frequency Presets
```http
GET /api/schedules/frequencies
Authorization: Bearer <admin-api-key>
```

**Response:**
```json
{
  "frequencies": [
    {
      "id": "daily",
      "name": "Daily",
      "description": "Run once per day at a specific time",
      "example_cron": "0 2 * * *",
      "example_description": "Daily at 2:00 AM"
    },
    {
      "id": "weekly",
      "name": "Weekly",
      "description": "Run once per week on a specific day",
      "example_cron": "0 2 * * 1",
      "example_description": "Weekly on Monday at 2:00 AM"
    },
    {
      "id": "monthly",
      "name": "Monthly",
      "description": "Run once per month on a specific day",
      "example_cron": "0 2 1 * *",
      "example_description": "Monthly on the 1st at 2:00 AM"
    },
    {
      "id": "custom",
      "name": "Custom",
      "description": "Custom cron expression",
      "example_cron": "0 */6 * * *",
      "example_description": "Every 6 hours"
    }
  ],
  "timezone_examples": [
    "UTC", "America/New_York", "America/Los_Angeles",
    "Europe/London", "Europe/Paris", "Asia/Tokyo", "Australia/Sydney"
  ]
}
```

---

### Get Schedule
```http
GET /api/schedules/{schedule_id}
Authorization: Bearer <admin-api-key>
```

---

### Create Schedule
```http
POST /api/schedules
Authorization: Bearer <admin-api-key>
Content-Type: application/json
```

**Request Body:**
```json
{
  "target": "https://example.com",
  "cron_expression": "0 2 * * *",
  "timezone": "America/New_York",
  "profile": "web-deep",
  "policy_id": "pol_abc123",
  "max_concurrent": 1,
  "catch_up": true
}
```

---

### Update Schedule
```http
PATCH /api/schedules/{schedule_id}
Authorization: Bearer <admin-api-key>
Content-Type: application/json
```

**Request Body:**
```json
{
  "cron_expression": "0 3 * * *",
  "timezone": "UTC",
  "profile": "api-deep",
  "state": "active",
  "max_concurrent": 2,
  "catch_up": false,
  "enabled": true
}
```

---

### Delete Schedule
```http
DELETE /api/schedules/{schedule_id}
Authorization: Bearer <admin-api-key>
```

**Response:**
```json
{
  "deleted": true,
  "schedule_id": "sched_abc123"
}
```

---

### Pause Schedule
```http
POST /api/schedules/{schedule_id}/pause
Authorization: Bearer <admin-api-key>
```

---

### Resume Schedule
```http
POST /api/schedules/{schedule_id}/resume
Authorization: Bearer <admin-api-key>
```

---

### Run Schedule Now
```http
POST /api/schedules/{schedule_id}/run
Authorization: Bearer <admin-api-key>
```

**Response:**
```json
{
  "schedule_id": "sched_abc123",
  "job_id": "job_xyz789",
  "target": "https://example.com",
  "started_at": 1705312800,
  "finished_at": 1705312860,
  "state": "completed",
  "findings_count": 5,
  "new_high_severity": 1,
  "error": "",
  "alert_emitted": true
}
```

---

### Scheduler Status
```http
GET /api/scheduler/status
Authorization: Bearer <admin-api-key>
```

**Response:**
```json
{
  "running": true,
  "total_schedules": 10,
  "active_schedules": 8,
  "paused_schedules": 2
}
```

---

## Probe Endpoint

### Security Header Probe
```http
POST /api/probe
Authorization: Bearer <api-key>
Content-Type: application/json
```

**Request Body:**
```json
{
  "url": "https://example.com",
  "timeout": 6.0
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "status_code": 200,
  "latency_ms": 145.23,
  "security_headers": {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-frame-options": "SAMEORIGIN",
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'self'",
    "referrer-policy": "strict-origin-when-cross-origin"
  },
  "raw_headers": {
    "server": "nginx",
    "date": "Mon, 15 Jan 2024 10:30:00 GMT",
    "content-type": "text/html; charset=utf-8",
    "set-cookie": ["session=abc123; HttpOnly; Secure; SameSite=Strict"]
  },
  "body_snippet": "<!DOCTYPE html>...",
  "security_score": 85,
  "security_grade": "B",
  "deductions": [
    {"header": "permissions-policy", "points": 5, "reason": "Missing Permissions-Policy header"},
    {"header": "cross-origin-opener-policy", "points": 5, "reason": "Missing COOP header"}
  ],
  "error": null,
  "blocked": false,
  "reason": null
}
```

**Blocked Response:**
```json
{
  "url": "https://example.com",
  "status_code": "blocked",
  "latency_ms": 0,
  "security_headers": {},
  "raw_headers": {},
  "body_snippet": "",
  "security_score": null,
  "security_grade": "N/A",
  "deductions": [],
  "blocked": true,
  "reason": "Target https://example.com is not within authorized scope"
}
```

---

## Proof Verification

### Verify Proof Pack
```http
POST /api/proof/verify
Content-Type: application/json
```

**Authentication:** None (public)

**Request Body:**
```json
{
  "proof": {
    "version": "1.0",
    "issuer": "ishastra",
    "issued_at": 1705312800,
    "job_id": "job_abc123",
    "target": "https://example.com",
    "policy": {...},
    "findings": [...],
    "signatures": {...}
  },
  "trusted_issuer": "optional-pinned-issuer-key",
  "trusted_gate": "optional-pinned-gate-key"
}
```

**Response:**
```json
{
  "valid": true,
  "issuer_verified": true,
  "gate_verified": true,
  "chain_valid": true,
  "policy_verified": true,
  "findings_verified": true,
  "errors": [],
  "verified_at": 1705313000
}
```

---

## Rate Limiting

Rate limits are enforced per API key tier:

| Tier | General requests/min | Assessment submissions/min |
|------|----------------------|----------------------------|
| `standard` | 5 | 5 |
| `elevated` | 60 | 20 |
| `unlimited` | 300 | 60 |

The tier controls rate limits only; all features are identical and MIT-licensed.

**Headers Returned:**
- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Requests remaining in window
- `X-RateLimit-Reset`: Unix timestamp when window resets

**Rate Limit Exceeded (429):**
```json
{
  "detail": "Rate limit exceeded. Try again in 45 seconds."
}
```

---

## Error Responses

All errors follow a consistent format:

```json
{
  "detail": "Human-readable error message",
  "errors": [
    {
      "loc": ["body", "field_name"],
      "msg": "Field required",
      "type": "missing"
    }
  ]
}
```

### Common HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success (inline assessment) |
| 201 | Created (schedule) |
| 202 | Accepted (queued assessment) |
| 400 | Bad Request (validation error) |
| 401 | Unauthorized (invalid/missing API key) |
| 403 | Forbidden (insufficient permissions, target out of scope) |
| 404 | Not Found (job, schedule, policy not found) |
| 409 | Conflict (job not in retryable state, duplicate key) |
| 422 | Validation Error (request body invalid) |
| 429 | Rate Limit Exceeded |
| 500 | Internal Server Error |
| 501 | Not Implemented (PDF generation unavailable) |
| 503 | Service Unavailable (queue full, worker unavailable, Redis down) |

---

## Example Requests

### Complete Assessment Workflow

#### 1. Create API Key (Admin)
```bash
curl -X POST http://localhost:8000/api/keys/create \
  -H "Authorization: Bearer sk_admin_abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant": "acme-corp",
    "tier": "unlimited",
    "ttl_days": 365
  }'
```

#### 2. Create Policy (Admin)
```bash
curl -X POST http://localhost:8000/api/policies \
  -H "Authorization: Bearer sk_admin_abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant": "acme-corp",
    "program": "Acme Corp Bug Bounty",
    "authorized_by": "Security Team",
    "authorization_ref": "BB-2024-001",
    "include": ["example.com", "api.example.com"],
    "exclude": ["staging.example.com"],
    "authorized_networks": ["10.0.0.0/8"],
    "allowed_ports": [80, 443, 8080, 8443],
    "allow_broad_networks": false,
    "ttl_seconds": 31536000
  }'
```

#### 3. Queue Assessment (Tenant)
```bash
curl -X POST http://localhost:8000/api/assess \
  -H "Authorization: Bearer sk_live_tenant_key" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: assessment-2024-01-15-001" \
  -d '{
    "target": "https://example.com",
    "profile": "web-deep",
    "timeout": 300,
    "policy_id": "pol_abc123"
  }'
```

#### 4. Poll for Results
```bash
curl -X GET http://localhost:8000/api/assess/job_abc123 \
  -H "Authorization: Bearer sk_live_tenant_key"
```

#### 5. Get SARIF Report
```bash
curl -X GET http://localhost:8000/api/assess/job_abc123/sarif \
  -H "Authorization: Bearer sk_live_tenant_key" \
  -o results.sarif
```

#### 6. Get HTML Report
```bash
curl -X GET http://localhost:8000/api/assess/job_abc123/report.html \
  -H "Authorization: Bearer sk_live_tenant_key" \
  -o report.html
```

#### 7. Update Finding Status
```bash
curl -X PATCH http://localhost:8000/api/assess/job_abc123/findings/a1b2c3d4e5f6 \
  -H "Authorization: Bearer sk_live_tenant_key" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "fix_verified",
    "note": "Verified fix in commit abc123"
  }'
```

---

### Monitoring Setup (Admin)

#### Configure Monitor
```bash
curl -X POST http://localhost:8000/api/monitor/configure \
  -H "Authorization: Bearer sk_admin_abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "interval_seconds": 300,
    "targets": ["https://example.com", "https://api.example.com"],
    "replace": true
  }'
```

#### Add Slack Webhook
```bash
curl -X POST http://localhost:8000/api/alerts/webhook \
  -H "Authorization: Bearer sk_admin_abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "slack-security-alerts",
    "url": "https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>"
  }'
```

---

### Scheduling Recurring Assessments (Admin)

#### Create Daily Schedule
```bash
curl -X POST http://localhost:8000/api/schedules \
  -H "Authorization: Bearer sk_admin_abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "cron_expression": "0 2 * * *",
    "timezone": "America/New_York",
    "profile": "web-deep",
    "policy_id": "pol_abc123",
    "max_concurrent": 1,
    "catch_up": true
  }'
```

#### Run Schedule Immediately
```bash
curl -X POST http://localhost:8000/api/schedules/sched_abc123/run \
  -H "Authorization: Bearer sk_admin_abc123"
```

---

### Probe Endpoint

#### Quick Security Header Check
```bash
curl -X POST http://localhost:8000/api/probe \
  -H "Authorization: Bearer sk_live_tenant_key" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "timeout": 6.0
  }'
```

---

### Public Proof Verification

```bash
curl -X POST http://localhost:8000/api/proof/verify \
  -H "Content-Type: application/json" \
  -d '{
    "proof": {...},
    "trusted_issuer": "optional-pinned-key"
  }'
```

---

## WebSocket / Real-time Updates

Currently, the API does not provide WebSocket endpoints. For real-time updates, use:
- Polling `GET /api/assess/{job_id}` with exponential backoff
- Webhook alerts via `/api/alerts/webhook` for monitoring events

---

## SDKs and Client Libraries

### Python (httpx)
```python
import httpx

client = httpx.Client(
    base_url="http://localhost:8000/api",
    headers={"Authorization": "Bearer sk_live_tenant_key"}
)

# Queue assessment
response = client.post("/assess", json={
    "target": "https://example.com",
    "profile": "web-deep"
})
job = response.json()

# Poll for completion
while job["state"] in ("queued", "running"):
    import time
    time.sleep(5)
    job = client.get(f"/assess/{job['id']}").json()

print(f"Verdict: {job['verdict']}")
print(f"Findings: {len(job['findings'])}")
```

### cURL Wrapper Script
```bash
#!/bin/bash
# ishastra-cli.sh
API_KEY="${ISHASTRA_API_KEY}"
BASE_URL="${ISHASTRA_BASE_URL:-http://localhost:8000/api}"

strix_api() {
    curl -s -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" "$@"
}
```

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 0.1.0 | 2024-01-15 | Initial API documentation |

---

## Support

- **Documentation:** `/docs` (Swagger UI) or `/redoc` (ReDoc)
- **Issues:** GitHub Issues
- **Security:** security@example.com
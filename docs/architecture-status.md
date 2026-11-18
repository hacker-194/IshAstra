# Strix Architecture

Status: describes the implementation in the current working tree (v3.5.0).
Companion documents: [`ARCHITECTURE.md`](../ARCHITECTURE.md) (detailed
reference), [`codemaps.md`](codemaps.md) (module map),
[`customer-workflows.md`](customer-workflows.md) (what works), and
[`production-readiness.md`](production-readiness.md) (what is safe to run).

## 1. Shape

Strix is a **modular monolith**: one Python package, one FastAPI process by
default, one SQLite database, one bounded worker pool in that process. Modules
have explicit contracts but are not separate services. This is deliberate:
the operational cost of microservices is not justified before there is a
validated multi-node requirement.

```
CLI / REST / static UI
        │
        ▼
API layer (auth, tenant state, rate limit, body limits, audit)
        │
        ▼
Job orchestration ──► queue (in-process default, Celery optional)
        │
        ▼
Scope gate ──► adapters (HTTP, crawl, OpenAPI, authz, SSRF, git, TCP, nmap, nuclei)
        │
        ▼
Findings engine (normalize, dedupe, redact, fingerprint, SARIF)
        │
        ▼
Store (SQLite/aiosqlite; optional PostgreSQL) + audit chain
```

## 2. Product components and current code

| Component | Responsibility | Code |
|---|---|---|
| **Strix Core** | Configuration, scope gate, policies, jobs, worker, store, findings, audit, metrics | `src/strix/config.py`, `src/strix/core/*` |
| **Strix Scan** | Live-target detection adapters and profiles | `core/adapters.py`, `adapter_base.py`, `probe.py`, `crawler.py`, `ports.py`, `exposure.py`, `signatures.py` |
| **Strix Intelligence** | Advisory AI triage; monitoring baselines | `analyst.py`, `monitor.py` (trend analytics absent) |
| **Strix Proof** | Signed grants, receipt chain, offline verification | `proof.py`, `core/collab.py`, CLI `grant/gate/proof/verify` |
| **Strix Monitor** | Recurring assessments, new-finding alerts | `core/scheduler.py`, `monitor.py`, `/api/schedules` |
| **Strix Integrations** | SIEM, ticketing, chat, CI/CD, webhooks, vault | `integrations/*` |
| **Strix Organizations & Access** | Organizations, teams, memberships, roles, SSO, SCIM | Multi-user `admin`/`analyst`/`viewer`, organizations/teams (`/api/v2/orgs`), OIDC + SAML SSO (`/auth/*`) and SCIM 2.0 (`/scim/v2`) implemented |

## 3. Contracts

**HTTP API.** Bearer key authentication; tenant derived from the key, never from
headers. Tenant-scoped reads return 404 rather than confirming another tenant's
object. Status changes are audited and sealed for security-relevant events.

**Adapter contract** (`core/adapter_base.py`). Every adapter:

- declares `id`, `version`, `asset_types`, `requires`;
- calls `checked_destination(target)` before any network operation;
- honours the wall-clock timeout and cancellation event;
- returns `AdapterResult(findings, notes, partial)`;
- never invents evidence or upgrades an inference to an observation.

**Connector contract** (`integrations/base.py`). Connectors declare availability,
send bounded finding/alert payloads, redact secrets, and return a structured
result. They do not mutate findings.

**Finding contract** (`core/findings.py`). Frozen dataclass; identity is
`sha256(asset | category | location)`; severity, confidence and verification are
independent axes; output is redacted. Lifecycle transitions are validated
server-side.

**Job contract** (`core/jobs.py`). States are `queued → running → completed |
partial | failed | cancelled`. Coverage per adapter is recorded. A job may only
claim "clean" when every selected adapter completed with no findings.

**Store contract** (`core/store.py`). Async functions are canonical; synchronous
wrappers exist for the CLI and worker threads. SQLite is the default. The
PostgreSQL path uses loop-aware pools and a scheduler memory job store with the
database as the authoritative schedule record; validated: schema migrations
v1-v20, SIGTERM soak (no stale lock, audit chain intact, API verify passes),
load soak (10 jobs, 0 failed), Celery queue integration (10 jobs distributed
across Celery workers). No HA/multi-node support.

## 4. Runtime modes

| Mode | Trigger | Status |
|---|---|---|
| Single process, in-memory queue | Default | Supported |
| Redis rate limiting | `STRIX_WORKERS>1` or `STRIX_REDIS_REQUIRED=1` | Supported |
| Celery + Redis job queue | `STRIX_QUEUE_MODE=celery`, compose `celery` profile | **Experimental** (10-job load soak passed) |
| PostgreSQL | `STRIX_DATABASE_URL` plus `asyncpg` extra | **Advanced: tested single-host, no HA** (SIGTERM soak, load soak, audit chain, Celery integration passed) |
| Multi-node API + shared queue | Celery mode | Not production-ready |

As of this change, API routers obtain their queue from
`core.queue.get_assessment_worker()`, so `STRIX_QUEUE_MODE=celery` actually
routes submissions and policy revocations to Celery instead of silently using
the in-process worker. Cancellation is persisted in the database; the Celery
worker polls it, revokes queued task IDs and stops running jobs cooperatively.
Running and queued cancellation were validated on one host. Multi-node
scheduling, exactly-once execution and crash recovery remain unsupported.

## 5. Security boundaries

| Boundary | Control |
|---|---|
| Authorization → network | Three-layer scope gate; pinned destination prevents DNS-rebinding TOCTOU |
| Tenant A → tenant B | Key-derived tenant, tenant-filtered queries, 404 on foreign objects, bound scope snapshots |
| Client → API | Body size/depth limits, request IDs, security headers, per-tier rate limits |
| Tool output → findings | Bounds, defused XML, control-character stripping, redaction |
| Secrets → output | Redaction at evidence, errors, audit, SARIF, HTML, webhook boundaries |
| Operator → audit history | Hash-chained audit, optional HMAC key, startup verification |
| AI → system | No tool execution, cannot change severity/status/evidence, fingerprint-bound output |

## 6. Architectural decisions

1. **Keep the modular monolith.** No microservices until a measured scaling or
   isolation requirement appears.
2. **SQLite remains the default.** It matches the supported single-node
   deployment. PostgreSQL has a tested single-host worker path (SIGTERM soak,
   load soak, audit chain integrity, Celery integration all passed) but no HA or
   multi-node migration; multi-node promotion requires failover tests.
3. **In-process queue remains the default.** Celery is an opt-in deployment mode,
   not a second supported architecture. Durable cancellation is implemented and
   tested on one host, but multi-node scheduling/idempotency are not.
4. **No paid edition or feature gating.** Organizations, RBAC and SSO belong in
   the MIT project; there is no billing or commercial feature matrix.
5. **No new runtime dependency without a named user problem.** Optional tool
   integrations stay optional and degrade with explicit partial coverage.
6. **AI is advisory.** Core scanning never depends on a model provider.

## 7. Gaps blocking the next architecture step

- Organizations, teams, memberships and OIDC/SAML SSO are implemented; there is
  no long-term compliance dashboard and no organization-level billing. Phase 1
  is free by design (`commercialization.md`).
- Asset inventory is derived from jobs/findings, with no explicit registration
  or policy linkage.
- Finding events are job-scoped, but `/api/findings` aggregates stable
  fingerprints with first/last seen, tenant-level remediation, bounded date-range
  trends, and coverage-checked resolution. There is no long-term compliance
  dashboard.
- Risk exceptions have an audited request/administrator-decision workflow and
  computed expiry, but no notifications or background expiry sweep.
- Keys support read/write scope and tenant roles, but there are no
  per-project/per-endpoint scopes and no organization-level role inheritance.
- No optional operational usage reporting for quotas (not billing).
- No independent security audit, HA/failover exercise or representative soak.

Each is a product decision, not an invitation to add infrastructure. The
recommended order is: per-project scopes → multi-node/HA deployment. Exception
approval now exists; notifications and a background expiry worker do not.

## 8. Evolution triggers

Add PostgreSQL only when: multi-process API writes are required, SQLite write
contention is measured, and the worker no longer depends on per-thread event
loops. Single-host PostgreSQL is validated (migrations, SIGTERM, load, audit
chain, Celery). Add a shared queue as default only when cross-process
cancellation, idempotency and operational runbooks are tested. Add
per-project/per-endpoint scopes before delegating keys beyond tenant-level
roles.

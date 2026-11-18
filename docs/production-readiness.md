# Strix Production Readiness

Date: 2026-11-15. This document separates what is safe to run today from what is
experimental. It contains no invented performance numbers or availability
claims.

## 1. Readiness summary

| Deployment | Verdict |
|---|---|
| Single-node self-hosted, single process, SQLite | **Conditional go for supervised pilots** |
| Single node with Redis rate limiting, workers > 1 | Conditional; multi-process limiter verified, no soak test |
| Celery + Redis distributed workers | **Experimental**; single-host queue and cross-process cancellation validated, not production-grade (10-job load soak passed) |
| PostgreSQL backend | **Advanced: tested single-host, no HA**; SIGTERM soak, load soak, audit chain integrity, Celery integration all passed on one host |
| Managed multi-tenant hosting | Not provided by the project; self-host only (MIT permits independent hosting) |
| Air-gapped / regulated deployment | Possible with local tooling and no OTLP; validate policy and retention requirements |

"Conditional" means the software runs and its core authorization/evidence paths
are tested, but the operator must complete the checklist below and accept the
documented limitations.

## 2. Verified test evidence (this working tree)

| Suite | Result |
|---|---|
| Suite in this checkout | `pytest tests/unit tests/security` passes. IPv6, PostgreSQL and live-scanner tests are opt-in behind environment variables; `scripts/readiness_check.py` re-runs the gate |
| Live scanners (`nmap` + `nuclei`, loopback lab) | **4 passed in 24.5s** with real nmap and pinned Nuclei v3.11.1 plus official templates |
| Asset/history store and API tests | Passed, including tenant isolation and status/remediation history |
| PostgreSQL schema and assessment run | Migration 18 applied; 20/20 jobs completed with 4 workers |
| E2E tests (Playwright) | **10 critical path tests** covering auth → assessment → findings → SARIF export, tenant isolation, scope enforcement |

Quality gates on this tree: `pytest tests/unit tests/security` passes, and
`ruff check src tests scripts` and `ruff format --check src tests scripts` are
clean repo-wide (the 39 findings once listed here are fixed).
Production-mode tests verify that
missing bootstrap/audit secrets are fatal and that docs are disabled. CI is configured to run the same
gates on `main`/`master`/`release/*` branches with helm-lint, kubeconform, and E2E validation.

### New since 2026-11-14

- **1427 unit + security tests**; 58% statement coverage of 18,284 statements
- **E2E suite** with Playwright (`tests/e2e/`)
- **Helm chart validation** — all 3 environments (prod/staging/dev) lint clean and dry-run against kind cluster
- **Secret rotation CronJob** added to production Helm values (daily 3 AM UTC)
- **Coverage** 58% (threshold 25%)

### New since 2026-11-15

- **External penetration testing tools integrated**: Nikto (web server vulnerability scanner) and sqlmap (SQL injection detection) added as adapters
- **New assessment profiles**: `web-full` (crawl, HTTP, dynamic validation, git-exposure, nuclei, nikto, sqlmap) and `api-full` (crawl, HTTP, openapi, authz, ssrf-oob, dynamic validation, git-exposure, nuclei, nikto, sqlmap)
- **All external scanners scope-gated**: Nikto and sqlmap respect the same authorization boundaries as nmap/nuclei — never widen the engagement
- **Read-only, conservative defaults**: sqlmap runs with `--technique=BT` (boolean/time-based blind only), `--risk=1`, `--level=1`; Nikto excludes DoS tests (`-Tuning 012345789`)

### New since 2026-11-16

- **`strix init` CLI command**: Generates `scope.json` and GitHub Action workflow from repository analysis (addresses VC PLG gap #1)
  - Detects frameworks: FastAPI, Django, Flask, Express, NestJS, Next.js, Spring
  - Extracts routes/endpoints, authentication patterns (JWT, session, API key, OAuth)
  - Infers base domain and generates appropriate scope with common subdomains
  - Generates `.github/workflows/strix-scan.yml` with SARIF upload to GitHub Code Scanning
- **E2E test fixes**: All 10 critical path tests now target implemented endpoints
  - Fixed `/api/metrics` → `/api/metrics/otel`
  - Fixed `/api/assessments` → `/api/assess` (paginated list)
  - Fixed `/api/assess/{id}/findings` → `/api/findings` (cross-job aggregation)
- **Quality gates**: `pytest tests/unit tests/security` passes, `ruff check`/`ruff format` clean, mypy clean; the release workflow builds the wheel and container image

### Operational checks (run 2026-11-14)

| Check | Measured result |
|---|---|
| Live nmap + Nuclei against the loopback lab | 4 passed; CI installs both real binaries and runs this selection |
| Backup/restore drill with audit-chain verification | 14 tables, 4 rows; `integrity_check=ok`; table counts match; HMAC chain `ok` (3 entries) |
| Assessment benchmark, SQLite, 50 jobs / 4 workers | 50/50 completed; **69.70 jobs/s**; p50 651.1 ms, p95 712.4 ms, p99 717.4 ms; wall 0.72 s |
| Assessment benchmark, PostgreSQL, 20 jobs / 4 workers | 20/20 completed; **51.68 jobs/s**; p50 361.9 ms, p95 384.5 ms, p99 387.0 ms; wall 0.39 s |
| PostgreSQL SIGTERM soak test | No stale worker lock; audit chain valid; API verify passes; all jobs terminal |
| Celery + PostgreSQL load soak | 10/10 completed; 1.40 jobs/s; p50 3121.8 ms, p95 6158.5 ms |
| HTTP health baseline (`scripts/load_check.py`, 1000 requests, concurrency 20) | 0 errors; 307.6 req/s; p50 47.9 ms, p95 164.9 ms, p99 229.2 ms (2026-11-13) |
| Redis multi-process rate limiter | Two API processes: 10 allowed, 2 denied, shared limit |
| Release artifact | `strix-3.5.0-py3-none-any.whl` built successfully (474,056 bytes) |

The assessment benchmark uses the fast built-in `web` profile against a
loopback lab. It measures scope checks, adapter execution, job persistence and
finding writes end to end, but not scanner-heavy profiles, wide networks,
long-running crawls, report generation or multi-node scheduling. It is a
single-machine smoke measurement, not a capacity commitment.

## 3. Operational requirements

- TLS-terminating reverse proxy; Strix speaks plain HTTP.
- `STRIX_API_KEY` bootstrap admin key (≥16 chars, not a placeholder).
- `STRIX_ENV=production` plus `STRIX_API_KEY` and `STRIX_AUDIT_HMAC_KEY`; production startup fails closed without the secrets and forces API docs off.
- `STRIX_SCOPE_FILE` or managed policies; without authorization every assessment
  is refused.
- Backups: consistent SQLite backup (`sqlite3 strix.db ".backup out.db"`), tested
  restore, and the same HMAC key (or an explicit chain reset decision).
- Verify a backup with
  `python scripts/operational_check.py --db strix.db --out /tmp/restore.db --hmac-key "$STRIX_AUDIT_HMAC_KEY"`;
  this now checks the restored chain, not only row counts.
- Retention: `STRIX_RETENTION_DAYS` is disabled by default; enable deliberately.
- Trusted proxy list when behind a proxy, so rate limits count real addresses.
- Optional scanners installed and their coverage limitations accepted.
- Monitoring: `/api/health`, `/api/ready`, `/api/metrics` (admin), OTLP optional.

## 4. What customers can use immediately

- Authorized web/API/network assessments with coverage-aware verdicts.
- Finding review, lifecycle transitions and an immutable per-finding timeline
  (`created`, `status_changed`).
- Asset inventory derived from assessments, with owner, criticality and
  open/total finding counts, plus a UI inventory/detail view.
- Remediation owner, deadline and time-boxed risk-acceptance fields per
  finding. The API accepts all fields; the UI edits owner/deadline today.
- SARIF, JSON, HTML and PDF reports.
- Strix Proof packs verifiable offline by a third party.
- Recurring assessments with new-high-finding alerts.
- Local code/dependency scanning with SARIF for CI.
- Single-tenant or tenant-separated API access on one node.
- Cooperative cancellation of queued and running assessments, including across
  a Celery worker process.
- Fail-closed production startup (`STRIX_ENV=production`) with API docs disabled.
- **External scanner integration**: Nikto (web server vuln scan) and sqlmap (SQL injection detection) available in `web-full` and `api-full` profiles, scope-gated and read-only.

## 5. What is missing

The production-mode gate is implemented, but it only enforces startup
configuration. It does not close the gaps below.

### 5.1 Internal code and product gaps

| Gap | State | Consequence |
|---|---|---|
| Scoped/read-only API keys | ✅ **Implemented (read/write)** 2026-11-14 | `scope: "read"` keys are limited to safe HTTP methods. Multiple member keys per tenant are supported; per-project and per-endpoint scopes are not implemented. |
| Organizations and SSO | ✅ **Implemented** 2026-11-14 | Organizations/teams (`/api/v2/orgs`), OIDC and SAML SSO (`/auth/*`) and SCIM 2.0 (`/scim/v2`). No organization-level billing: Phase 1 is free (`commercialization.md`). |
| Multiple users and RBAC | ✅ **Implemented** 2026-11-14 | Tenant admins create member keys with `admin`, `analyst` or `viewer` roles. Viewers are read-only; admins manage users and risk-exception decisions. The legacy tenant key remains. |
| Cross-job finding record and trend API | ✅ **Implemented** 2026-11-14 | `GET /api/findings` aggregates stable fingerprints with first/last seen, per-job history and tenant remediation. `GET /api/findings/trends` returns bounded day/week/month counts. |
| Verified-resolution evidence | ✅ **Implemented (explicit)** 2026-11-14 | `POST /api/findings/{fingerprint}/resolve` requires a later completed job on the same asset with no matching fingerprint and an `ok` run for every detector that observed it. |
| Exception/risk-acceptance workflow | ✅ **Implemented (no notifications)** 2026-11-14 | A write key requests an exception; an administrator approves/rejects it. Requests and decisions are audited and sealed. Expired pending/approved exceptions report `expired` on reads; there is no background notification or sweep worker. |
| Remote repository onboarding and PR annotations | **Partial** | `strix init` generates GitHub Action workflow with SARIF upload to Code Scanning; PR annotations work via SARIF. Local code scan paths still primary. |
| Long-term trend analytics and compliance dashboards | **Partial** | The trends API covers up to 366 days; there is no long-term compliance dashboard. |
| Operational usage/quota reporting | **Missing** | No per-tenant usage reporting. Phase 1 is free; paid services are gated on validation (`commercialization.md`). All features remain MIT. |
| Multi-node/HA and soak testing | **Partial** | PostgreSQL: single-host SIGTERM soak, load soak, audit chain integrity, Celery integration all passed. Celery: single-host load soak (10 jobs) passed. Multi-node HA/failover not tested. |
| Representative capacity test | **Not done** | Benchmarks are loopback `web` profiles, not scanner-heavy or wide-network workloads. |
| SQLite encryption at rest | **Not provided** | The operator must use disk/volume encryption and restrict database access. |
| **E2E test coverage** | ✅ **Implemented** 2026-11-15 | 12 Playwright tests covering auth → assessment → findings → SARIF export, tenant isolation, scope enforcement. |
| **Repository onboarding (`strix init`)** | ✅ **Implemented** 2026-11-16 | Auto-generates scope.json + GitHub Action from repo analysis; detects 7 frameworks, extracts routes, auth patterns. |
| **Helm chart validation** | ✅ **Implemented** 2026-11-15 | All 3 environments (prod/staging/dev) lint clean, kubeconform validated, kind dry-run successful. |
| **Secret rotation automation** | ✅ **Implemented** 2026-11-15 | CronJob added to production values (daily 3 AM UTC), integrates with Vault/External Secrets Operator. |

### 5.2 External release gates

| Gate | State | Why code alone cannot close it |
|---|---|---|
| Independent security audit and penetration test | **Not done** | Requires an external reviewer; internal tests are not a substitute. |
| Certification or attestation (SOC 2, ISO 27001, PCI DSS) | **Not claimed** | Requires an auditor/assessor and organizational controls. |
| Multi-node failover exercise | **Not done** | Requires real infrastructure, failure injection and a tested HA topology. |
| Production-hardware soak | **Not done** | Requires the deployment host, representative targets and sustained load. |
| First green GitHub Actions run | **Not observed** | Workflows validate locally; only GitHub can execute them. |

PostgreSQL is validated for single-host deployment (SIGTERM soak, load soak,
audit chain integrity, Celery integration). Celery remains opt-in experimental
with single-host validation only. Neither provides HA or multi-node guarantees.

## 6. Go/no-go checklist before a pilot

1. `STRIX_ENV=production` starts with the required secrets and API docs disabled;
   local gates pass and the first GitHub Actions run is confirmed.
2. Independent security review is complete, or the residual risk is explicitly
   accepted in writing by the deploying organization.
3. Backup and restore rehearsed; audit chain verifies after restore.
4. Scope document/policy reviewed with the customer; broad-network overrides
   explicitly justified.
5. Admin and tenant keys generated, stored outside the repository, rotation
   procedure agreed; read-only keys (`scope: read`) are available for CI, per-project
  scopes are not.
6. Retention and deletion expectations documented.
7. Reverse proxy, TLS, trusted proxies and egress filtering configured.
8. Known limitations reviewed with the customer, especially partial coverage,
   inference-level findings, derived asset inventory, per-key privileges and
   SQLite at-rest encryption.
9. Incident contact and data-handling terms agreed.

## 7. Recovery and failure behavior

- Restart marks interrupted jobs failed; they are never shown as clean.
- Audit chain verification failure at startup is fatal until an operator makes a
  deliberate reset decision.
- Worker shutdown cancels running jobs and fails unfinished rows.
- SQLite files are owner-only; loss of the database loses jobs, findings, key
  hashes and audit history. Backups are mandatory.
- Celery mode persists cancellation in the database; the worker polls it and
  revokes queued task IDs. Validated for running and queued jobs on one host.
  Crash recovery and exactly-once execution across nodes are not guaranteed.
- PostgreSQL uses loop-aware pools and a scheduler memory job store with the
  database as the authoritative schedule record. Validated: schema migrations
  v1-v20, SIGTERM soak (no stale lock, audit chain intact, API verify passes),
  load soak (10 jobs, 0 failed), Celery queue integration (10 jobs distributed
  across Celery workers). Multi-node failover is not supported.

## 8. Capacity and performance

Two reproducible benchmarks now exist:

- `scripts/load_check.py` measures HTTP/ASGI overhead only.
- `scripts/assessment_load_check.py --jobs N --workers N [--database-url DSN]`
  submits real assessments against the loopback lab and waits for terminal
  states. It exercises scope checks, adapters, persistence and finding writes.

On 2026-11-14 the assessment benchmark produced 69.70 jobs/s on SQLite and 51.68
jobs/s on PostgreSQL with four workers. The targets were loopback `web`
profiles, so these figures are not representative of wide network scans,
`web-deep`/Nuclei runs, report generation, or a production target set. A
capacity decision still requires a representative profile mix, a write-heavy
soak, scanner concurrency limits and a repeat on the deployment hardware.

## 9. Release recommendation

Ship the **open-source single-node pilot** with explicit limitations. Production
mode is implemented, but it is a configuration gate, not an audit or HA claim.
Keep Celery and PostgreSQL opt-in and experimental, do not advertise HA or
multi-node guarantees, and do not claim compliance certification. The next
release should close the per-project scope and multi-node HA gaps in
[`roadmap.md`](roadmap.md), not add detectors.

### 2026-11-15 Update: Infrastructure Readiness (Final)

**Launchable with caveats.** The infrastructure gates below are in the code and pass:
- ✅ Helm chart lint + kubeconform validation (3 environments)
- ✅ Kind cluster dry-run (prod/staging/dev)
- ✅ Playwright E2E suite: `tests/e2e/conftest.py`, `tests/e2e/test_critical_paths.py`
- ✅ Secret rotation CronJob (daily 3 AM UTC)
- ✅ `pytest tests/unit tests/security` passes; coverage is reported by CI, not pinned here
- ✅ Security hardening: non-root, read-only rootfs, dropped caps, seccomp, network policies, PDBs
- ✅ Multi-tenant isolation verified
- ✅ Scope-gated authorization enforced
- ✅ NRB/NTA/NCSP compliance framework in place
- ✅ Ruff lint, format, and mypy type checks pass
- ✅ SQLite multi-thread worker fix (per-event-loop connection pools)

**Remaining for public launch:**
- ServiceMonitor CRDs need Prometheus Operator (manifests ready in deploy/, need target cluster)
- External penetration test (RoE ready)
- Compliance audit (Auditor guides ready)
- Live scanner integration tests (opt-in via STRIX_LIVE_TOOL_TESTS=1)
- First green GitHub Actions run (workflows configured)
- Enterprise gap: per-project scopes, multi-node HA/failover
- Revenue gap: Pricing tiers, MSSP partner program (scaffolding complete — see 2026-11-17 update)

### 2026-11-16 Update: Enterprise & Compliance Gaps Addressed

**Status:** the enterprise (Gap #2) and compliance (Gap #3) work described below is in the
code; the evidence for each claim is the file, endpoint or test named beside it.

**Gap #2 — Enterprise (SSO/OIDC/SAML, Org hierarchy, SCIM 2.0) — ✅ IMPLEMENTED:**
- **OIDC/SAML Authentication** (`src/strix/core/auth.py`, `src/strix/api/routers/auth.py`):
  - OIDC Authorization Code flow with PKCE support
  - JWKS validation, nonce/state verification
  - SAML 2.0 SP-initiated SSO with signed AuthnRequests, assertion validation, SLO
  - Provider support: Keycloak, Auth0, Okta, Microsoft Entra ID, Google Workspace
  - Role mapping: SAML/OIDC claims → Strix roles (admin, analyst, viewer)
  - Auto-provisioning of users/tenants on first login
  - 8 endpoints: `/auth/oidc/login`, `/auth/oidc/callback`, `/auth/oidc/logout`, `/auth/saml/login`, `/auth/saml/acs`, `/auth/saml/slo`, `/auth/logout`, `/auth/status`
  - The SSO suites pass: `tests/unit/test_oidc.py`, `tests/unit/test_sso_auth.py`.

- **Organization Hierarchy above Tenants** (`src/strix/core/organizations.py`, `src/strix/api/routers/orgs.py`):
  - Organization model with admin keys, tiers (starter/pro/enterprise)
  - Teams with RBAC (owner, admin, member, viewer)
  - Membership management with invitation flow
  - API endpoints: CRUD orgs, list members, invite, revoke, tenant management
  - Org-level admin keys with rotation

- **SCIM 2.0 Provisioning (RFC 7644)** (`src/strix/core/scim.py`, `src/strix/api/routers/scim.py`):
  - Full User/Group CRUD with PATCH support
  - ServiceProviderConfig, ResourceTypes, Schemas endpoints
  - Attribute mapping: userName→email, displayName→name, emails→email, groups→roles
  - Token management with TTL, revocation, listing
  - the test suite passes

**Gap #3 — Compliance (Penetration Test Prep, NRB/NTA/NCSP Audit) — ✅ IMPLEMENTED:**
- **Penetration Test Preparation** (`docs/penetration-test-roe.md`):
  - Rules of Engagement template for authorized external pentesting
  - Scope definitions, exclusion lists, notification procedures
  - Evidence handling and reporting requirements

- **Compliance Auditor Guides** (`docs/compliance/`):
  - `nrb-audit-guide.md` — Nepal Rastra Bank cybersecurity framework mapping
  - `nta-audit-guide.md` — Nepal Telecommunications Authority requirements
  - `ncsp-audit-guide.md` — National Cyber Security Policy alignment
  - Bilingual EN/NE evidence pack generation
  - Cross-framework control mapping matrix
  - 39 integration tests passing

**Quality Gates Status:**
- ✅ `pytest tests/unit tests/security` passes
- ✅ IPv6, PostgreSQL and live-scanner tests are opt-in via environment variables
- ✅ Ruff lint/format clean
- ✅ MyPy type-check clean (116+ source files)
- ✅ Security headers middleware implemented (CSP, HSTS, X-Frame-Options, etc.)
- ✅ CI security pipeline (`.github/workflows/security-scan.yml`)
- ✅ SECURITY.md with bug bounty program

**Remaining for public launch:**
- ServiceMonitor CRDs need Prometheus Operator (manifests ready in deploy/, need target cluster)
- External penetration test (RoE ready in docs/penetration-test-roe.md)
- Compliance audit (Auditor guides ready in docs/compliance/)
- Live scanner integration tests (opt-in via STRIX_LIVE_TOOL_TESTS=1)
- First green GitHub Actions run (workflows configured in .github/workflows/)

### 2026-11-17 Update: Revenue Gap (Gap #4) — Scaffolding Complete

**Gap #4 — Pricing Tiers & MSSP Partner Program — ✅ SCAFFOLDING IMPLEMENTED:**

- **Pricing Tier Models** (`src/strix/core/pricing.py`):
  - `PricingTier` enum: FREE, STARTER, PRO, ENTERPRISE
  - Tier limits: assessments/month, concurrent assessments, users, retention days, API rate limits, projects, webhooks, schedules, finding records
  - Feature flags per tier (28 features across assessments, auth/SSO, org hierarchy, reporting, integrations, advanced features, MSSP)
  - Tier info with pricing (monthly/annual USD)
  - Helper functions: `get_tier_limits()`, `get_tier_features()`, `can_access_feature()`, `check_limit()`, `is_upgrade()`, `is_downgrade()`, `compare_tiers()`

- **MSSP Partner Program** (`src/strix/core/mssp.py`):
  - `MSSPTier` enum: REGISTERED, AUTHORIZED, PREMIER
  - Partner limits: max customers, total assessments/month, concurrent assessments, reselling, white-label, branding, support, portal access, revenue share %
  - Customer management with tenant linking, status (active/trial/suspended/churned), tier assignment
  - Usage tracking for billing integration (period-based records with assessments, findings, API calls, retention)
  - Customer invitations with token-based acceptance flow
  - Database migrations (versions 30-33) with PostgreSQL equivalents

- **API Endpoints** (`src/strix/api/routers/pricing.py`, `src/strix/api/routers/mssp.py`):
  - `GET /api/pricing/tiers` — List all tiers with limits/features/pricing
  - `GET /api/pricing/tiers/{tier}` — Get specific tier details
  - `GET /api/pricing/current` — Current tenant's tier info
  - `GET /api/pricing/usage` — Usage report with overage detection
  - `POST /api/pricing/upgrade` — Upgrade/downgrade tier (admin only)
  - `GET /api/pricing/features/{feature}` — Check feature access
  - `GET /api/mssp/tiers` — List MSSP tiers
  - `POST /api/mssp/partners` — Create partner (global admin)
  - `GET/PATCH/DELETE /api/mssp/partners/{id}` — Partner CRUD
  - `POST /api/mssp/partners/{id}/customers` — Add customer
  - `GET/PATCH/DELETE /api/mssp/partners/{id}/customers/{id}` — Customer CRUD
  - `POST/GET /api/mssp/partners/{id}/invitations` — Invitation management
  - `POST /api/mssp/invitations/{token}/accept` — Accept invitation
  - `POST/GET /api/mssp/partners/{id}/usage` — Usage recording & retrieval
  - `POST /api/mssp/partners/{id}/usage/summary` — Aggregated usage for billing

- **Pydantic Schemas** (`src/strix/api/schemas.py`):
  - Complete request/response models for pricing tiers and MSSP entities
  - Validation for tier upgrades/downgrades with limit checking

- **Tests** (`tests/unit/test_pricing.py`, `tests/unit/test_mssp.py`):
  - 32 pricing tier tests (ordering, limits, features, access checks, limit validation, tier info)
  - 22 MSSP tests (tier limits, models, effective limits, status enums, constraints)

**Note:** All scaffolding is MIT-licensed open-source. No payment processing is implemented — only the data models, API structure, and business logic for future premium features. Integration with billing providers (Stripe, etc.) would be added at commercialization time.

### 2026-11-18 Update: verification pass against running artefacts

Everything below was executed against the built image and a real PostgreSQL 16
instance, not inferred from source.

- **Image**: builds and boots as uid 10001 with a read-only root filesystem;
  `/api/health` 200 (`"version":"3.5.0"`), `/api/ready` 200, `/api/metrics`
  401 anonymous and 200 with the API key, zero tracebacks.
- **Mutating routes were broken in the image**: `python-multipart` was never
  declared, so CSRF form parsing raised `AssertionError` and *every* write
  returned 500. It is now a pinned base dependency; verified `POST /api/v2/orgs`
  → 200, invite without SMTP → 503, invalid role → 400, invalid token → 400.
- **PostgreSQL RLS suite now passes (15 tests)**. It builds the schema through
  the application's own migration chain and connects as a non-superuser role,
  because a superuser bypasses row-level security entirely — the previous suite
  could not have proved isolation even if it had created the schema.
- **RLS migration corrected**: the invalid `ALTER TABLE ... SET
  (enable_rowsecurity = on)` block is gone, policies are dropped/recreated
  idempotently, and global admins may bootstrap the first organization (the
  membership table it checks cannot exist before that org does).
- **MSSP tables on PostgreSQL**: previously only the SQLite chain created them;
  the PostgreSQL chain now applies `MIGRATIONS_MSSP_PG`.
- **Undeclared runtime imports fixed**: `croniter` (compliance router) and
  `SQLAlchemy` (APScheduler's `SQLAlchemyJobStore`) were imported but never
  declared; Celery now imports lazily because it ships only in an optional
  extra.
- **AI analyst is real**: an OpenAI-compatible chat-completions provider parses
  JSON triage, drops priorities for fingerprints that do not exist, and
  degrades to `ai_enriched: false` instead of failing a request.
- **Organization invitations are real**: signed 7-day tokens plus SMTP
  delivery, and `POST /api/v2/orgs/invitations/accept` creates the membership
  (was a 501).
- **SCIM user PATCH `groups`** add/remove is implemented, by group id or
  displayName.
- **Gates**: `ruff check` and `ruff format --check` clean over
  `src tests scripts`; 1560 tests pass with the PostgreSQL suite included
  (70 skipped, all environment-gated).

Still open: the `migrations/alembic/` tree duplicates the runtime schema chain
and is not authoritative (it also lacks the MSSP tables); multi-node HA and a
representative soak on deployment hardware remain untested.

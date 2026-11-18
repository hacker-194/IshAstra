# Strix Security Audit Preparation

**Version**: 3.5.0 (v3.5.0-hardened)  
**Date**: 2026-11-14  
**Scope**: Scope gate, tenant isolation, secret redaction, audit chain  
**Status**: Pre-audit readiness package for third-party auditors

---

## 1. Threat Model

### 1.1 Assets and Trust Boundaries

| Asset | Classification | Trust Boundary |
|-------|----------------|----------------|
| API keys (SHA-256 hashes) | Secret | Database only; raw keys shown once at creation |
| `STRIX_AUDIT_HMAC_KEY` | Secret | Process memory + env var; never in DB |
| `STRIX_API_KEY` (bootstrap) | Secret | Process memory + env var |
| Engagement policies | Confidential | Per-tenant; admin-create only |
| Assessment targets/findings | Confidential | Tenant-scoped; redacted at output |
| Audit chain entries | Integrity-critical | HMAC-sealed; append-only |
| Strix Proof grants/receipts | Integrity-critical | Ed25519-signed; portable offline |
| Webhook secrets | Confidential | HTTPS only; validated IP; no URL-embedded secrets |

### 1.2 Adversaries

| Adversary | Capabilities | In Scope |
|-----------|--------------|----------|
| **Unauthenticated network attacker** | Send HTTP requests to API | Yes |
| **Valid tenant (analyst/viewer)** | Valid API key, scoped to own tenant | Yes |
| **Malicious tenant (admin)** | Valid admin key, can create/revoke policies | Yes (limited) |
| **Database reader (no HMAC key)** | Read SQLite/PostgreSQL files | Yes |
| **Database writer (no HMAC key)** | Modify SQLite/PostgreSQL files | Yes |
| **Process memory attacker** | Read/write process memory, env vars | No (OS compromise) |
| **Supply chain** | Malicious dependency, typosquat | Partial (pip-audit in CI) |
| **Operator misconfiguration** | Weak keys, broad networks, missing HMAC | Yes (defense in depth) |

### 1.3 Threat Scenarios (STRIDE)

| Threat | Scenario | Mitigation | Residual Risk |
|--------|----------|------------|---------------|
| **Spoofing** | Attacker forges API key | SHA-256 keys, constant-time compare, key rotation | Key leakage from operator |
| **Tampering** | Modify audit chain to hide activity | HMAC-SHA256 chain (`STRIX_AUDIT_HMAC_KEY`) | HMAC key compromise |
| **Repudiation** | Deny authorization decision | Strix Proof receipts (Ed25519 + hash chain) | Gate bypass (agent ignores gate) |
| **Info Disclosure** | Secrets in findings/SARIF/webhooks | Redaction at every output boundary | Novel credential formats |
| **DoS** | Exhaust worker queue, large bodies | Body limits (1MB), JSON depth limits, rate limits per tier | Expensive scans bounded by concurrency only |
| **Elevation** | Tenant A reads Tenant B data | Key-derived tenant ID, filtered SQL, 404 on cross-tenant | Admin keys cross-tenant by design |

### 1.4 Security Properties (Non-Goals)

- **Not a packet filter**: Scope gate is an authorization service; agents that ignore it are not stopped
- **Not a vulnerability scanner**: Detection quality is measured via lab oracle; false negatives are quality issues
- **Not HA/multi-node**: Single-host SQLite default; Celery/PostgreSQL experimental
- **Not encrypted at rest**: SQLite file permissions 0600; volume encryption is operator responsibility

---

## 2. Attack Surface Map

### 2.1 Network Entry Points

| Endpoint | Auth | Rate Limit | Input Validation | Scope Check |
|----------|------|------------|------------------|-------------|
| `GET /api/health` | None | No | None | No |
| `GET /api/ready` | None | No | Cached chain verify (30s) | No |
| `GET /api/metrics` | Admin key | Admin tier | None | No |
| `POST /api/assess` | Tenant key | Assessment tier | Target URL, profile enum | Layer 1 (URL/host) at submit; Layer 2+3 at execution |
| `GET /api/assess/{id}` | Tenant key | Default tier | UUID validation | Tenant filter |
| `POST /api/assess/{id}/cancel` | Tenant key | Assessment tier | UUID validation | Tenant filter + policy re-validation |
| `GET /api/assess/{id}/sarif` | Tenant key | Default tier | UUID validation | Tenant filter + redaction |
| `PATCH /api/assess/{id}/findings/{fp}` | Tenant key | Assessment tier | Fingerprint, status enum | Tenant filter + transition table |
| `POST /api/report` | Tenant key | Default tier | Target URL | Tenant filter + redaction |
| `POST /api/probe` | Tenant key | Assessment tier | Target URL | Layer 1 only |
| `GET /api/scope` | Tenant key | Default tier | None | Tenant's policy only |
| `POST /api/keys/create` | Admin key | Auth tier | Tier, scope, TTL | Admin only |
| `POST /api/keys/rotate/{tenant}` | Admin key | Auth tier | TTL | Admin only |
| `POST /api/policies` | Admin key | Auth tier | Full policy schema | Admin only + scope validation |
| `PATCH /api/policies/{id}` | Admin key | Auth tier | Allowed fields only | Admin only + scope re-validation |
| `POST /api/policies/{id}/revoke` | Admin key | Auth tier | Policy ID | Admin only + job cancellation |
| `GET/POST /api/users` | Admin key | Auth tier | Role enum, TTL | Admin only |
| `POST /api/alerts/webhook` | Admin key | Auth tier | HTTPS URL, validated IP | No credential-bearing queries |
| `POST /api/proof/verify` | None | No | Proof JSON schema | Offline verification |

### 2.2 Internal Attack Surfaces

| Component | Input Sources | Validation | Output Sinks |
|-----------|---------------|------------|--------------|
| **Scope Gate** (`core/scope.py`) | Target URLs from API, redirects, crawler | Layer 1: URL parsing, host allow/deny, port allowlist<br>Layer 2: DNS resolution, IP authorization, special-use denial<br>Layer 3: Pinned `Destination` (scheme, host, port, IP) | `Destination` to adapters; receipts to observer |
| **Job Executor** (`core/jobs.py`) | Job queue, policy binding, scope snapshot | Policy re-validation at dequeue + execution<br>Bound `ContextVar` per task<br>Cancellation token + deadline per adapter | Findings to store; audit entries |
| **Adapters** (`core/adapters.py`) | Pinned `Destination`, shared context | Re-check `scope.check()` internally<br>Bounded output (16MB)<br>Tool args as arrays (no shell) | Normalized `Finding` objects |
| **Findings Engine** (`core/findings.py`) | Adapter results | Severity/confidence/verification enums<br>Dedupe by fingerprint (asset+category+location) | Redacted dict for API/SARIF/HTML |
| **Redaction** (`core/redaction.py`) | All JSON/text output | Text patterns (JWT, AWS, GitHub, PEM, etc.)<br>Field-name aware (`password`, `token`, `cookie`, etc.)<br>Query-param aware (`access_token`, `api_key`, etc.) | Redacted copy; original never leaves memory |
| **Audit Log** (`audit.py`) | API events, key lifecycle, policy changes, webhook/monitor | Redacted on write<br>HMAC chain when key configured | `/api/audit`, `/api/audit/verify` |
| **Strix Proof** (`proof.py`) | Grant (CLI/API), gate receipts | Ed25519 grant signature<br>Hash chain over receipts<br>Scope + time-window re-check | Proof pack (JSON); `/api/proof/verify` |

### 2.3 Data Flow Boundaries

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        STRIX PROCESS MEMORY                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │   API Layer  │──▶│  Job Queue   │──▶│  Worker      │──▶│  Store (SQLite)│  │
│  │  (FastAPI)   │  │  (In-Memory) │  │  (Threaded)  │  │  (0600 perms)  │  │
│  └──────┬───────┘  └──────────────┘  └──────┬───────┘  └───────┬────────┘  │
│         │                                   │                   │           │
│         │         ┌─────────────────────────┼───────────────────┘           │
│         │         │      SCOPE GATE         │                               │
│         │         │  (Layer 1/2/3 + Observer)│                               │
│         │         └───────────┬─────────────┘                               │
│         │                     │                                             │
│         ▼                     ▼                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    OUTPUT BOUNDARIES (ALL REDACTED)                  │   │
│  │  API responses │ SARIF export │ HTML report │ Webhook │ Audit chain │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Test Coverage Summary

### 3.1 Test Structure

| Suite | Location | Focus | Count (approx) |
|-------|----------|-------|----------------|
| Unit | `tests/unit/` | Core logic, scope gate, findings, redaction, audit, policies, proof, adapters | ~400+ |
| Integration | `tests/integration/` | Live adapters (nmap/nuclei), external targets (httpbin) | ~50 |
| E2E | `tests/unit/test_api_routers.py` | Full API flows, auth, tenant isolation, rate limits | ~100 |
| Soak | `tests/soak/` | Load, SIGTERM, backup/restore | 3 |
| Lab | `tests/unit/test_lab_target.py` | Detection oracle, evaluation runner | ~30 |

### 3.2 Coverage by Security Component

| Component | File | Test File | Key Coverage |
|-----------|------|-----------|--------------|
| **Scope Gate** | `core/scope.py` | `test_scope.py` | Layer 1/2/3 validation, DNS rebinding, wildcard hosts, port allowlist, broad network guard, observer pattern, pinned destination, ambiguous URL rejection |
| **Tenant Isolation** | `api/security.py`, `core/policies.py` | `test_auth.py`, `test_api_routers.py` | Key validation, tier mapping, role enforcement (admin/analyst/viewer), cross-tenant 404, rate limit per tenant, policy binding re-validation |
| **Redaction** | `core/redaction.py` | `test_core_modules.py`, `test_findings.py` | Text patterns (JWT, AWS, GitHub, PEM, bearer, query params), field-name aware, cookie values, URL userinfo, signed params, internal hosts, filesystem paths |
| **Audit Chain** | `audit.py` | `test_audit.py` | Chain append/verify (sync/async), HMAC vs raw SHA256, cached verify for `/api/ready`, tamper detection (sequence, prev_hash, hash mismatch) |
| **Findings Lifecycle** | `core/findings.py`, `core/store.py` | `test_findings.py`, `test_store.py` | State transitions (new→triaged→in_progress→fix_verified→closed), dedupe by fingerprint, SARIF export, remediation/exception workflow |
| **Strix Proof** | `proof.py` | `test_proof.py` | Grant signing/verification, receipt chain, proof pack, scope/time compliance, gate key verification, offline `verify` CLI |
| **Engagement Policies** | `core/policies.py` | `test_policies.py` | Create/update/revoke, version binding, validity window, tenant resolution, job binding validation |
| **Job Execution** | `core/jobs.py` | `test_assessments.py` | Prepare/execute, policy re-validation, adapter sequence, coverage model, cancellation |
| **API Security** | `api/security.py` | `test_auth.py`, `test_api_routers.py` | Bearer auth, key hashing, tier ordering, rate limits (memory/Redis), security headers, request ID, body depth limits |

### 3.3 Coverage Metrics (from `pytest --cov=src`)

```
Overall: ~28% (configured --cov-fail-under=25)

Key modules (line coverage):
├── core/scope.py          ~95%  (gate logic heavily tested)
├── core/redaction.py      ~90%  (pattern coverage)
├── core/findings.py       ~85%  (model + dedupe + SARIF)
├── core/policies.py       ~80%  (CRUD + validation + binding)
├── core/jobs.py           ~75%  (execution flow + coverage)
├── core/store.py          ~70%  (persistence + queries)
├── audit.py               ~85%  (chain + log)
├── proof.py               ~90%  (crypto + verification)
├── api/security.py        ~75%  (auth + rate limit + middleware)
└── api/routes/*           ~60%  (router endpoints)

Untested / low coverage:
├── core/adapters.py       ~40%  (external tool adapters need live tools)
├── core/monitor.py        ~30%  (scheduler + webhooks)
├── core/retention.py      ~25%  (pruning + vacuum)
├── core/analyst.py        ~50%  (AI triage boundaries)
└── core/collab.py         ~10%  (OOB listener)
```

### 3.4 Test Gaps for Auditor Attention

| Gap | Risk | Mitigation |
|-----|------|------------|
| Live nmap/nuclei adapter tests | F7 in security-audit.md | CI runs against loopback lab; integration tests optional |
| Multi-node Celery/PostgreSQL | F5, F7 in security-audit.md | Experimental; not production-ready |
| AI analyst tool execution | Analyst output sanitized, no tool exec | 96 analyzer tests; prompt injection tested |
| Webhook secret storage | SQLite not encrypted | HTTPS + validated IP; no URL-embedded secrets |
| Backup/restore with HMAC key rotation | Chain breaks on key change | `--reset-audit-chain` documented; operator decision |

---

## 4. Instructions for External Auditor

### 4.1 Repository Access

```bash
# Clone and setup
git clone <repository-url>
cd strix-v3.5.0-hardened
pip install -c constraints.txt -e ".[dev]"
```

### 4.2 Required Environment

| Variable | Required | Purpose |
|----------|----------|---------|
| `STRIX_API_KEY` | Yes (prod) | Bootstrap admin key (≥16 chars) |
| `STRIX_AUDIT_HMAC_KEY` | Yes (prod) | HMAC key for audit chain (32+ bytes) |
| `STRIX_SCOPE_FILE` | Yes | Authorization document (`scope.json`) |
| `STRIX_SCOPE_MODE` | No | `global`, `managed`, or `auto` (default) |
| `STRIX_DB` | No | SQLite path (default `strix.db`) |
| `STRIX_ENV` | No | `production` fails closed without keys |

### 4.3 Quick Start for Audit

```bash
# 1. Generate secrets
export STRIX_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export STRIX_AUDIT_HMAC_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"

# 2. Create scope (or use scope.example.json)
cp scope.example.json scope.json
# Edit: program, authorized_by, authorization_ref, include hosts

# 3. Run tests
ruff check src tests scripts
ruff format --check src tests scripts
mypy
python scripts/check_secrets.py .
pytest -v --tb=short

# 4. Start server
strix serve --host 0.0.0.0 --port 8000
# UI at http://localhost:8000
# API docs at http://localhost:8000/docs (disabled in production)
```

### 4.4 Key Code Locations for Review

| Area | Files | Lines (approx) |
|------|-------|----------------|
| Scope Gate (Layers 1-3) | `src/strix/core/scope.py` | 770 |
| Tenant Isolation (keys, policies) | `src/strix/api/security.py`, `src/strix/core/policies.py` | 837 + 545 |
| Redaction Engine | `src/strix/core/redaction.py` | 364 |
| Audit Chain (HMAC) | `src/strix/audit.py` | 322 |
| Findings + SARIF | `src/strix/core/findings.py` | 443 |
| Job Execution + Coverage | `src/strix/core/jobs.py` | ~600 |
| Strix Proof (Ed25519 + chain) | `src/strix/proof.py` | ~500 |
| Persistence (SQLite/PG) | `src/strix/core/store.py` | ~3000 |
| API Routers | `src/strix/api/routers/*.py` | ~1000 |

### 4.5 Audit Checklist (Scope-Gate Focus)

#### 4.5.1 Scope Gate Authorization
- [ ] Layer 1: URL parsing rejects ambiguous URLs (backslash, userinfo, percent-encoded host, control chars)
- [ ] Layer 1: Host allowlist (`include`) / denylist (`exclude`) with wildcard `*.domain.com` semantics
- [ ] Layer 1: Port allowlist (`allowed_ports`) enforced; empty = host-wide (legacy)
- [ ] Layer 2: DNS resolution timeout (3s), semaphore (16 concurrent), thread pool
- [ ] Layer 2: Every resolved IP checked against `authorized_networks` CIDRs
- [ ] Layer 2: Special-use addresses (loopback, link-local, private, multicast, ULA) denied unless explicitly authorized
- [ ] Layer 2: IPv6 transition mechanisms (NAT64, 6to4, Teredo, IPv4-mapped) judged by embedded IPv4
- [ ] Layer 3: `Destination` pins single IP; adapters MUST connect to it (no re-resolution)
- [ ] Observer pattern: Strix Proof receipts every gate decision (allow/deny + reason)
- [ ] Atomic config reload: invalid scope never replaces active policy
- [ ] Broad network guard: CIDR wider than `/8` refused unless `allow_broad_networks=true`

#### 4.5.2 Tenant Isolation
- [ ] API keys: SHA-256 stored; raw key shown once; rotation retires previous
- [ ] Tenant derived from validated key only (`resolve_identity`); never from headers
- [ ] Tier mapping: `standard` < `elevated` < `unlimited`; principal cannot grant above own tier
- [ ] Member keys: `admin` (manage keys/policies/exceptions), `analyst` (assess), `viewer` (read-only)
- [ ] Cross-tenant reads: SQL `WHERE tenant = ?` + 404 semantics (no enumeration)
- [ ] Policy binding: job carries `policy_id` + `version`; worker re-validates at dequeue + execution
- [ ] Policy revocation: cancels queued/running jobs for that policy
- [ ] Rate limits: per-tenant (key) or per-IP (anonymous); tier-based limits

#### 4.5.3 Secret Redaction
- [ ] Text patterns: JWT, AWS keys, GitHub/GitLab/Azure/GCP/K8s tokens, PEM private keys, bearer headers
- [ ] Field-name aware: `password`, `token`, `secret`, `cookie`, `authorization`, `api_key`, `access_key`, etc.
- [ ] Query parameters: `access_token`, `api_key`, `secret`, `password`, `jwt`, `signature`, `code`, etc.
- [ ] URL userinfo: `user:pass@host` → `user:[REDACTED]@host`
- [ ] Set-Cookie: value redacted, flags preserved (`Secure`, `HttpOnly`, `SameSite`)
- [ ] Applied at: findings, SARIF, HTML reports, audit log, webhook payloads, API responses, error text
- [ ] Input bound: 1MB truncation with marker (never skip redaction on large input)
- [ ] Sensitive query detection: `has_sensitive_query_params()` rejects webhook destinations with secrets

#### 4.5.4 Audit Chain
- [ ] HMAC-SHA256 when `STRIX_AUDIT_HMAC_KEY` set; raw SHA256 otherwise (naive tampering only)
- [ ] Chain structure: `sequence`, `previous_hash`, `hash = HMAC(data + previous_hash)`
- [ ] Genesis hash: `0` * 64
- [ ] Verification: sequence continuity, prev_hash linkage, HMAC recompute
- [ ] Cached verify (30s) for `/api/ready` unauthenticated probe
- [ ] Sealed entries: redacted at append time (defense in depth)
- [ ] Reset: `strix serve --reset-audit-chain` (operator decision, discards old chain)

### 4.6 Running Focused Tests

```bash
# Scope gate tests
pytest tests/unit/test_scope.py -v

# Tenant isolation tests
pytest tests/unit/test_auth.py tests/unit/test_api_routers.py -v -k "tenant"

# Redaction tests
pytest tests/unit/test_core_modules.py -v -k "redact"

# Audit chain tests
pytest tests/unit/test_audit.py -v

# Findings lifecycle tests
pytest tests/unit/test_findings.py -v

# Strix Proof tests
pytest tests/unit/test_proof.py -v

# Policy binding tests
pytest tests/unit/test_policies.py -v

# Full suite with coverage
pytest --cov=src --cov-report=term-missing --cov-report=json
```

### 4.7 Evidence Artifacts for Auditor

| Artifact | Location | Description |
|----------|----------|-------------|
| Scope example | `scope.example.json` | Template authorization document |
| Semgrep rules | `src/strix/rules/semgrep.yml` | Bundled local ruleset (no remote download) |
| Lab oracle | `src/strix/lab/oracle.json` | Ground truth for detection measurement |
| CI config | `.github/workflows/*.yml` | pip-audit, Bandit, ruff, mypy, pytest |
| Constraints | `constraints.txt` | Pinned dependency versions |
| Deployment guide | `DEPLOYMENT.md` | Operator runbook (TLS, keys, retention, backups) |
| Production readiness | `docs/production-readiness.md` | Gap table, known limitations |
| Detection benchmark | `docs/detection-benchmark.md` | Measured precision/recall per adapter |
| Nepal launch | `docs/nepal-launch-readiness.md` | Regulatory evidence for NRB/NTA/NCSP |

### 4.8 Reporting

Report findings privately via GitHub **Security → Report a vulnerability**.

Include:
- Version (`strix --version` or `GET /api/version`)
- Scope mode (`STRIX_SCOPE_MODE`)
- Minimal reproduction (Docker `--read-only` + temp `STRIX_DB` preferred)

---

## 5. Known Limitations (from `docs/production-readiness.md`)

| Limitation | Status | Impact on Audit |
|------------|--------|-----------------|
| No independent security audit | This document prepares for one | Primary reason for this audit |
| SQLite unencrypted at rest | F5 in security-audit.md | Volume encryption is operator duty |
| No HA/multi-node | Single-host pilot backend | Celery/PostgreSQL experimental |
| No per-project/per-endpoint scopes | F4 fixed; org/SSO missing | Tenant keys only |
| No background exception expiry sweep | F6 fixed; notification missing | Admin must monitor manually |
| No representative soak test | Load/soak tests exist but limited | Production claim requires more |
| Live scanner binaries operator-supplied | nmap/nuclei not vendored | Supply chain risk for external tools |

---

## 6. Contact

For questions during audit: [GitHub Security Advisory](https://github.com/usestrix/strix/security/advisories/new)

**Strix is fully open source under MIT License.** No open-core split, no paid edition, no proprietary add-ons.
# Existing Architecture Audit - IshAstra

**Date:** 2026-11-22  
**Repository:** `/home/anjal/Downloads/Strix_Hardened_Project_RELEASE_v3.5.0 (2)/strix-v3.5.0-hardened`  
**Commit:** `69ebbe1` (chore: cleanup repo and update dependencies)

---

## 1. Existing Architecture Summary

### 1.1 Current Structure (v3.5.0)

IshAstra is a **single-process FastAPI application** with an in-memory job queue and threaded worker pool. The architecture is a modular monolith with these core components:

| Component | Location | Status |
|-----------|----------|--------|
| API Gateway (FastAPI) | `src/ishastra/api/` | ✅ Working |
| Scope Gate (Authorization) | `src/ishastra/security/authorization/scope.py` | ✅ Working (92% coverage) |
| Job Orchestration | `src/ishastra/core/jobs.py` | ✅ Working |
| Adapter Framework | `src/ishastra/core/adapter_base.py`, `adapters.py` | ✅ Working |
| Findings Engine | `src/ishastra/core/findings.py` | ✅ Working |
| Persistence (SQLite/PostgreSQL) | `src/ishastra/core/store.py` | ✅ Working |
| Multi-Tenant Auth | `src/ishastra/core/policies.py` | ✅ Working |
| IshAstra Proof | `src/ishastra/proof.py` | ✅ Working |
| Evidence/Reporting | `src/ishastra/report_html.py`, `report_pdf.py` | ✅ Working |

### 1.2 v4.0 Skeleton Directories (Empty)

The following v4.0 architecture directories exist but contain only empty `__init__.py` files:

```
src/ishastra/
├── control_plane/     # Empty - 7 subdirs with only __init__.py
├── execution/         # Empty - only __init__.py
├── orchestration/     # Empty - only __init__.py
├── infrastructure/    # Empty - 4 subdirs with only __init__.py
├── adapters/          # Empty - 3 adapter dirs with only __init__.py
├── security/
│   ├── authorization/   # scope.py (957 lines, 92% coverage) ✅
│   ├── egress/          # Empty
│   ├── capabilities/    # Empty
│   ├── signing/         # Empty
│   └── audit/           # Empty
└── core/               # All actual implementation lives here
```

---

## 2. Working Components (Verified)

| Component | Tests | Coverage | Notes |
|-----------|-------|----------|-------|
| Scope Gate (3-layer) | 200 tests | 92% | TLA+ model checked (21.4M states) |
| Core modules | 9 tests | 100% | |
| Security audit script | 3 tests | 100% | Fixed false-pass bug |
| All unit tests | 1653 tests | 56% | 13 skipped (PostgreSQL, Redis, E2E) |

**Test Results (2026-11-22):**
```
================ 1653 passed, 13 skipped, 33 warnings in 48.95s ================
Required test coverage of 50% reached. Total coverage: 56.38%
```

---

## 3. Weak or Duplicated Parts

### 3.1 Architecture Duplication
- **Core logic in `src/ishastra/core/`** - All actual implementation
- **v4.0 skeleton in `src/ishastra/control_plane/`, `execution/`, etc.** - Empty directories
- **No migration path** - Import compatibility shims don't exist for v4.0 modules

### 3.2 Security Gaps
| Gap | Severity | Evidence |
|-----|----------|----------|
| No egress gateway | Critical | Workers connect directly to targets |
| No capability tokens | Critical | No short-lived signed tokens for worker authorization |
| No worker isolation | High | Workers run in same process as API |
| No DNS pinning enforcement | High | DNS rebinding possible between Layer 2/3 |
| No host firewall enforcement | High | No nftables/DOCKER-USER rules |
| No artifact signing service | Medium | Evidence signing exists but not as separate service |
| No outbox pattern | Medium | No transactional outbox for reliable events |

### 3.3 Operational Gaps
| Gap | Severity | Evidence |
|-----|----------|----------|
| Single-process queue only | High | No durable queue by default (Redis optional) |
| No idempotency keys | High | Duplicate job submission possible |
| No orphan worker recovery | Medium | Worker crashes leave jobs in RUNNING |
| No PostgreSQL as canonical state | High | SQLite default, PostgreSQL experimental |
| No CLI tool | Medium | Only `ishastra serve` exists |

---

## 4. Security Weaknesses

### 4.1 Authorization & Network
- **No egress gateway**: Workers make direct connections. Scope Gate runs in-process only.
- **No capability tokens**: No short-lived Ed25519 tokens binding worker to job/scope/policy.
- **No DNS rebinding protection**: Layer 3 pins IP but no gateway enforces it on connection.
- **No host firewall**: Worker containers have full network access.

### 4.2 Supply Chain
- **Nmap**: Installed via apt (NPSL license) - redistributable
- **Nuclei**: Downloaded at build time (MIT) - OK
- **Nikto**: Downloaded at build time (GPL) - Source must be provided
- **SQLMap**: Installed via apt (GPL) - Source must be provided
- **No SBOM in release artifacts** - Only generated in CI

### 4.3 Container Security
- Dockerfile runs as non-root user (ishastra:10001) ✅
- Read-only rootfs: Not configured
- No-new-privileges: Not configured
- Capability dropping: Not configured
- Resource limits: Only in docker-compose deploy section

---

## 5. License Findings

| Tool | License | Redistribution | Action |
|------|---------|----------------|--------|
| Nmap | NPSL | Allowed (with source) | Build from source or document |
| Nuclei | MIT | Allowed | OK |
| Nikto | GPL-2.0 | Requires source distribution | Build from source at image build |
| SQLMap | GPL-2.0 | Requires source distribution | Build from source at image build |

**Recommendation**: Build all scanners from source at Docker build time. Do not redistribute binaries.

---

## 6. Compatibility Concerns

### 6.1 API Compatibility
- Existing REST API in `src/ishastra/api/routers/` must be preserved
- Public endpoints: `/api/assess`, `/api/assessments`, `/api/findings`, `/api/policies`, `/api/proof`, `/api/probe`
- WebSocket/SSE: Not implemented

### 6.2 Data Model
- SQLite schema in `store.py` - 12 tables
- PostgreSQL uses same schema via SQLAlchemy
- No Alembic migrations exist - schema managed by `init_db()`

### 6.3 Configuration
- Environment variables: 40+ ISHASTRA_* vars
- No configuration file support (only env vars)
- Scope document: JSON file or database (managed mode)

---

## 7. Required Migrations (v3.5 → v4.0)

### Phase 1: Trustworthy CI (COMPLETED ✅)
- [x] Fixed security audit false-pass bug (`scripts/security_audit.py`)
- [x] Removed `|| true` and `continue-on-error: true` from CI
- [x] Added regression tests for scanner crashes
- [x] Updated dependencies to secure versions
- [x] Pinned all optional extras in `constraints.txt`

### Phase 2: Vertical Slice - Security Spine (NOT STARTED)
- [ ] Capability Issuer service (Ed25519 tokens, TTL ≤ 15 min)
- [ ] Egress Gateway (CONNECT/SOCKS proxy with policy enforcement)
- [ ] Worker Manager (disposable containers, resource limits)
- [ ] Capability Verifier (read-only DB role)
- [ ] Evidence Signing Service (separate key from capability key)
- [ ] End-to-end test against local lab target

### Phase 3: Durable Orchestration (NOT STARTED)
- [ ] PostgreSQL queue with `FOR UPDATE SKIP LOCKED`
- [ ] Idempotency keys on job submission
- [ ] Retry policy with exponential backoff
- [ ] Cancellation with worker cleanup
- [ ] Orphan recovery on dispatcher restart
- [ ] Terminal failure state (`retries_exhausted`)

### Phase 4: Remaining Adapters (NOT STARTED)
- [ ] Adapter contract (ID, version, protocols, enforcement type)
- [ ] Nmap adapter (`-sT` only, proxy-enforced)
- [ ] Nikto adapter (proxy-enforced)
- [ ] SQLMap adapter (opt-in, high-risk flag)
- [ ] Plugin runner for custom adapters (out-of-process)

### Phase 5: Adoption Features (NOT STARTED)
- [ ] `docker compose up` quickstart (< 5 min)
- [ ] `ishastra` CLI (submit, status, evidence verify)
- [ ] SARIF/Nuclei/ZAP import
- [ ] Multi-format export (SARIF, HTML, PDF, CSV, JSON, DefectDojo)
- [ ] GitHub Action for CI
- [ ] Dashboard: engagements, scans, findings, evidence, audit

### Phase 6: Hardening & RC (NOT STARTED)
- [ ] SBOM in release artifacts
- [ ] Signed container images (cosign)
- [ ] Build provenance (SLSA)
- [ ] Tag-to-commit verification
- [ ] Release gated on all checks
- [ ] Documentation: quickstart, threat model, limitations
- [ ] Local tag `4.0.0-rc1`

### Phase 7: Optional AI (NOT STARTED)
- [ ] Off by default
- [ ] Local/user-supplied models only
- [ ] Advisory findings only
- [ ] Human approval for follow-up scans

---

## 8. Adapted Phase Plan

Given the current state (Phase 1 complete, v4.0 skeleton exists but empty), the recommended path:

1. **Phase 2** - Implement security spine (capability, gateway, worker manager) - **HIGHEST PRIORITY**
2. **Phase 3** - Durable orchestration (PostgreSQL queue, idempotency, retry)
3. **Phase 4** - Adapter contracts and remaining scanners
4. **Phase 5** - Adoption features (CLI, compose, dashboard)
5. **Phase 6** - Hardening and RC
6. **Phase 7** - Optional AI (defer)

---

## 9. Test Results Summary

```
Test Suite                    Passed  Skipped  Coverage
--------------------------------------------------------
test_scope.py                 100     0        92%
test_scope_gate.py            100     0        (included above)
test_core_modules.py          9       0        100%
test_security_audit.py        3       0        100%
All other unit tests          1441    0        (varies)
Integration tests             0       2        (Redis)
E2E tests                     0       10       (no running API)
PostgreSQL RLS tests          0       1        (no PG DSN)
--------------------------------------------------------
TOTAL                         1653    13       56.38%
```

**Security Properties Status:**

| Property | Status | Evidence |
|----------|--------|----------|
| Scope Gate Layer 1 (URL/Host) | VERIFIED | 200 tests, TLA+ checked |
| Scope Gate Layer 2 (DNS/IP) | VERIFIED | 200 tests, TLA+ checked |
| Scope Gate Layer 3 (Pinned Dest) | VERIFIED | 200 tests |
| Multi-tenant isolation | VERIFIED | ContextVar tests |
| Scanner crash = FAIL | VERIFIED | Regression tests added |
| No secret leakage | VERIFIED | Redaction tests |
| Egress gateway enforcement | NOT IMPLEMENTED | No gateway exists |
| Capability token auth | NOT IMPLEMENTED | No issuer/verifier |
| Worker isolation | NOT IMPLEMENTED | Same process |
| DNS rebinding protection | PARTIAL | Layer 3 pins but no gateway |
| Artifact signing | PARTIAL | Proof exists, no separate service |
| Durable queue | NOT IMPLEMENTED | In-memory only |
| Idempotency | NOT IMPLEMENTED | No keys |
| Orphan recovery | NOT IMPLEMENTED | No recovery logic |

---

## 10. Questions for Phase 0 Review

1. **LICENSE**: Apache-2.0 is acceptable. How to handle scanner redistribution?
   - Current: Nmap/SQLMap via apt, Nuclei/Nikto downloaded at build
   - Recommendation: Build all from source at Docker build time

2. **Container Runtime**: Is rootless Docker/Podman available on target hosts?
   - Current Dockerfile runs as non-root but doesn't enforce rootless

3. **Python Versions**: Must support 3.12+ (current), 3.13, 3.14 (tested in CI)

4. **API Backward Compatibility**: Existing consumers need strict compatibility?
   - Current API is stable; v4.0 should add, not change

5. **PostgreSQL Requirement**: Can PostgreSQL be mandated as canonical state?
   - Current: SQLite default, PostgreSQL experimental
   - v4.0 design: PostgreSQL required for single-node default

---

**End of Audit**  
**Next Step**: Await review before proceeding to Phase 2 implementation.
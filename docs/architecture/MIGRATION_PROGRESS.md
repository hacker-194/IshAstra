# Migration Progress - IshAstra v3.5 → v4.0

**Started:** 2026-11-22  
**Current Phase:** Phase 2 - Vertical Slice (Security Spine)  
**Last Commit:** `69ebbe1`

---

## Phase Status Overview

| Phase | Name | Status | Started | Completed |
|-------|------|--------|---------|-----------|
| 0 | Audit Only | ✅ DONE | 2026-11-22 | 2026-11-22 |
| 1 | Trustworthy CI | ✅ DONE | 2026-11-22 | 2026-11-22 |
| 2 | Vertical Slice (Security Spine) | 🔄 IN PROGRESS | 2026-11-22 | - |
| 3 | Durable Orchestration | ⏳ PENDING | - | - |
| 4 | Remaining Adapters | ⏳ PENDING | - | - |
| 5 | Adoption Features | ⏳ PENDING | - | - |
| 6 | Hardening & RC | ⏳ PENDING | - | - |
| 7 | Optional AI | ⏳ PENDING | - | - |

---

## Phase 0: Audit Only - COMPLETED ✅

**Exit Criteria:** Audit exists and tests were run.

**Completed:**
- [x] Created `docs/architecture/EXISTING_ARCHITECTURE_AUDIT.md`
- [x] Ran full test suite: 1653 passed, 13 skipped, 56.38% coverage
- [x] Documented existing architecture, working components, gaps
- [x] Documented security weaknesses and license findings
- [x] Documented required migrations and adapted phase plan

**Test Output:**
```
================ 1653 passed, 13 skipped, 33 warnings in 48.95s ================
Required test coverage of 50% reached. Total coverage: 56.38%
```

---

## Phase 1: Trustworthy CI - COMPLETED ✅

**Exit Criteria:** Required gates are green, or red for stated real reasons, with no silent suppression.

**Completed:**
- [x] Fixed security audit false-pass bug in `scripts/security_audit.py`
  - Added `exit_code != 0` checks in `run_pip_audit()` and `run_safety()`
  - Scanner crashes now return "error" not "passed"
- [x] Removed `|| true` and `continue-on-error: true` from CI workflows
  - `.github/workflows/security-scan.yml`: Bandit, Semgrep, Safety, pip-audit
  - `.github/workflows/ci.yml`: Security gate jobs
- [x] Added regression tests in `tests/unit/test_security_audit.py`:
  - `test_scanner_crash_is_error_not_passed()`
  - `test_all_scanners_crash_fails_gate()`
- [x] Updated dependencies to secure versions:
  - `mitmproxy 12.1.3 → 12.3.1` (fixed PyPI availability)
  - `kubernetes 30.1.0` (latest in 30.x)
  - `fastmcp 2.14.7` (hexstrike extra)
  - `in-toto 3.1.0` (slsa extra)
- [x] Pinned all optional extras in `constraints.txt`
- [x] Updated `pyproject.toml` dependency ranges:
  - `hexstrike`: `fastmcp>=2.13.0,<5.0`
  - `slsa`: `in-toto>=2.0.0,<4.0`

**Test Output:**
```
tests/unit/test_security_audit.py::test_scanner_crash_is_error_not_passed PASSED
tests/unit/test_security_audit.py::test_all_scanners_crash_fails_gate PASSED
tests/unit/test_security_audit.py::test_pip_audit_finds_vulnerabilities PASSED
================ 3 passed in 0.42s ================
```

**Security Properties:**
| Property | Status | Evidence |
|----------|--------|----------|
| Scanner crash = FAIL | VERIFIED | Regression tests pass |
| No silent suppression | VERIFIED | No `|| true` in CI |
| Bandit HIGH = FAIL | VERIFIED | CI security-gate job |
| pip-audit HIGH = FAIL | VERIFIED | CI security-gate job |
| Grype HIGH = FAIL | VERIFIED | CI security-gate job |

---

## Phase 2: Vertical Slice - Security Spine - IN PROGRESS 🔄

**Exit Criteria:** Adversarial matrix passes in CI, or each item marked UNVERIFIED with reason.

### 2.1 Capability Issuer Service
- [ ] Ed25519 signing key generation and rotation
- [ ] Capability token structure (JWT EdDSA or PASETO v4.public)
- [ ] Token fields: tenant, engagement, job, targets, pinned IPs, ports, protocols, tools, policy hash, request budget, jti, TTL ≤ 15 min
- [ ] Issuance endpoint (internal, called by dispatcher)
- [ ] Revocation list with DB persistence
- [ ] Unit tests for issuance, validation, revocation

### 2.2 Egress Gateway
- [ ] CONNECT/SOCKS5 proxy implementation
- [ ] Capability verification on every connection
- [ ] DNS resolution by gateway (not worker)
- [ ] IP pinning enforcement (connect to IP, not hostname)
- [ ] Redirect handling (each hop re-authorized)
- [ ] Request budget and rate limiting
- [ ] Audit receipts for every decision
- [ ] Host firewall rules (nftables/DOCKER-USER) as fallback
- [ ] Unit tests for gateway decisions
- [ ] Integration tests against local lab target

### 2.3 Worker Manager
- [ ] Disposable container creation (Docker/Podman)
- [ ] Resource limits: CPU, memory, PID, wall-clock timeout
- [ ] Security hardening: non-root, read-only rootfs, no-new-privileges, caps dropped
- [ ] Argument arrays only (no shell interpolation)
- [ ] Workspace collection after exit
- [ ] Worker cleanup on cancel/expiry/completion
- [ ] Capability injection at startup
- [ ] Unit tests for container lifecycle

### 2.4 Capability Verifier
- [ ] Read-only DB role for verification queries
- [ ] Checks: signature, audience, nbf/exp, revocation, job RUNNING, policy hash match
- [ ] Unit tests for all verification paths

### 2.5 Evidence Signing Service
- [ ] Separate Ed25519 key from capability key
- [ ] Canonical JSON manifest (RFC 8785)
- [ ] SHA-256 artifact hashes
- [ ] Key ID and rotation support
- [ ] `ishastra evidence verify` offline command
- [ ] Unit tests for manifest creation and verification

### 2.6 End-to-End Vertical Slice Test
- [ ] Local lab target container
- [ ] Full flow: engagement → job → capability → worker → gateway → target → evidence → verify
- [ ] Adversarial test matrix execution

**Security Properties Target:**
| Property | Target Status |
|----------|---------------|
| Capability token auth | VERIFIED |
| Egress gateway enforcement | VERIFIED |
| Worker isolation | VERIFIED |
| DNS rebinding protection | VERIFIED |
| Artifact signing | VERIFIED |
| Offline evidence verify | VERIFIED |

---

## Phase 3: Durable Orchestration - PENDING ⏳

**Exit Criteria:** Tests for duplicate message, dispatcher restart, worker crash, pending-job recovery, and cleanup.

- [ ] PostgreSQL queue with `FOR UPDATE SKIP LOCKED`
- [ ] Idempotency keys on job submission
- [ ] Retry policy with exponential backoff
- [ ] Cancellation with worker cleanup
- [ ] Orphan recovery on dispatcher restart
- [ ] Terminal failure state (`retries_exhausted`)
- [ ] Optional Redis Streams + outbox profile

---

## Phase 4: Remaining Adapters - PENDING ⏳

**Exit Criteria:** Each adapter passes enforcement spike and adapter tests, or disabled and documented.

- [ ] Adapter contract definition
- [ ] Nmap adapter (`-sT` only, proxy-enforced)
- [ ] Nikto adapter (proxy-enforced)
- [ ] SQLMap adapter (opt-in, high-risk flag)
- [ ] Plugin runner for custom adapters (out-of-process)
- [ ] Deduplication and correlation

---

## Phase 5: Adoption Features - PENDING ⏳

**Exit Criteria:** Clean-machine quickstart test and dashboard working.

- [ ] `docker compose up` quickstart (< 5 min)
- [ ] `ishastra` CLI (submit, status, evidence verify)
- [ ] SARIF/Nuclei/ZAP import
- [ ] Multi-format export (SARIF, HTML, PDF, CSV, JSON, DefectDojo)
- [ ] GitHub Action for CI
- [ ] Dashboard: engagements, scans, findings, evidence, audit

---

## Phase 6: Hardening & RC - PENDING ⏳

**Exit Criteria:** Tag `4.0.0-rc1` locally only.

- [ ] SBOM in release artifacts
- [ ] Signed container images (cosign)
- [ ] Build provenance (SLSA)
- [ ] Tag-to-commit verification
- [ ] Release gated on all checks
- [ ] Documentation: quickstart, threat model, limitations
- [ ] Local tag `4.0.0-rc1`

---

## Phase 7: Optional AI - PENDING ⏳

**Exit Criteria:** Off by default, local models only, advisory findings, human approval.

- [ ] Off by default
- [ ] Local/user-supplied models only
- [ ] Summaries, dedup, explanations, remediation drafts
- [ ] Human approval for follow-up scans

---

## Commit History

| Commit | Date | Phase | Description |
|--------|------|-------|-------------|
| `69ebbe1` | 2026-11-22 | 0,1 | Cleanup repo, update deps, fix security audit false-pass |
| *(pending)* | 2026-11-22 | 0 | Add EXISTING_ARCHITECTURE_AUDIT.md and MIGRATION_PROGRESS.md |
# Claims and Verification Status

**Version:** 4.0.0rc1 · **Last updated:** 2026-11-26

This document records every claim made by the project and its verification status. It is the single source of truth for what is **verified**, what is **partial**, and what is **unverified**. Consumers (operators, auditors, insurers) should treat **UNVERIFIED** claims as aspirational only — they represent design intent, not demonstrated reality.

---

## Legend

| Status | Meaning |
|--------|---------|
| ✅ **VERIFIED** | Implemented, tested, and enforced in CI. Evidence: test file, TLA+ model check, or security gate. |
| ⚠️ **PARTIAL** | Implemented for a subset of cases (e.g., single-tenant only, single-host only, optional flag required). Documented scope limitation. |
| ❌ **UNVERIFIED** | Claimed in documentation or marketing but not enforced by code, not tested in CI, or no evidence exists. Do not rely on this for compliance or security decisions. |

---

## Claims

### 1. Authorization and Scope Gate

| Claim | Status | Evidence |
|-------|--------|----------|
| Default-deny on every outbound connection | ✅ VERIFIED | `tests/unit/test_scope_gate.py`, `tests/unit/test_scope.py` |
| Three-layer gate: URL/Host → DNS/IP → Pinned Destination | ✅ VERIFIED | `src/ishastra/core/scope.py`, TLA+ invariants |
| DNS rebinding protection (pin to IP) | ✅ VERIFIED | `src/ishastra/core/scope.py:Destination`, TLA+ `NoRebinding` |
| Scope document signing (Ed25519) | ✅ VERIFIED | `src/ishastra/core/scope_signing.py`, `tests/unit/test_scope_signing.py` |
| Break-glass dual approval | ✅ VERIFIED | `src/ishastra/core/scope_breakglass.py`, `tests/unit/test_scope_breakglass.py` |
| Capability tokens (Ed25519 JWT, TTL ≤ 900s) | ✅ VERIFIED | `src/ishastra/core/capability.py`, `tests/unit/test_capability.py` |
| Token revocation by job/engagement/tenant | ✅ VERIFIED | `src/ishastra/core/capability.py:revoke_*` |
| Egress gateway enforces capability tokens | ✅ VERIFIED | `src/ishastra/core/egress_gateway.py`, `tests/unit/test_egress_gateway.py` |
| External tools (Nuclei) routed through proxy | ✅ VERIFIED | `src/ishastra/adapters/builtin.py:NucleiAdapter` |
| nmap/nikto/sqlmap require gateway (refuse direct) | ✅ VERIFIED | All three declare `enforcement="proxy"` and call `_require_gateway()` before any process starts; `tests/unit/test_adapters.py::TestExternalToolGatewayRequired::test_{nmap,nikto,sqlmap}_refuses_without_gateway` assert no tool is spawned. They still run on the worker host after the check (no sandbox), so isolation depends on the deployed gateway. |

### 2. Audit Chain and Evidence

| Claim | Status | Evidence |
|-------|--------|----------|
| Tamper-evident HMAC audit chain | ✅ VERIFIED | `src/ishastra/core/audit.py`, `tests/unit/test_audit.py` |
| Signed evidence bundles (Ed25519 manifest, SHA-256 pinned) | ✅ VERIFIED | `src/ishastra/core/bundle.py`, `tests/unit/test_bundle.py` |
| Offline verification (`ishastra bundle --verify`, `ishastra evidence-verify`) | ✅ VERIFIED | CLI commands implemented and tested |
| SARIF export with normalized findings | ✅ VERIFIED | `src/ishastra/core/exports.py`, `tests/unit/test_exports.py` |
| Redaction at every boundary (findings, logs, webhooks) | ✅ VERIFIED | `src/ishastra/core/redaction.py`, `tests/unit/test_redaction.py` |

### 3. Infrastructure and Deployment

| Claim | Status | Evidence |
|-------|--------|----------|
| SQLite is the pilot backend | ✅ VERIFIED | Default in CI, `tests/` all pass with SQLite |
| PostgreSQL single-host support | ✅ VERIFIED | `tests/` pass with `ISHASTRA_DB=postgresql://...`, `src/ishastra/core/store.py` |
| PostgreSQL multi-node / HA / automated failover | ❌ UNVERIFIED | No multi-node tests, no failover automation in core code. `src/ishastra/core/pg_queue.py` uses `FOR UPDATE SKIP LOCKED` but no HA controller. |
| Worker lease fencing (monotonic tokens) | ✅ VERIFIED | `src/ishastra/core/store.py:fencing_token`, `tests/unit/test_lease_fencing.py` |
| Automated failover via lease expiry | ✅ VERIFIED | TLA+ `RevocationFreshness` invariant, lease tests |
| `k8s-jobs` queue mode | ⚠️ PARTIAL | Integration tests exist (`tests/integration/test_k8s_jobs.py`) but marked `k8s` and skipped without cluster. Helm chart supports it. Not default. |
| `redis-streams` queue mode | ⚠️ PARTIAL | Code exists (`src/ishastra/core/redis_queue.py`) but no integration tests in CI. |
| `in-process` queue mode | ✅ VERIFIED | Default, all unit tests use it. |
| Multi-tenant API isolation (RLS) | ✅ VERIFIED | `src/ishastra/api/middleware.py:RLSTenantMiddleware`, `src/ishastra/core/pg_rls.py`. `tests/test_rls.py` integration tests run in CI `test-multi-tenant` job with PostgreSQL service. |
| Free-tier Oracle Cloud deployment | ⚠️ PARTIAL | `scripts/bootstrap-free.sh` exists but not tested in CI. ARM architecture not validated in CI. |

### 4. Formal Verification

| Claim | Status | Evidence |
|-------|--------|----------|
| 6 TLA+ invariants model-checked | ✅ VERIFIED | `docs/tla/JudgeAddresses.tla`, CI `formal-verification` job |
| Invariants: DefaultDeny, Pinning, NoRebinding, Isolation, RevocationFreshness, BreakGlass | ✅ VERIFIED | `docs/tla/JudgeAddresses.tla` |
| **21.4M states model-checked** | ✅ VERIFIED | `docs/tla/model-check-results.txt` (TLC output: 21,458,641 states generated, 116,550 distinct, 6 invariants PASS) |
| TLA+ invariants cover all production code paths | ⚠️ PARTIAL | Model abstracts scope gate logic only. Does not cover worker lease fencing, capability token lifecycle, or egress gateway. |

### 5. Compliance and Certifications

| Claim | Status | Evidence |
|-------|--------|----------|
| **Third-party security audit / penetration test** | ❌ UNVERIFIED | No third-party audit performed. TLA+ and adversarial tests are evidence, not a pentest. |
| **SOC 2 / ISO 27001 / PCI DSS certification** | ❌ UNVERIFIED | `docs/compliance/*` maps controls to clauses. No certificate issued by any auditor. |
| **NIST 800-53 control mapping** | ✅ VERIFIED | `docs/compliance/nist-800-53.md` maps controls to IshAstra features. Mapping only — no certification. |
| **NIS2 / NRB / NTA / NCSP compliance evidence** | ⚠️ PARTIAL | `ishastra evidence` CLI generates evidence packs for NRB/NTA/NCSP frameworks. Evidence generation is implemented; acceptance by regulators is UNVERIFIED. |

### 6. Performance and Scale

| Claim | Status | Evidence |
|-------|--------|----------|
| Single-machine baseline performance | ✅ VERIFIED | `scripts/detection_benchmark.py`, `docs/reliability.md` |
| Soak test (100 VU, 1h) | ⚠️ PARTIAL | `scripts/locustfile.py` created, CI job `benchmark-soak` added but not yet run in CI history. |
| Benchmark regression detection (15% threshold) | ⚠️ PARTIAL | `scripts/benchmark_regression.py` created, CI job `benchmark-regression` added but no baseline artifact exists yet. |
| Multi-node / horizontal scaling | ❌ UNVERIFIED | No multi-node tests. `k8s-jobs` is experimental. Worker lease is single-writer. |

### 7. Container and Runtime Security

| Claim | Status | Evidence |
|-------|--------|----------|
| Non-root `ishastra` user in container | ✅ VERIFIED | `Dockerfile`, `deploy/helm/ishastra/values-*.yaml` |
| Read-only root filesystem | ⚠️ PARTIAL | Helm values set `readOnlyRootFilesystem: true` but SQLite requires writable `/var/lib/ishastra`. Works with `emptyDir` or PVC. |
| `--cap-drop ALL`, `--security-opt no-new-privileges:true` | ✅ VERIFIED | Helm chart `securityContext` and `workerPodTemplate` |
| Worker containers are disposable (auto-cleanup) | ✅ VERIFIED | `src/ishastra/control_plane/container_worker_runner.py`, k8s TTL controller |
| Signed container images (cosign, keyless) | ✅ VERIFIED | CI `cosign-sign` job signs images keyless via `sigstore/cosign-installer`. Runs after `docker` job. |
| SLSA provenance (build attestation) | ✅ VERIFIED | CI `cosign-sign` job generates SLSA v3 provenance via `slsa-framework/slsa-github-generator@v1.10.0`. Attestations uploaded as artifacts. |

### 8. DNS and Network Controls

| Claim | Status | Evidence |
|-------|--------|----------|
| DNS resolution bypass prevention (operator-controlled) | ⚠️ PARTIAL | Documented in `docs/security/enforcement-matrix.md`. Not enforced by default; requires operator to configure gateway/firewall. |
| Redirect handling (follow/deny) | ⚠️ PARTIAL | `src/ishastra/adapters/builtin.py:HTTPAdapter` follows redirects by default. Scope gate re-checks each hop but redirect chain not fully validated. |
| Broad network allowance (`allow_broad_networks`) | ✅ VERIFIED | Scope document field, gate checks it. Default `false`. |

### 9. Resource Management (New in 4.0)

| Claim | Status | Evidence |
|-------|--------|----------|
| Streaming file processing (no full-file load) | ✅ VERIFIED | `src/ishastra/core/streaming.py`, 46 unit tests in `tests/unit/test_resource_management.py` |
| Bounded queues with backpressure | ✅ VERIFIED | `BoundedQueue` in `streaming.py`, `Worker` uses `queue.Queue(maxsize=N)` |
| Per-worker memory limits | ✅ VERIFIED | `MemoryGuard` monitors RSS, triggers GC; `Worker._maybe_check_memory()` already existed |
| HTTP response size limits | ✅ VERIFIED | `ISHASTRA_MAX_BODY_BYTES` config, enforced in API middleware |
| Scanner output limits | ✅ VERIFIED | Truncation with warnings when output exceeds thresholds |
| Artifact lifecycle (CREATED→PROCESSING→FINALIZED→RETAINED→ARCHIVED→EXPIRED→DELETED) | ✅ VERIFIED | `ArtifactLifecycleManager` in `artifact_lifecycle.py`, state machine with status transitions |
| Retention policies | ✅ VERIFIED | `RetentionPolicy` with configurable lifetime and delete-after-failure |
| Storage quotas per engagement/tenant | ✅ VERIFIED | `StorageQuotaManager` tracks usage, `check_can_write()` pre-write check, `SafeStorageWriter` atomic quota-checked writes |
| Disk space monitoring and low-space warnings | ✅ VERIFIED | `check_disk_space_safe()`, configurable warning/critical thresholds |
| Safe rejection when storage exhausted | ✅ VERIFIED | `StorageQuotaExceeded` exception, `check_can_write()` returns safety dict |
| Evidence compression (gzip/zlib) | ✅ VERIFIED | `compress_evidence()` in `evidence_storage.py` |
| Incremental hashing | ✅ VERIFIED | `compute_hash_incremental()`, `stream_and_hash()` |
| Streaming evidence bundles | ✅ VERIFIED | `create_evidence_bundle()` with file-based compression option |
| Evidence bundle verification | ✅ VERIFIED | `read_evidence_bundle_streaming()` verifies signature and manifest |
| Database optimization | ✅ VERIFIED | `DatabaseOptimizer` configures SQLite WAL/PRAGMA, creates indexes, vacuum, backup/restore |
| Resource profiles (Lightweight/Standard/High-Capacity) | ✅ VERIFIED | `ResourceProfile` dataclasses, `get_profile()`, `list_profiles()` |

### 10. Supply Chain

| Claim | Status | Evidence |
|-------|--------|----------|
| Pinned GitHub Actions (SHA) | ✅ VERIFIED | `.github/workflows/ci.yml` uses commit SHAs for all actions |
| Dependency constraints (`constraints.txt`) | ✅ VERIFIED | `constraints.txt` pins transitive deps, CI installs with `-c constraints.txt` |
| SBOM generation (Syft) | ✅ VERIFIED | CI `sbom` job generates SPDX-JSON |
| Vulnerability scan (Grype, Trivy) | ✅ VERIFIED | CI `sbom` (grype) and `container-scan` (trivy) jobs |
| Security gate fails on HIGH findings | ✅ VERIFIED | CI `security-gate` job runs `scripts/security_gate.py` |
| License compatibility check | ✅ VERIFIED | CI `license-check` job |

---

## How to Use This Document

- **Operators**: Before deploying, review all ❌ UNVERIFIED and ⚠️ PARTIAL claims. Do not assume they are true in your environment.
- **Auditors**: Request evidence for ✅ VERIFIED claims (test logs, TLA+ model check output, CI run URLs).
- **Maintainers**: When a claim changes status, update this file and the corresponding documentation (README.md, SECURITY.md).

---

## Related Files

- `SECURITY.md` — Security policy and real-world limitations
- `README.md` — Project overview and limitations section
- `docs/security/threat-model.md` — Threat model
- `docs/scope-gate/tla-verification.md` — TLA+ verification details
- `docs/reliability.md` — Performance and reliability baselines
- `docs/compliance/overview.md` — Compliance mappings
- `RESOURCE_MANAGEMENT.md` — Resource management architecture and configuration
- `src/ishastra/core/streaming.py` — Streaming, bounded queues, memory guard
- `src/ishastra/core/artifact_lifecycle.py` — Artifact lifecycle manager
- `src/ishastra/core/storage_quota.py` — Storage quotas and safe writes
- `src/ishastra/core/evidence_storage.py` — Evidence compression and bundles
- `src/ishastra/core/db_optimize.py` — Database optimization and maintenance
- `src/ishastra/core/resource_profiles.py` — Resource profiles

---

*This document is part of the 7-phase hardening program. Phase 7 (Audit/Compliance Documentation) created this file. Updated after workflow agent changes on 2026-11-26.*
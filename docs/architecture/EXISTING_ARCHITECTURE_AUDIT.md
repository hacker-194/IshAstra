# Existing Architecture Audit - IshAstra

**Phase:** 0 (audit only, no code changes)
**Date:** 2026-11-23
**Branch:** `master`
**HEAD:** `3d681e3` (docs: add Phase 0 audit and migration progress)
**Version in `pyproject.toml`:** 3.5.0
**Working tree:** dirty - 5 modified files, 8 untracked files (see §3.5)

This audit supersedes the 2026-11-22 version. The earlier version said Phase 2 had
not started; an uncommitted Phase 2 scaffold now exists in the tree and is
described below exactly as it is, not as its docstrings claim.

---

## 1. Existing Architecture Summary

IshAstra today is a **single-process FastAPI application** with an in-memory job
queue and a threaded worker pool. Tool adapters run **in the API process** and
connect to targets **directly**. A three-layer Scope Gate authorizes each
outbound request in-process.

| Component | Location | State |
|---|---|---|
| API (FastAPI, 40+ `ISHASTRA_*` env vars) | `src/ishastra/api/` | Working |
| Scope Gate (3 layers, default-deny) | `src/ishastra/security/authorization/scope.py` (957 stmts, 1683 lines) | Working, 92% coverage |
| Job orchestration + queue | `src/ishastra/core/jobs.py`, `queue*.py`, `k8s_queue.py` | Working; in-process default |
| Adapters (nmap, Nuclei, SQLMap, Nikto, HTTP, crawler) | `src/ishastra/core/adapter_base.py`, `adapters.py` | Working, in-process |
| Findings + dedupe + redaction | `src/ishastra/core/findings.py` | Working |
| Persistence (SQLite default, PostgreSQL experimental) | `src/ishastra/core/store.py` | Working; schema via `init_db()`, **no Alembic** |
| Multi-tenant API keys | `src/ishastra/core/authz.py`, `policies.py` | Working |
| Audit chain (hash-chained) | `src/ishastra/proof.py`, `audit.py` | Working (76% coverage) |
| Signed evidence bundles | `src/ishastra/core/bundle.py`, `scope_signing.py` | Working |
| Reporting (HTML/PDF/SARIF/CSV) | `report_html.py`, `report_pdf.py`, `proof.py` | Working |
| CLI | `src/ishastra/cli.py` (`ishastra serve/demo/bundle/...`) | Working |

### 1.1 v4.0 target directories

The target tree had 25 placeholder modules that were empty (0-byte `__init__.py`)
and imported by nothing: `control_plane/{identity,tenants,engagements,policies,jobs,findings,evidence,reporting}`,
`orchestration/`, `infrastructure/{database,queue,object_storage,configuration}`,
`adapters/{nmap,nuclei,sqlnikto}`, `analysis/{ai,correlation,risk_scoring}`,
`observability/`, `reporting/`, `security/audit/`. They were removed on
2026-11-23 under the rule "create directories only when code lands" (verified:
no import statements referenced them; `"ishastra.adapters"` survives only as an
entry-point group string in `core/adapters.py`).

`src/ishastra/security/` is the only v4.0 area with real code, and that code is
uncommitted (see §3.5). `deploy/compose`, `deploy/docker`, `deploy/gateway`,
`migrations/`, `frontend/` from the target layout do **not** exist. Deployment
today is `docker-compose.yml`, `deploy/single-host/compose.yaml`, `deploy/helm`,
`deploy/kustomize`, `k8s/`.

---

## 2. Working Components (verified by tests)

| Component | Tests | Coverage | Notes |
|---|---|---|---|
| Scope Gate (3 layers) | 200 tests (`test_scope.py`, `test_scope_gate.py`) | 92% | TLA+ model checked (21.4M states) |
| Core modules | `test_core_modules.py` | 100% | |
| Security audit script | 3 tests (`test_security_audit.py`) | 100% | Crash = error, not pass |
| Evidence bundles / proof | `tests/unit/test_proof*.py`, `test_bundle*` | 76% (`proof.py`) | Offline verify works |
| Auth / tenancy | `test_auth.py`, `test_rls.py` | - | RLS verified on `postgres:16-alpine`: 16 passed (2026-11-23) |

### 2.1 Test run (real output, 2026-11-23)

Command:

```bash
.venv/bin/python -m pytest -q
```

Result (exit 0):

```
1668 passed, 13 skipped, 34 warnings in 57.03s
Required test coverage of 50% reached. Total coverage: 54.79%
```

Skips, with reason:

```
SKIPPED [1]  tests/test_rls.py:24: Set ISHASTRA_TEST_PG_DSN to run PostgreSQL RLS tests
SKIPPED [10] tests/e2e/test_critical_paths.py: ISHASTRA_E2E_BASE_URL not set; e2e tests need a running API
SKIPPED [2]  tests/unit/test_redis_queue.py:27: no Redis server available for the durable queue test
```

### 2.2 Quality gates (real output, 2026-11-23)

| Check | Exit | Result |
|---|---|---|
| `pytest -q` | 0 | 1668 passed, 13 skipped, 54.79% |
| `ruff check src tests scripts` | **1** | **90 errors** |
| `mypy src` | **1** | **30 errors in 8 files** |

Ruff breakdown: 20 `W292` (missing newline at EOF), 19 `E501`, 18 `F401`
(unused import), 9 `UP045`, 8 `I001`, 3 `SIM118`, 3 `PIE790`, 2 `UP041`,
2 `UP017`, 2 `F841`. Hot spots: `security/egress/gateway.py` (10),
`integrations/connectors/slack.py` (9), `security/capabilities/revocation.py` (8),
`security/capabilities/issuer.py` (8), `integrations/connectors/sentinel.py` (6),
`execution/worker_manager.py` (6), `security/capabilities/verifier.py` (5).
Roughly a third of the 90 errors come from the uncommitted Phase 2 files, so the
lint gate is red because of work in progress, not only pre-existing debt.

Mypy: `security/egress/gateway.py` 12, `integrations/github_issues.py` 12,
`integrations/connectors/sentinel.py` 6, `security/capabilities/issuer.py` 3,
`integrations/base.py` 3, `security/capabilities/verifier.py` 1,
`integrations/connectors/slack.py` 1, `integrations/__init__.py` 1,
`audit.py` 1. The gateway errors are real type mismatches between `bytes` and
`str` in the CONNECT parser (`gateway.py:191,196,212,318-324`).

---

## 3. Weak or Duplicated Parts

### 3.1 Architecture duplication

- All behavior lives in `src/ishastra/core/`; the v4.0 tree is empty scaffolding
  with docstrings describing components that do not exist.
- **No import shims**: nothing in `src/` imports the new `capabilities`,
  `egress.gateway`, `signing.service`, or `worker_manager` modules (verified by
  grep excluding the modules themselves). They are dead code in the current
  build: 3 of them are at 0% coverage.
- `src/ishastra/security/authorization/scope.py` is the live scope engine.
  `src/ishastra/control_plane/scope/__init__.py` is empty. There is one
  implementation and one placeholder, not two implementations - good, but the
  target layout implies a move that has not happened.

### 3.2 Docstrings that describe nonexistent tests

`issuer.py`, `verifier.py`, `gateway.py`, `signing/service.py`, and
`worker_manager.py` each say "Tests in tests/unit/test_<name>.py". Those files do
not exist. The only Phase 2 test file is `tests/unit/test_capability_token.py`
(348 lines), which covers `token.py` only. This is exactly the failure mode the
working rules forbid: documentation claiming coverage that is not there.

### 3.3 Duplicated schema definitions

`store.py` now defines `capability_revocations` and `capability_tokens` twice
(SQLite ~line 578, PostgreSQL ~line 1113), and `revocation.py` defines the same
DDL a third time. Three copies of the same schema with no migration mechanism
will drift. `init_db()` auto-creates tables; there is **no Alembic and no
`migrations/` directory**, so there is no rollback story.

### 3.4 Repository hygiene

Generated/runtime artifacts sit in the working directory (git-ignored, but
confusing): `:memory:.worker-lock`, `:memory:_scheduler.db`, `ishastra.db`,
`strix.db`, `strix_scheduler.db`, `ishastra_scheduler.db`, `coverage.json`,
`build/`, `dist/`, `site/`, `security-reports/`, `prod-secrets/`.
`prod-secrets/` is especially worth confirming is excluding real key material
from accidental publication before Phase 6.

### 3.5 Uncommitted state (do not overwrite, do not commit yet)

Modified: `core/store.py` (+82: capability tables and migration bumps),
`security/capabilities/__init__.py` (+72: re-exports),
`security/egress/__init__.py` (+9), `security/signing/__init__.py` (+10),
`tests/unit/test_store.py` (+6/-2).

Untracked: `security/capabilities/{token,issuer,verifier,revocation}.py`,
`security/egress/gateway.py`, `security/signing/service.py`,
`execution/worker_manager.py`, `tests/unit/test_capability_token.py`.

Total ~2,989 lines of uncommitted Phase 2 work. It is **not** committed, **not**
reviewed, and per this audit **not functional end to end**.

---

## 4. Security Weaknesses

### 4.1 What does not exist at all (v3.5 behavior, which is what ships)

| Gap | Evidence |
|---|---|
| No egress enforcement: adapters dial targets directly from the API process | `core/adapters.py` uses the Gate for a decision, then `httpx`/subprocesses connect normally; no proxy is mandated |
| No capability tokens in the running path | New modules are unimported (§3.1) |
| Workers are not isolated containers | Jobs run in threads inside the API process (`core/jobs.py`) |
| No host-firewall rules | No nftables/DOCKER-USER code anywhere; `worker_manager` only logs intent |
| DNS rebinding protected only in-process | Layer 3 pins a `Destination`, but the actual socket is opened by httpx/subprocess, not by the gate |
| No separate evidence-signing key | Evidence signing reuses the scope-signing key path (`core/bundle.py`) |
| No durable queue by default | In-process queue loses queued jobs on restart |

### 4.2 The Phase 2 scaffold's real holes (Phase 0 snapshot)

This table is the state at the Phase 0 audit. Most rows were fixed in the
Phase 2 pass on 2026-11-23; see §8 for the current status and
`docs/architecture/EGRESS_ENFORCEMENT.md` for the tested mechanism.

Read line by line. These are facts, not inferences:

| Location | Problem |
|---|---|
| `egress/gateway.py:484` | `_pipe_data` is `pass`. A CONNECT returns `200 Connection Established` and then **forwards zero bytes**. The gateway cannot proxy anything. |
| `egress/gateway.py:340` | `_extract_token_from_socks5` returns `None`. SOCKS5 can never authenticate, so the SOCKS path is dead. |
| `egress/gateway.py:455-470` | `_connect_upstream` returns an `asyncio.Transport` built with `ssl=(port == 443)`. For CONNECT the client already speaks TLS; wrapping the upstream in TLS again is wrong, and a `Transport` cannot be piped to a `StreamWriter` anyway. |
| `egress/gateway.py:144-145` | Firewall fallback is a log line: `"firewall fallback enabled (nftables/DOCKER-USER rules would be installed)"`. No rules are installed. |
| `egress/gateway.py:433-434` | Request budget and RoE rate limit are not enforced: "For now, log the connection for audit". |
| `egress/gateway.py:503-515` | Receipts go to `audit_log` (plain append table), not to `audit_chain` (the hash-chained table in `store.py:126`). Gateway receipts are therefore **not tamper-evident**, contrary to §5.6. |
| `capabilities/verifier.py:137-146` | Sync `verify()` silently skips revocation and job-state checks with `pass`. `verify_async()` does them, and the gateway calls `verify_async()` (`gateway.py:365`), so the gateway path is fine - but any future caller that uses `verify()` gets a false "valid". Security-relevant API trap. |
| `capabilities/verifier.py` `_get_job_state` | Compares `state` to `"running"`. The job-state machine in the target design uses uppercase `RUNNING`; `store.py`'s existing states must be confirmed before this check means anything. Untested. |
| `capabilities/verifier.py` (class docstring) | Claims "Uses read-only database role". There is no separate role, credential, or connection anywhere in the code. Not implemented. |
| `execution/worker_manager.py` `WorkerConfig.network_mode` | Defaults to `--network none`, so a worker cannot reach the gateway either. The design needs a worker network attached only to the gateway. |
| `execution/worker_manager.py` `_build_docker_command` | Passes the capability token as `-e ISHASTRA_CAPABILITY_TOKEN=<b64>` in the `docker run` **argv**, so the token is visible to any local user via `ps`/`/proc`. Also bind-mounts a host directory (`-v /tmp/ishastra-workers/<job>:/workspace`), which the target rules disallow ("no host mounts"). |
| `execution/worker_manager.py` | No seccomp profile, no image digest pinning, no rootless runtime check. `--rm`, `--read-only`, `--tmpfs`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--pids-limit`, `--memory`, `--user 10001:10001` are present and correct. |
| `signing/service.py:66` | `canonical_json` is `json.dumps(sort_keys=True, separators=...)`, not RFC 8785: number formatting and Unicode escaping are not the JCS rules. Signing/verification is self-consistent, so it is not a forgery hole, but the "RFC 8785" claim in docs would be false. 0% coverage, unimported. |

Well-formed parts worth keeping: `capabilities/token.py` (signed body excludes the
signature, TTL capped at 900s, issuer fingerprint bound to the signing key,
`iat`/`exp` enforced), `capabilities/issuer.py` key rotation with `previous_keys`,
and `revocation.py`'s indexed JTI lookup. `core/store.py::_adapt_placeholders`
(line 1913) converts `?` to `$n` for PostgreSQL, so the new DML is portable.

### 4.3 Supply chain and container hardening

- Dockerfile runs as non-root `ishastra:10001`.
- `docker-compose.yml` contains **no** `read_only`, `security_opt`,
  `cap_drop`, or `no-new-privileges` settings (grep: zero matches). Service
  hardening exists only in the Kubernetes manifests/operator, not in Compose.
- No SBOM in release artifacts locally; syft/grype run in CI only.
- Scanners: Nmap/SQLMap via apt, Nuclei/Nikto fetched at build time. See §5.

---

## 5. License Findings

| Tool | License | Current handling | Action |
|---|---|---|---|
| Nmap | NPSL | apt package | Redistribution terms are unclear; prefer fetch/build at image build, do not vendor binaries |
| Nuclei | MIT | downloaded at build | OK |
| Nikto | GPL-2.0 | downloaded at build | If binaries are shipped in an image, source must be offered; build from source or document |
| SQLMap | GPL-2.0 | apt package | Same as Nikto |
| IshAstra itself | Apache-2.0 (`LICENSE`, `NOTICE`) | unchanged | Keep; ask before any change |

`NOTICE` exists and should be kept in sync with anything vendored.

---

## 6. Compatibility Concerns

- **API surface to preserve:** `/api/assess`, `/api/assessments`, `/api/findings`,
  `/api/policies`, `/api/proof`, `/api/probe`, `/api/health`, `/api/ready`,
  `/metrics`. Health/readiness and `/metrics` are used by Compose, Helm and the
  operator; changing them breaks deployments.
- **CLI:** `ishastra` entry point with `serve`, `demo`, `bundle`, `rotate-keys`,
  `lifecycle`. Phase 5 adds `evidence verify`; it must not repurpose `bundle`.
- **Data model:** SQLite schema created by `init_db()`; PostgreSQL via
  `_adapt_placeholders`. Any schema change must keep both paths working and must
  add the missing migration story before v4.0 claims upgrades are safe.
- **Config:** env vars only (`ISHASTRA_*`); no config file. The new modules read
  no config at all yet, so operator wiring is undefined.
- **Plugins:** `ishastra.adapters` entry points, **in-process**, gated by
  `ISHASTRA_ALLOW_PLUGINS=1`. This directly conflicts with the target rule that
  third-party adapters run out of process. A deprecation path is needed, not a
  silent behavior change.

---

## 7. Required Migrations (v3.5 -> v4.0)

Reality check against the earlier plan:

| Phase | Claimed | Actual |
|---|---|---|
| 0 Audit | Done | Done (this document) |
| 1 Trustworthy CI | Done | **Partial** - see §7.1 |
| 2 Vertical slice | In progress | **Scaffold only** - token module tested, everything else unimported/untested (§4.2) |
| 3 Durable orchestration | Pending | Pending |
| 4 Adapters | Pending | Pending |
| 5 Adoption | Pending | Pending |
| 6 Hardening/RC | Pending | Pending |
| 7 AI | Pending | Pending |

### 7.1 Corrections to the Phase 1 "done" claim

- `continue-on-error` is absent from all workflows - claim holds.
- `|| true` remains only on the Bandit, pip-audit and grype *report* steps,
  where it captures artifacts for upload. The deciding step is now
  `python scripts/security_gate.py`, which fails closed on a missing, empty,
  unreadable or malformed report and on any HIGH finding. Its logic is covered
  by `tests/unit/test_security_gate.py` (14 tests, including expired and
  incomplete exceptions), and empty scanner output is an error in
  `scripts/security_audit.py`. The `jq ... || echo 0` fallbacks that turned a
  missing report into "zero findings" were removed.
- `MIGRATION_PROGRESS.md` claimed `mitmproxy 12.1.3 -> 12.3.1`; `constraints.txt`
  still pins `mitmproxy==12.1.3`. The progress entry was wrong and has been
  corrected.
- `pyproject.toml` declares version **3.5.0**, not 4.0.0. Nothing in the tree is
  version-bumped.

### 7.2 Work required, ordered

1. **Phase 2 completion** (must precede anything else): make the gateway actually
   relay bytes, authenticate SOCKS5 or remove it, connect to the pinned IP
   without double TLS, enforce budget/rate limit, write receipts into
   `audit_chain`, wire issuer -> dispatcher -> worker -> gateway, add tests for
   every check in §5.4, fix the token-in-argv leak, and put workers on a network
   that reaches only the gateway.
2. **Lint/type green**: 90 ruff + 30 mypy errors, a third from Phase 2 files.
3. **Host firewall** (`DOCKER-USER`/nftables) with a test that proves a direct
   socket is blocked. Until then every egress claim is PARTIAL at best.
4. **Phase 3**: Postgres `FOR UPDATE SKIP LOCKED` queue, idempotency, retries,
   cancel/timeout, orphan recovery, terminal `retries_exhausted`.
5. **Alembic** (or an explicit documented replacement) with rollback, so the
   three duplicated DDL copies become one.
6. **Adapters** behind the contract, out-of-process plugins, enforcement spikes.
7. **Adoption**, **hardening**, then optionally AI.

---

## 8. Security Properties Status

Only properties with a named, passing test are VERIFIED.

| Property | Status | Evidence / reason |
|---|---|---|
| Scope Gate L1 host/port deny | VERIFIED | `tests/unit/test_scope.py`, `test_scope_gate.py` (200 tests) |
| Scope Gate L2 every resolved IP checked | VERIFIED | same |
| Scope Gate L3 destination pinning | VERIFIED | same |
| Tenant isolation via ContextVar | VERIFIED | `tests/unit/*tenant*`, `test_auth.py` |
| Scanner crash/timeout/missing = failure | VERIFIED | `tests/unit/test_security_audit.py` (3 tests) |
| Secret redaction in reports | VERIFIED | redaction tests in `test_core_modules.py` |
| Capability token signing, TTL <= 15 min, issuer binding, exp/iat | VERIFIED | `tests/unit/test_capability_token.py` |
| Capability key rotation | UNVERIFIED | `issuer.rotate_key` has no test |
| Revocation list | UNVERIFIED | `revocation.py` 24% coverage, no test file |
| Gateway token verification (signature, exp) | VERIFIED | `test_expired_token_is_denied`, `test_token_signed_by_unknown_key_is_denied` |
| Gateway audience/version pinning | VERIFIED | `test_wrong_audience_is_denied`, `test_unknown_token_version_is_denied` |
| Gateway host/port/protocol/pinned-IP checks | VERIFIED | `test_host_outside_scope_is_denied`, `test_port_outside_scope_is_denied`, `test_protocol_outside_scope_is_denied`, `test_mixed_dns_answers_are_denied` |
| Gateway byte relay (CONNECT) | VERIFIED | `test_allowed_connection_relays_bytes_both_ways` |
| SOCKS5 egress | **NOT IMPLEMENTED** | dead handler removed; CONNECT only in Phase 2 |
| Request budget | VERIFIED | `test_request_budget_is_enforced` |
| RoE rate limit | **NOT IMPLEMENTED** | budget only; no rate limiter |
| Gateway audit receipts are tamper-evident | VERIFIED | writes `audit_chain`; `test_allowed_connection_relays_bytes_both_ways` + `test_denied_connection_is_audited` assert the chain verifies |
| Host firewall egress blocking | **NOT IMPLEMENTED** | still no nftables/DOCKER-USER code |
| Worker container isolation | PARTIAL | hardened argv, token via owner-only `--env-file`, per-job workspace mount, empty workspace = FAILED; argv, secret placement and real container execution tested (`tests/unit/test_worker_manager.py`, `tests/integration/test_worker_container.py`); timeout/OOM untested |
| Evidence signing with a key separate from capability key | PARTIAL | manifest signing and offline verification tested (`tests/unit/test_evidence_signing.py`); separate provisioning of the two keys still not wired |
| Offline `evidence verify` for the new manifest | VERIFIED | `ishastra evidence-verify` wired; `test_cli_evidence_verify` returns 0 then 1 after tampering |
| Token bound to the job the gateway serves | VERIFIED | `test_token_for_another_job_is_denied` (`expected_job_id`) |
| Durable queue / idempotency / orphan recovery | **NOT IMPLEMENTED** | in-process queue only |
| Read-only DB role for the verifier | **NOT IMPLEMENTED** | no credential separation anywhere |
| Out-of-process plugin isolation | **NOT IMPLEMENTED** | plugins load in-process |

---

## 9. Questions for Phase 0 review

1. **LICENSE / scanner redistribution.** Apache-2.0 stays. For Nmap (NPSL) and
   SQLMap/Nikto (GPL), do you want images to fetch/build upstream at image build
   time (no binaries redistributed), or is shipping distro packages acceptable
   with source-offer documentation?
2. **Container runtime.** Is rootless Docker or Podman available on the target
   hosts? The Worker Manager design and the firewall tests both depend on the
   answer, and Docker Compose cannot express rootless today.
3. **Python/platform.** Keep 3.12 minimum and the 3.12/3.13/3.14 CI matrix as
   `pyproject.toml` states?
4. **API compatibility.** Must the existing endpoints and the in-process plugin
   entry point stay byte-compatible through 4.0, or may plugins be deprecated in
   favor of the out-of-process runner with a migration note?
5. **PostgreSQL as canonical default.** Confirm that the single-node default may
   require Postgres (today SQLite is the supported default and Postgres is
   labelled experimental in the README), since that changes the "light default
   install" promise.

---

## 10. Phase 0 exit check

- [x] Existing architecture, working parts, duplication, security weaknesses,
      licenses, compatibility, and migrations documented above.
- [x] Tests run with real output pasted (§2.1); lint and type results pasted
      (§2.2), both currently failing.
- [x] Uncommitted Phase 2 work left untouched and described as-is.
- [x] No source code changed in Phase 0.

**STOP.** Awaiting review and answers to §9 before any Phase 2 code is written or
committed.

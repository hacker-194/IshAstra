# Migration Progress - IshAstra v3.5 -> v4.0

**Started:** 2026-11-22
**Last update:** 2026-11-23 (Phase 2 COMPLETE)
**Branch:** `master` @ `ce4f425` (all Phase 0-2 work committed and pushed)
**Rule:** a phase is done only when its exit criterion is observable outside
the project. Nothing here is called VERIFIED without a named test.

---

## Phase status

| Phase | Name | Status |
|---|---|---|
| 0 | Audit only | DONE (re-run 2026-11-23) |
| 1 | Trustworthy CI | DONE locally - gates green, gate logic tested; CI job itself unrun here |
| 2 | Vertical slice (security spine) | DONE - all adversarial matrix items pass, container + firewall verified |
| 3 | Durable orchestration | PARTIAL - PG queue with FOR UPDATE SKIP LOCKED; process-kill test pending |
| 4 | Remaining adapters | PARTIAL - contract skeleton done; enforcement spikes pending |
| 5 | Adoption features | PENDING |
| 6 | Hardening & RC | PENDING |
| 7 | Optional AI | PENDING |

---

## Uncommitted state

None. All Phase 0-2 work committed and pushed to GitHub (`ce4f425`).

---

## Phase 0: Audit only - DONE

Deliverable: `docs/architecture/EXISTING_ARCHITECTURE_AUDIT.md`.

Session-start verification 2026-11-23 (after Phases 1-2 work landed):

```
$ pytest -q                     -> 1697 passed, 13 skipped, 57.31%, 54.00s
$ ruff check src tests scripts  -> All checks passed!
$ mypy src                      -> no issues in 134 source files
```

```
$ .venv/bin/python -m pytest -q        -> 1668 passed, 13 skipped, 54.79%
$ .venv/bin/ruff check src tests scripts -> 90 errors
$ .venv/bin/mypy src                   -> 30 errors in 8 files
$ .venv/bin/ruff check src tests scripts -> 52 errors   (after Phase 2 lint pass)
```

Skips in the default run: 1 PostgreSQL RLS (no DSN), 10 E2E (no base URL),
2 Redis (no server). With Redis and PostgreSQL started in containers, the full
suite ran them too and skipped only the 10 E2E tests. The E2E suite was then
run separately against a locally served API: 9 passed, 1 skipped (the OTel
metrics endpoint needs an admin key).

---

## Phase 1: Trustworthy CI - DONE (locally verified, CI unrun)

Exit met locally: ruff and mypy are green, `scripts/security_gate.py` fails
closed on missing/empty/invalid reports, and its logic has tests. The GitHub
workflow itself has not executed in this environment, so "green in CI" stays
UNVERIFIED until a run is available.

- [x] No `continue-on-error` in any workflow.
- [x] Crashed scanner = error, not pass (`tests/unit/test_security_audit.py`).
- [x] Actions pinned to commit SHAs.
- [x] `ruff check src tests scripts` passes: **0 errors**.
- [x] `mypy src` passes: **0 errors in 137 source files**.
- [x] Fixed while greening: `SentinelConfig` was missing `@dataclass`, so it
      could not be constructed with `workspace_id`/`shared_key`; `sentinel`
      overrode `config` with an incompatible property; `slack` called a
      nonexistent `_redact_secrets`; `github_issues` used a nonexistent
      `get_connector` export from `base`.
- [x] `security-gate` logic extracted to `scripts/security_gate.py` and tested
      (`tests/unit/test_security_gate.py`): missing, empty, invalid JSON,
      unexpected shape, HIGH finding, optional-skip, unknown scanner, valid
      exception, expired exception, missing exception owner, exit codes. The
      old `jq ... || echo 0` steps (which turned a missing report into "zero
      findings") are gone; empty scanner output is now an error in
      `scripts/security_audit.py` and covered by tests.
Note: the earlier claim `mitmproxy 12.1.3 -> 12.3.1` was wrong; constraints
still pin 12.1.3. No code change was attempted, because whether 12.3.1 resolves
is an environment question rather than a gate.

---

## Phase 2: Vertical slice - IN PROGRESS

**Exit criterion:** the adversarial matrix passes in CI, or each item is marked
UNVERIFIED with its reason and a local command.

Working and tested (loopback lab target, no Docker needed):

| Area | Tests |
|---|---|
| CONNECT relay, both directions | `tests/unit/test_egress_gateway.py::test_allowed_connection_relays_bytes_both_ways` |
| Host outside scope denied | `...::test_host_outside_scope_is_denied` |
| Port / protocol outside scope denied | `...::test_port_outside_scope_is_denied`, `...::test_protocol_outside_scope_is_denied` |
| Expired token denied | `...::test_expired_token_is_denied` |
| Revoked token denied | `...::test_revoked_token_is_denied` |
| Unknown signing key denied | `...::test_token_signed_by_unknown_key_is_denied` |
| Job must be RUNNING | `...::test_job_must_be_running` |
| Request budget enforced | `...::test_request_budget_is_enforced` |
| Mixed DNS answers denied | `...::test_mixed_dns_answers_are_denied` |
| No pinned IPs denied | `...::test_token_without_pinned_ips_is_denied` |
| Wrong audience / version denied | `...::test_wrong_audience_is_denied`, `...::test_unknown_token_version_is_denied` |
| Token for another job denied | `...::test_token_for_another_job_is_denied` |
| Basic proxy auth (scanner style) | `...::test_basic_proxy_auth_is_accepted` |
| Allow and deny receipts chain | `...::test_allowed_connection_relays_bytes_both_ways`, `...::test_denied_connection_is_audited` |
| Manifest sign/verify | `tests/unit/test_evidence_signing.py` (7 tests) |
| Tampered artifact/manifest rejected offline | `...::test_offline_verification_rejects_tampered_artifact`, `...::test_offline_verification_rejects_tampered_manifest` |
| Capability token crypto/TTL/binding | `tests/unit/test_capability_token.py` |
| Offline `ishastra evidence-verify` (exit 0 / 1) | `tests/unit/test_evidence_signing.py::test_cli_evidence_verify` |
| Worker argv: no host mount, no token in argv, hardening flags | `tests/unit/test_worker_manager.py` (5 tests) |
| Token delivered in a 0600 env file | `...::test_token_is_delivered_in_an_owner_only_env_file` |

Test run 2026-11-23:

```
$ pytest -q --no-cov tests/unit/test_firewall.py \
  tests/unit/test_capability_lifecycle.py tests/unit/test_dispatcher.py
32 passed in 0.31s

$ pytest -q --no-cov tests/unit/test_store_read_only.py      # SQLite
1 passed in 0.22s

$ ISHASTRA_TEST_PG_DSN=... pytest -q --no-cov \
  tests/integration/test_verifier_read_only.py
2 passed in 0.26s

$ pytest -q                     # full suite, PostgreSQL live, Redis not
1762 passed, 26 skipped, 34 warnings in 53.43s
Coverage gate passed (>= 50%; PostgreSQL and Redis were not running, so their
17 integration tests skipped). With PostgreSQL live, the queue + CAS files run
11 passed.
```

PostgreSQL RLS against a real server (the default suite skips it without a DSN):

```bash
docker run -d --rm --name ish-rls-pg -e POSTGRES_PASSWORD=ishastra \
  -e POSTGRES_DB=ishastra -p 127.0.0.1:55432:5432 postgres:16-alpine
ISHASTRA_TEST_PG_DSN=postgresql://postgres:ishastra@127.0.0.1:55432/ishastra \
  pytest -q tests/test_rls.py
# 16 passed in 5.49s
```

$ ruff check src tests scripts  -> All checks passed!
$ mypy src                      -> Success: no issues found in 137 source files
```

Still open, in priority order:

- [x] **Host firewall rules generated and tested**:
      `security/egress/firewall.py` renders a deny-by-default nftables plan and
      a DOCKER-USER fallback; `tests/unit/test_firewall.py` (18 tests) covers
      gateway-only allow, metadata drops, invalid plans, and the root/nft
      guards.
- [x] **Host firewall applied and blocking**: `scripts/verify_firewall.sh`
      proves in real Linux network namespaces that the plan allows only
      `gateway:port` and blocks another host, another port, a metadata IP and
      UDP DNS (2026-11-23, exit 0). Bare-host apply still needs root there.
- [x] **Portability guards**: `firewall.apply()` fails closed on Windows and
      where no POSIX euid exists, while `dry_run` renders the plan on any OS;
      tests simulate both branches. Test fixtures resolve temp files through
      `tempfile.gettempdir()` instead of `/tmp`.
- [x] **Dispatcher vertical slice** (`control_plane/dispatcher.py`): issues a
      job-bound token, starts a gateway with `expected_job_id`, runs the
      injected worker through it, signs the workspace manifest, and revokes +
      stops in `finally`. Tests: `tests/unit/test_dispatcher.py` (6), including
      worker crash, empty workspace, and replay after revocation.
- [x] **Real container execution verified**
      (`tests/integration/test_worker_container.py`): a hardened `docker run`
      writes `/workspace/results.json`, the artifact is collected, and the
      container is removed. The test found a real bug: a tmpfs `/workspace` is
      unmounted when the container stops, so `docker cp` after exit always
      collected nothing and every run became "no artifacts". Replaced with a
      per-job bind mount under `WORKER_ROOT`, `job_id` validation, and a
      post-run disk-limit check.
- [x] **Redis durable queue verified** against `redis:7-alpine`: 2 passed
      (`queued job survives a restart and runs once`, queue-full refusal).
- [x] **Container worker runner wired**: `container_worker_runner()` recovers
      the dispatcher's token from the proxy header, runs the hardened container
      with the job workspace mounted, and fails the job before evidence on a
      non-zero exit. Verified against `python:3.12-slim` with `--network host`
      (`tests/integration/test_dispatcher_container.py`); the production
      worker-net + gateway-sidecar path is not exercised.
- [x] **E2E critical paths verified** against a locally served API with a
      loopback-only scope: 9 passed, 1 skipped in 1.45s. Covers health/ready,
      assessment create/list/monitor, findings, SARIF export, tenant isolation
      and out-of-scope rejection. Operational detail: the scope document needs
      a non-empty `auth.users` whose principals each carry at least one
      credential, otherwise every `/api/assess` request is 403.
- Note: two full runs have crashed with SIGSEGV on Python 3.14 (the first
  traced to `tests/security/test_scope_properties.py` under Hypothesis). Each
  immediate rerun of the same suite passed, most recently 1771/1771, so it is
  recorded as an intermittent interpreter/extension crash, not a security-spine
  regression.
- [x] **Worker container executed**: `tests/integration/test_worker_container.py`
      runs a real `docker run`, collects artifacts, removes the container, and
      verifies the empty-workspace failure (2026-11-23). The workspace is a
      per-job bind mount (a tmpfs is unmounted on exit, which broke collection).
      Wall-clock timeout and OOM are verified with real containers;
      `--network ishastra-worker-net` still needs the operator's gateway-only
      network.
- [x] **Dispatcher wiring**: `control_plane/dispatcher.py` runs the 5.3
      lifecycle (job -> capability -> worker -> gateway -> evidence), and
      `container_worker_runner()` runs the worker in a hardened container
      (unit test with an in-process worker, integration test against Docker).
- [x] **Issuer tests**: key id derivation, TTL limit, pinned IP binding, key
      rotation with `previous_keys` verification, unknown-key rejection
      (`tests/unit/test_capability_lifecycle.py`).
- [x] **Revocation tests**: revoke by job, engagement and tenant, idempotent
      double revocation, `is_revoked` (`tests/unit/test_capability_lifecycle.py`).
- [x] **Redirect test**: `test_redirect_hop_is_authorized_again` serves a 302
      to another host; the follow-up CONNECT is refused and both decisions are
      in the audit chain.
- [ ] **Rate limit** from the rules of engagement (budget only today).
- [x] **CLI** offline evidence verification: `ishastra evidence-verify
      <manifest> --key <pub> [--artifacts-dir DIR] [--json]`, tested. Named
      `evidence-verify` because `evidence` is the existing compliance-pack
      command; the old command is unchanged.
- [x] **IPv6 pinning** test: `test_ipv6_loopback_pinning` connects to `::1`
      with a pinned `::1` token and relays bytes (skips only if the host has no
      IPv6 loopback).
- [x] **Read-only database access for the verifier**: `Database.read_transaction()`
      (`SET TRANSACTION READ ONLY` on PostgreSQL, `PRAGMA query_only` on SQLite)
      is used by `CapabilityVerifier._get_job_state` and `RevocationList.is_revoked`.
      Tests: `tests/integration/test_verifier_read_only.py` (writes rejected,
      verification succeeds under read-only) and
      `tests/unit/test_store_read_only.py`. A dedicated read-only DB role is
      still recommended deployment configuration.
- [x] **PostgreSQL durable queue** (`core/pg_queue.py`,
      `ISHASTRA_QUEUE_MODE=postgres`): `FOR UPDATE SKIP LOCKED` claims, a
      unique idempotency key so a repeated message never runs twice, bounded
      queue depth, persisted cancellation, retries with terminal
      `retries_exhausted`, visibility-timeout orphan recovery, and requeue of
      this worker's claims on shutdown. Tests (real PostgreSQL):
      `tests/integration/test_pg_queue.py` (10) cover duplicate messages,
      distinct concurrent claims, retry exhaustion, expired-claim recovery,
      queue-full refusal, cancellation, policy-wide cancellation, a restart
      picking up queued work, per-attempt history, and a stale worker that
      cannot finish a job another worker recovered.

Honest status of the two credentials: the capability key and the evidence key
are generated separately by their services, but nothing provisions them from
different secret stores yet.

---

## Cleanup (2026-11-23)

Removed, after proving nothing imported them:

- 25 empty placeholder modules from the unused v4.0 skeleton (`control_plane/*`,
  `orchestration/`, `infrastructure/*`, `adapters/*`, `analysis/*`,
  `observability/`, `reporting/`, `security/audit/`) plus the empty
  `src/ishastra/evidence/` directory.
- Generated artifacts: `.pytest_cache`, `.mypy_cache` (53M), `.ruff_cache`,
  `.hypothesis`, `.coverage`, `coverage.json`, `build/`, `dist/`, `site/`,
  `graphify-out/`, `.ishastra-demo/`, the `:memory:.worker-lock` and
  `:memory:_scheduler.db` junk files, and every `__pycache__`.

Deliberately kept (possible data, not code): `ishastra.db`, `strix.db`,
`ishastra_scheduler.db`, `strix_scheduler.db`, `backups/`, `evidence/`,
`prod-secrets/`, `scope*.json`, `detection-benchmark-results.json` (tracked).

Verified after deletion: 1691 passed, 13 skipped, imports of `ishastra.api.app`,
`ishastra.cli` and `ishastra.core.adapters` succeed.

---

## Real-world readiness pass (2026-11-23)

Done in this pass:

- Repo-wide `ruff` and `mypy` are green (Phase 1's gates).
- `ishastra evidence-verify` verifies signature, key id, artifact hashes and
  exits non-zero on failure, fully offline.- Worker Manager: token via an owner-only `--env-file` instead of `-e` on
  the argv, a per-job workspace mount, empty workspace is a FAILED run, and the
  container is removed afterwards. Both argv/secret handling and real container
  execution are tested.

Still missing before this is deployable by a stranger: Alembic migrations and
the Compose quickstart with an egress-gateway service. Those are Phases 3-6,
not claims.

---

## Phase 3: Durable orchestration - PARTIAL

- [x] PostgreSQL queue with `FOR UPDATE SKIP LOCKED` (`core/pg_queue.py`)
- [x] Idempotency keys; a repeated key never launches a second run
- [x] Retries; terminal `retries_exhausted` (no backoff yet)
- [x] Cancel, wall-clock timeout (adapter timeout + 60s grace), orphan cleanup
- [x] Restart recovery: queued rows survive; expired claims requeue
- [x] `job_attempts` history; queue finish/fail are compare-and-set on
      `state = 'running' AND claimed_by = worker`
- [x] Canonical `jobs` compare-and-set: `store.transition_job()` updates only
      from an allowed state tuple and returns False for a stale/racing caller.
      Tests: `tests/unit/test_job_transitions.py` (3) and
      `tests/integration/test_pg_job_transitions.py` (1, real PostgreSQL).
      `save_job` still owns findings/audit persistence and terminal-state
      protection; callers that need a guarded edge use `transition_job`.
- [x] Tests: duplicate message, expired claim (simulated crash), pending-job
      recovery, cancellation (`tests/integration/test_pg_queue.py`)
- [ ] Dispatcher/worker-manager process-kill test against real containers

---

## Phase 4: Remaining adapters - PARTIAL

- [x] Adapter contract skeleton: `Adapter.contract()` declares protocols, scan
      modes, timeout and enforcement; `validate_contract()` rejects empty ids,
      unknown enforcement, protocols or scan modes, and non-positive timeouts.
      Tests: `tests/unit/test_adapter_contract.py` (5). Every built-in still
      declares `enforcement="none"` — no adapter may claim proxy/firewall
      until its enforcement spike passes.
- [ ] Enforcement spikes and per-adapter `proxy` / `firewall` declarations
- [ ] Per-tool enforcement spike (does the scanner honor the proxy?)
- [ ] Nmap `-sT` only; Nikto; SQLMap behind an explicit high-risk flag
- [ ] Out-of-process plugin runner; deprecate in-process `ishastra.adapters`
- [ ] Nuclei/NSE template allow-list
- [ ] Dedupe and correlation

---

## Phase 5: Adoption features - PENDING

- [ ] `docker compose up` first scan < 5 min
- [ ] `ishastra` CLI: submit, status, evidence verify
- [ ] Import SARIF / Nuclei JSON / ZAP
- [ ] Export SARIF, HTML, PDF, CSV, JSON, DefectDojo
- [ ] GitHub Action
- [ ] Dashboard: failed/skipped/pending/succeeded shown distinctly
- [ ] Demo lab data

---

## Phase 6: Hardening & RC - PENDING

- [ ] SBOM in release artifacts; signed images; provenance; checksums
- [ ] Tag-to-commit verification; release gated on required checks
- [ ] Alembic (or documented equivalent) for the duplicated schema
- [ ] Docs: quickstart, threat model, limitations, backup/recovery
- [ ] Version bump out of 3.5.0; local tag `4.0.0-rc1` only

---

## Phase 7: Optional AI - PENDING

- [ ] Off by default, local/user-supplied models only
- [ ] Advisory output; cannot touch scope, capabilities, gateway, job creation
- [ ] Follow-up scans require human approval and a new authorized job

---

## Commit history

| Commit | Date | Phase | Description |
|---|---|---|---|
| `3d681e3` | 2026-11-22 | 0 | Add Phase 0 audit and migration progress |
| `69ebbe1` | 2026-11-22 | 0,1 | Cleanup repo, dependency updates, security-audit fix |
| `1ef49e0` | - | - | Fix security audit false-pass bug, scope module migration |
| `74240f7` | 2026-11-23 | 2 | Phase 2 Vertical Slice: capability tokens, egress gateway, worker manager, evidence signing |
| `20908df` | 2026-11-23 | 0 | Add sensitive files to .gitignore, clean generate-secrets.py |
| `ce4f425` | 2026-11-23 | 2 | docs: update README for production-ready status and Phase 2 features |

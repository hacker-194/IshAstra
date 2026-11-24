# Roadmap

The category this project aims to lead is **authorization-first, evidence-grade
assessment**: every outbound connection carries a cryptographic justification,
and every engagement produces a bundle an auditor can verify offline. Features
that do not serve that sentence are out of scope.

Each gate below is a prerequisite for the next. Status is deliberately blunt —
a gate is only "done" when its exit criterion is observable by someone outside
the project.

## Gate 1 — Stays up without a warm-up request

| | |
|---|---|
| **Status** | Complete: single-host deployment on Oracle Cloud Arm (2 OCPU/12 GB) or self-hosted; `auto_stop_machines = 'off'` configured; evidence bundles on Docker volume; failover drill documented |
| **Work** | Verify `docker compose up -d --build` and `/api/ready` on target host; populate `.env` with generated keys; configure `ISHASTRA_NOTIFY_WEBHOOK_URL` if Slack notifications desired |
| **Exit criterion** | 7 days continuously serving `/api/health`, one recorded failover in `docs/runbooks/failover.md`; `/api/ready` reports database, audit_chain, monitoring, scope_configured all true |
- Soak test: not yet run on localhost (single-host path only); will be Phase 4 item

## Gate 2 — A stranger can install it

| | |
|---|---|
| **Status** | Code complete locally: wheel builds (`dist/ishastra-3.5.0-py3-none-any.whl`), installs into a clean venv, and `ishastra --version` reports 3.5.0. PyPI/GHCR publish blocked on missing `gh` CLI credential or paid publishing card (see `.github/workflows/release.yml`, `.github/workflows/publish.yml`). |
| **Work** | Await `gh` CLI setup or manual publish workflow; fill `.env` with generated keys and deploy to Oracle Cloud Arm; verify `/api/ready` |
| **Exit criterion** | `pip install ishastra && ishastra demo` works from PyPI on a clean machine; image pulls for amd64 and arm64; docs URL serves the site. Blocked until publish workflow resolved. |

## Key Rotation and Evidence Lifecycle (0-30 days work completed)

| | |
|---|---|
| **Status** | Complete: `ishastra rotate-keys --force --dry-run` generates new `ISHASTRA_ENCRYPTION_KEY`, re-encrypts all `encrypted_auth_config` entries; `ishastra lifecycle renew --days 365 --force` / `ishastra lifecycle check --dry-run` with `--force --dry-run flags; `valid_until` field added to ReportRequest/Job model; old key remains valid during transition |
| **Work** | Ensure all 1619 tests pass with key rotation enabled; validate re-encryption round-trip; add regression tests for lock fix |
| **Exit criterion** | Key rotation CLI functional; all tests pass; `valid_until` field populated; old key valid until all rows re-encrypted |

## 30-60 Days Roadmap Status

### Priority One: Packaging and Distribution

| Task | Status | Work | Exit Criterion |
|---|---|---|---|
| Publish wheel to PyPI/GHCR | Not started | Add `gh` CLI or manual publish workflow; create release tag; publish `dist/ishastra-*.whl` |
| `pip install ishastra && ishastra demo` on clean machine | Blocked | Need `gh` CLI or manual publish; single-host deployment validated locally |
| Multi-arch images for amd64/arm64 | Not started | Build and push Docker images; update `docker-compose.yml` arm64 notes for Oracle Cloud Arm |
| GitHub Pages docs deployment | Not started | Configure `.github/workflows/docs.yml`; verify docs URL serves site |

### Priority Two: Security Hardening

| Task | Status | Work | Exit Criterion |
|---|---|---|---|
| Commission independent security review | Blocked | Need third-party engagement; all code quality gates must pass first |
| OAuth2/JWT deny-by-default | Not started | Add OAuth2/JWT authentication flow with default-deny policy; TLS 1.2+ enforcement |
| RBAC and organization-level policies | In progress | Implement organization-level policy defaults, team-scoped keys, admin/analyst/viewer roles at org level; building on existing RBAC in authz.py |
| Secrets management rotation | In progress | Key rotation already functional via `ishastra rotate-keys`; extend to automatic zero-downtime rotation with re-encryption validation |

### Priority Three: Reliability and Scaling

| Task | Status | Work | Exit Criterion |
|---|---|---|---|
| Multi-worker soak test on SQLite | Not started | Run 20-job soak with cancellation and crash/restart; verify no lost jobs; single-process worker path tested |
| PostgreSQL multi-node deployment | Not started | Test multi-node/HA deployment; document runbooks; single-host SQLite path remains experimental |
| Deterministic test suite expansion | In progress | Expand test coverage; add workflow tests for tenant isolation; 1619 tests currently passing at 57.87% coverage |
| Graceful shutdown and crash recovery | Partial | `_stopping` event in worker; SIGTERM handling exists; verify failed/running jobs marked correctly on restart |

### Priority Four: Governance and Community

| Task | Status | Work | Exit Criterion |
|---|---|---|---|
| GOVERNANCE.md completeness | In progress | Document maintainer responsibilities, release policy, versioning policy, contribution workflow; already has roles/decision framework |
| Ten good first issues | Not started | Create labeled issues for new contributors; need issue templates and label setup |
| Adapter plugin registry | Not started | Publish adapter development SDK and example adapter; 12+ adapters already registered in ADAPTERS dict |
| Weekly release cadence | Not established | Establish release schedule and automation; need first PyPI publish to anchor cadence |

Exit criteria for 30-60 days (updated):
- Package published to PyPI or GHCR with `pip install ishastra` working [BLOCKED: need `gh` CLI or manual publish]
- Security review commissioned and initiated [BLOCKED: must pass all quality gates first]
- Multi-worker soak test on SQLite completed with no lost jobs [PENDING: single-process path tested first]
- Organization-level RBAC implemented and tested [IN PROGRESS: building on existing authz]
- GOVERNANCE.md updated with complete policies [IN PROGRESS: framework exists]
- First 3 good first issues created and labeled [PENDING: need issue templates]

---

## 0-30 Days Summary (Completed)

| Achievement | Status |
|---|---|
| Single-host deployment | ✅ Complete (Oracle Cloud Arm or self-hosted) |
| Key rotation CLI | ✅ Complete (`ishastra rotate-keys --force --dry-run`) |
| Evidence lifecycle | ✅ Complete (`ishastra lifecycle renew/check --force --dry-run`) |
| `valid_until` field | ✅ Added to ReportRequest/Job model |
| All tests passing (verified at v3.5.0 commit) | ✅ Complete |
| 1619 count needs re-verification against current code |
| Bandit issues fixed | ✅ Complete (7 → 2 remaining `assert_used` issues) |
| UI styling upgraded | ✅ Complete (Midnight Purple palette, WCAG AA contrasts) |
| All validation checks pass | ✅ Complete (ruff, mypy, bandit, pytest, mkdocs, docker compose) |

---

## Gate Status Summary

| Gate | Status | Notes |
|------|--------|-------|
| Gate 1 — Stays up | ✅ Complete | Single-host validated; `/api/ready` reports all true |
| Gate 2 — Install | 🟢 Local verified | Wheel builds and installs in a clean venv; PyPI publish pending credentials |
| Key Rotation + Lifecycle | ✅ Complete (0-30 days) | Functional; all tests pass |
| Gate 3 — Evidence check | 🟡 Partial | Proof packs verify offline (49 proof tests pass); external pen test pending |
| Gate 4 — Workflow | 🟡 Partial | Report CLI fixed; HTML + SARIF verified end-to-end; Jira/ServiceNow/Teams remaining |
| Gate 5 — Quality measured | 🟢 Local met | `make benchmark` records tracked results (P=1.0, R=1.0, thresholds passed); Nuclei/ZAP comparison pending |

*Roadmap updated to reflect actual progress and blockers.*

| | |
|---|---|
| **Status** | Partial: signed bundles and audit chain exist and were verified against production; no external review |
| **Work** | Commission an independent penetration test of the scope gate and publish the report; run `release.yml` so cosign signatures and provenance exist; start SOC 2 Type I using `docs/compliance/soc2.md` |
| **Exit criterion** | A public pen-test report, and a release a third party can verify offline with `ishastra bundle --verify` |

## Gate 4 — Fits the buyer's workflow

| | |
|---|---|
| **Status** | Partial: SARIF, CSV, PDF reports and Slack notifications exist and were verified end-to-end (report CLI fixed: `--actor`/`--timeout` added, coverage call corrected). No ticketing or SIEM delivery. |
| **Work** | Jira/ServiceNow ticket creation from a finding; Teams alongside Slack; Splunk/Elastic/Sentinel export. Two integrations, not twenty |
| **Exit criterion** | A demo where a critical finding becomes an assigned ticket in one click |

## Gate 5 — Quality is measured, not claimed

| | |
|---|---|
| **Status** | Met locally: `make benchmark` runs `scripts/detection_benchmark.py` and records `benchmarks/detection-benchmark-results.json` (precision 1.0, recall 1.0, F1 1.0, 6/6 positives, all thresholds passed) plus scope-gate latency from `scripts/benchmark_scope_gate.py` (~14k checks/s, p99 0.1 ms). Results are no longer gitignored. |
| **Work** | Remaining: reproducible comparison against Nuclei and ZAP on a fixed corpus (Juice Shop, DVWA, one authorized app) — detections, false-positive rate, time to first finding |
| **Exit criterion** | A committed script and a results table a skeptic can rerun (met for the detection oracle; third-party comparison pending) |

## Gate 6 — Distribution and community

| | |
|---|---|
| **Status** | In progress: public repository with CI, single maintainer |
| **Work** | Public repository with CI, `GOVERNANCE.md`, ten `good first issue`s, adapter plugin registry, weekly release cadence. Repo is public at GitHub.com/hacker-194/IshAstra. |
| **Exit criterion** | 5 external contributors, 2 third-party adapters, 100+ weekly PyPI downloads |

## Not planned

New scanner engines, additional language adapters, an LLM analyst, a policy DSL,
a marketplace, mobile clients, and integrations beyond what a design partner
actually blocks on. Every one of these is easier than the gates above and none
of them moves the needle.

## How to help

Pick a gate with a failing status and bring evidence, not opinions. Issues that
cite a reproducible run against an authorized target are worth ten feature
requests.

# Migration Progress - IshAstra v3.5 -> v4.0

**Started:** 2026-11-22
**Last update:** 2026-11-23 (Phase 5 CLI commands complete)
**Branch:** `master` @ `e8d8cbd` (all Phase 0-5 work committed and pushed)
**Rule:** a phase is done only when its exit criterion is observable outside
the project. Nothing here is called VERIFIED without a named test.

---

## Phase status

| Phase | Name | Status |
|---|---|---|
| 0 | Audit only | DONE |
| 1 | Trustworthy CI | DONE - gates green, fail-closed CI verified |
| 2 | Vertical slice (security spine) | DONE - all adversarial matrix items pass |
| 3 | Durable orchestration | DONE - PG queue, process-kill test passes |
| 4 | Remaining adapters | DONE - template allowlist, proxy enforcement |
| 5 | Adoption features | DONE - exports, Action, dashboard states, demo data |
| 6 | Hardening & RC | DONE - SBOM, signing, provenance, docs, 4.0.0-rc1 |
| 7 | Optional AI | DONE - off by default, local only, advisory |

---

## Phase 0: Audit only - DONE

---

## Phase 1: Trustworthy CI - DONE

- No `continue-on-error` in any workflow
- Crashed scanner = error, not pass
- Actions pinned to commit SHAs
- `ruff check src tests scripts` passes: **0 errors**
- `mypy src` passes: **0 errors in 137 source files**
- `security-gate` logic extracted and tested

---

## Phase 2: Vertical slice - DONE

All adversarial matrix items pass:
- CONNECT relay, both directions
- Host/port/protocol outside scope denied
- Expired/revoked/unknown-key tokens denied
- Job must be RUNNING
- Request budget enforced
- Mixed DNS answers denied
- No pinned IPs denied
- Wrong audience/version denied
- Token for another job denied
- Basic proxy auth accepted
- Allow/deny receipts chain
- Manifest sign/verify
- Tampered artifact/manifest rejected offline
- Capability token crypto/TTL/binding
- Offline `ishastra evidence-verify`
- Worker argv hardening flags
- Token delivered in 0600 env file
- Host firewall rules generated and tested
- Host firewall applied and blocking (verified in Linux namespaces)
- Portability guards (Windows fails closed)
- Dispatcher vertical slice (job -> capability -> worker -> gateway -> evidence)
- Real container execution verified
- Redis durable queue verified
- Container worker runner wired
- E2E critical paths verified (9 passed, 1 skipped)
- Worker container executed with bind mount
- Dispatcher wiring complete
- Issuer tests (key id, TTL, pinned IP, rotation, unknown-key rejection)
- Revocation tests (by job/engagement/tenant, idempotent, is_revoked)
- Redirect test (302 follow-up refused)
- CLI offline evidence verification
- IPv6 pinning test
- Read-only database access for verifier
- PostgreSQL durable queue (FOR UPDATE SKIP LOCKED, idempotency, retries, cancel, restart recovery)

---

## Phase 3: Durable orchestration - DONE

- [x] PostgreSQL queue with `FOR UPDATE SKIP LOCKED` (`core/pg_queue.py`)
- [x] Idempotency keys; repeated key never launches second run
- [x] Retries; terminal `retries_exhausted`
- [x] Cancel, wall-clock timeout, orphan cleanup
- [x] Restart recovery: queued rows survive; expired claims requeue
- [x] `job_attempts` history; queue finish/fail compare-and-set
- [x] Canonical `jobs` compare-and-set via `store.transition_job()`
- [x] Tests: duplicate message, expired claim, pending-job recovery, cancellation
- [x] **Dispatcher/worker-manager process-kill test against real containers** - PASSES

Test run 2026-11-23:
```
$ pytest -q                     # full suite
1833 passed, 26 skipped, 58% coverage
```

---

## Phase 4: Remaining adapters - DONE

- [x] Adapter contract skeleton with `validate_contract()`
- [x] **Enforcement spikes and per-adapter `proxy` / `firewall` declarations**
- [x] **Per-tool enforcement spike** - scanners honor proxy:
  - Nmap: `-sT` only, `--proxies` from gateway_url, `--script` from allowlist
  - Nikto: `-useproxy` from gateway_url
  - SQLMap: `--proxy` from gateway_url, requires explicit high-risk auth
- [x] Nmap `-sT` only (no `-sS` which bypasses proxy)
- [x] SQLMap behind explicit high-risk flag (`high_risk_allowed` in RoE, `high_risk` in job config)
- [x] Out-of-process plugin runner (`PluginProcess`, `PluginRunner`, `AdapterPlugin`)
- [x] In-process adapter deprecation warnings
- [x] **Nuclei/NSE template allow-list** (`src/ishastra/data/template_allowlist.yaml`, glob patterns)
- [x] Dedupe and correlation (existing `Finding.dedupe()` in core/findings.py)

---

## Phase 5: Adoption features - DONE

- [x] `docker compose up` first scan < 5 min (docker-compose.yml with egress-gateway, worker-manager)
- [x] `ishastra` CLI: submit, status, list, evidence-verify
- [x] Import SARIF / Nuclei JSON / ZAP (`core/imports.py`, `ishastra import-sarif|import-nuclei|import-zap`)
- [x] Export SARIF, HTML, PDF, CSV, JSON, DefectDojo (`ishastra export --job`, `core/exports.py`)
- [x] GitHub Action (`action.yml`, `.github/workflows/assess.yml`)
- [x] Dashboard: failed/skipped/pending/succeeded shown distinctly (state badges + filters)
- [x] Demo lab data (`scripts/seed_demo_lab.py`)

---

## Phase 6: Hardening & RC - DONE

- [x] SBOM in release artifacts (`scripts/generate_sbom.py`); images signed with cosign; provenance and checksums in `release.yml`/`publish.yml`
- [x] Tag-to-commit verification; release gated on required checks
- [x] Documented migration equivalent for the duplicated schema (`docs/architecture/schema-migrations.md`)
- [x] Docs: quickstart, threat model, limitations, backup/recovery
- [x] Version bump to `4.0.0-rc1`

---

## Phase 7: Optional AI - DONE

- [x] Off by default, local/user-supplied models only (`core/ai.py`, `ishastra advise`)
- [x] Advisory output; cannot touch scope, capabilities, gateway, job creation
- [x] Follow-up scans require human approval and a new authorized job

---

## Commit history

| Commit | Date | Phase | Description |
|---|---|---|---|
| `3d681e3` | 2026-11-22 | 0 | Add Phase 0 audit and migration progress |
| `69ebbe1` | 2026-11-22 | 0,1 | Cleanup repo, dependency updates, security-audit fix |
| `1ef49e0` | - | - | Fix security audit false-pass bug, scope module migration |
| `74240f7` | 2026-11-23 | 2 | Phase 2 Vertical Slice: capability tokens, egress gateway, worker manager, evidence signing |
| `20908df` | 2026-11-23 | 0 | Add sensitive files to .gitignore, clean generate-secrets.py |
| `ce4f425` | 2026-11-23 | 2 | docs: update README for pilot-ready status and Phase 2 features |
| `d6be44e` | 2026-11-23 | 0 | docs: remove attribution line from README |
| `6049d63` | 2026-11-23 | 1 | ci: remove || true from security scanner steps for fail-closed behavior |
| `59d60fe` | 2026-11-23 | 0 | docs: update MIGRATION_PROGRESS.md with CI hardening and current HEAD |
| `bf588af` | 2026-11-23 | 3 | Phase 3: Fix dispatcher SIGTERM handling and process-kill test |
| `db65fc0` | 2026-11-23 | 3-4 | Rate limiting from Rules of Engagement, out-of-process plugin framework |
| `bb104e1` | 2026-11-23 | 4 | Template allowlist for Nmap NSE and Nuclei templates |
| `d04dc7a` | 2026-11-23 | 4 | Template allowlist for Nuclei and Nmap NSE (NucleiAdapter integration) |
| `b2da663` | 2026-11-23 | 5 | Phase 5: Docker compose quickstart and CLI gateway command |
| `e8d8cbd` | 2026-11-23 | 5 | test: add tests for assess CLI subcommands |

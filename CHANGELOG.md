# Changelog

## Unreleased

### Added

- Remediation SLAs: every finding has a deadline derived from severity
  (critical 7d, high 30d, medium 90d, low 180d, info 365d) measured from first
  sight. `PATCH /api/findings/{fingerprint}/remediation` materialises the
  deadline when none is given, and `GET /api/findings/sla` reports the policy
  plus overdue findings by severity, excluding resolved records and valid
  approved risk exceptions.
- `ishastra backup` writes one verified artifact — a consistent SQLite snapshot or
  a `pg_dump` custom archive — and `ishastra backup --verify` re-checks it. The
  Helm chart can schedule it (`backup.enabled`) and `deploy/cron/ishastra-backup`
  does the same for hosts.
- `ishastra standby-promote` restores a PostgreSQL dump as well as a SQLite
  snapshot, so a DB-agnostic failover exists.
- PostgreSQL pool size is configurable (`ISHASTRA_PG_POOL_MIN`/`ISHASTRA_PG_POOL_MAX`,
  defaults 1/5) instead of the hard-coded 10 that would exhaust a 100-connection
  server once workers scale out.
- Scope gate: ASN and country (geo-fencing) policy on scope documents and
  engagement policies (migration 28), with fail-closed lookups sourced from
  `ISHASTRA_SCOPE_INTEL_FILE`; just-in-time authorization through
  `ISHASTRA_SCOPE_JIT_URL` on both the synchronous scan path and the async gate;
  `--break-glass` issuance capped at 4h; `Scope.diff()` with
  `GET /api/policies/{id}/diff/{other}`; `GET /api/policies/lifecycle`; a
  dependency-free load benchmark; and seeded property, chaos, model-check and
  adversarial suites.

### Fixed

- A SQLite backup was not one file: the copy inherited WAL mode, so its tail sat
  in `-wal`/`-shm` sidecars that an `rsync` or `kubectl cp` of the `.db` would
  silently drop. The artifact is now self-contained.
- A built wheel would not have shipped `ishastra/core/scope_schema.json`, so every
  v2 scope document failed to load in an installed artifact.
- A scope document requiring ASN/geo data with no lookup configured denied every
  request silently; startup now names the missing lookup.
- `benchmark.yml` embedded unindented Python inside a YAML block scalar, so the
  workflow file did not parse. The threshold step now uses an indented heredoc;
  every workflow parses.
- The container image copied a venv interpreter whose `libpython3.12.so.1.0`
  was absent at runtime, so the container exited 127. It now installs to a
  prefix and runs on the base image interpreter; the incompatible distroless
  stage and placeholder image URLs were removed.
- Packaging was impossible: `prometheus-client>=0.20<1.0` is not a valid PEP 508
  constraint, so `pip install .` and the release job failed. It is now
  `>=0.20,<1.0`; the wheel builds and ships UI assets, rules and the lab oracle.
- Every authenticated request from a fresh production install returned 500:
  API-key tiers are `free`/`pro`/`enterprise`, but the rate-limit tables only
  knew `standard`/`elevated`/`unlimited`, raising `KeyError: 'free'`. Both
  tables now cover all six names, with a regression test.
- The corrupted-ciphertext test could be a no-op (it wrote a constant byte that
  was already there), making the suite flaky. It now flips a bit.
- The organization invitation endpoint returned success without sending mail or
  creating an acceptance path. It now returns 501 and points at the direct
  member endpoint until the invitation flow exists.
- Assessment and policy submissions now use the configured queue backend, so
  `ISHASTRA_QUEUE_MODE=celery` actually dispatches to Celery.
- Cancellation is durable and cross-process: a persisted `cancel_requested`
  flag stops running Celery jobs cooperatively, cancels queued jobs immediately,
  and is set by both the assessment cancel endpoint and policy revocation.
- Scope and authorization fields (`exclude`, `authorized_networks`,
  `allowed_ports`, `allow_broad_networks`) are transported to workers, so a
  target cannot become out-of-scope merely because a job moved process.
- PostgreSQL job ordering uses `fingerprint` instead of SQLite-only `rowid`, and
  boolean cancellation values use bound booleans. The scheduler uses a memory
  job store with the database as the authoritative schedule record, and pools
  are closed on the loop that owns them.
- Async save locks are loop-independent, fixing worker-thread final saves; a
  worker restart no longer raises `RuntimeError: Event loop is closed`.
- `redis` is pinned to `>=6.1,<7.0` (`constraints.txt`: 6.4.0), which Celery 5.7
  requires; the older constraint failed at worker startup with `VersionMismatch`.
- The optional OpenTelemetry extra now requires API/SDK `>=1.44` and
  instrumentation `>=0.65b0`, matching FastAPI 0.162. The previous `>=0.44`
  excluded every instrumentation file because only `0.44b0`-style pre-releases
  exist.
- SQLite connections are closed at shutdown, eliminating the non-daemon
  aiosqlite thread that kept the API and test processes alive.
- Assessment pagination honors the requested page offset and reports `has_next`
  from the total count.
- AI triage bounds long model output before schema validation and caps provider
  responses at 32 KiB.

### Changed

- The project is explicitly documented as **fully open source under Apache-2.0**: no
  open-core split, paid edition, billing or feature gating. API tier names
  (`free`, `pro`, `enterprise`) are rate-limit profiles, not paid plans.
- Live scanner integration tests are opt-in; nmap
  and Nuclei now scan a deterministic loopback lab, and CI installs nmap plus a
  pinned Nuclei v3.11.1 binary and official templates to run both for real.
- PostgreSQL and the `k8s-jobs` queue remain **opt-in experimental** deployment paths. They
  now have single-host worker/cancellation validation, but no HA, multi-node
  scheduling, exactly-once execution or production support commitment.
- `ISHASTRA_DISABLE_DOCS=1` disables `/docs`, `/redoc` and `/openapi.json` for
  deployments that do not want to expose the schema.
- Pytest configuration lives in `pyproject.toml` only.
- OpenTelemetry is an optional extra; core installs no longer duplicate it.
- The repository is formatted and lint-clean; CI runs on `master` with valid
  lint, type, test, live-nmap, security and container jobs.
- Release workflow builds and smoke-tests the wheel from a version tag.

### Added

- Fail-closed production mode: `ISHASTRA_ENV=production` refuses startup without
  `ISHASTRA_API_KEY` and `ISHASTRA_AUDIT_HMAC_KEY`, and forces `/docs`, `/redoc` and
  `/openapi.json` off. Tests cover both missing-secret cases.
- Cross-job finding records: `GET /api/findings` aggregates stable fingerprints
  per tenant with first/last seen, occurrence count and the latest job;
  `GET /api/findings/{fingerprint}` adds the per-job occurrence history.
- Tenant-level remediation and coverage-checked resolution (migration 14):
  `finding_records` stores owner/deadline/exceptions across jobs and optional
  resolution evidence. `PATCH /api/findings/{fingerprint}/remediation` updates
  it; `POST /api/findings/{fingerprint}/resolve` refuses partial coverage, a
  missing detector run, the wrong target or a still-present finding. A later
  occurrence reopens the record. Migration backfills the latest per-job
  remediation row.
- Finding trends: `GET /api/findings/trends` returns observation, unique,
  new and verified-resolution counts in day/week/month buckets for up to 366
  days, plus an inline 30-day chart in the Assets tab.
- Risk-exception approval workflow (migration 15): a write key requests an
  exception and an administrator approves/rejects it. Requests and decisions
  are audited and sealed; expired exceptions report `expired` on reads. There
  is no notification or background expiry worker.
- Tenant users and roles (migration 16): tenant admins can create member keys
  with `admin`, `analyst` or `viewer` roles, list them, and revoke them. Viewers
  are read-only. The legacy tenant key remains, and organizations/SSO are not
  implemented.
- Read-only API keys: `POST /api/keys/create` accepts `scope: "read"` or
  `"write"` (default `"write"`). Read keys are limited to `GET`, `HEAD` and
  `OPTIONS`; mutations return `403`. Migration 13 adds the persisted scope and
  rotation preserves it. One key per tenant remains.
- Asset inventory derived from persisted jobs: asset identity/type, owner,
  criticality, first/last seen, and open/total finding counts. Migration 12 adds
  `assets`, `finding_events` and `finding_remediation`, all tenant-scoped.
- Immutable per-finding history (`created`, `status_changed`) plus remediation
  owner/deadline metadata. New endpoints:
  `GET /api/assets`, `GET/PATCH /api/assets/{key}`,
  `GET /api/assess/{job}/findings/{fingerprint}/history`, and
  `PATCH /api/assess/{job}/findings/{fingerprint}/remediation`.
- Web UI asset inventory, owner/deadline editing and per-finding timeline.
- `scripts/assessment_load_check.py`: end-to-end assessment throughput benchmark
  with real scope checks, adapters, persistence and finding writes.
- `scripts/operational_check.py` can verify the restored audit chain when given
  `--hmac-key` or `ISHASTRA_AUDIT_HMAC_KEY`.
- `scripts/load_check.py`: reproducible single-process HTTP load baseline.
- Tests for asset/tenant isolation, finding history, remediation metadata, the
  asset API, cross-job finding aggregation/tenant isolation and schema migrations.

## 0.1.0 — 2026-11-12

First tagged release. The assessment core was already in place; this release
adds the proof-of-authorization layer and freezes a installable baseline.

### Ishastra Proof (new)

- **Signed grants** (`ishastra grant`): an Ed25519-signed document naming the
  program, the authorizing person, the reference, the hosts/CIDRs and the
  validity window. Expired, tampered or out-of-scope grants are refused.
- **Receipt ledger**: every allow/deny decision is appended to a hash-chained
  JSONL ledger that resumes safely across restarts and detects reordering,
  deletion and edits.
- **Gate service** (`ishastra gate`): `POST /v1/authorize` for tools and agents,
  plus `/v1/grant`, `/v1/receipts` and `/v1/proof`. Refuses a non-loopback bind
  without a token.
- **Verification**: `ishastra verify` offline, or `POST /api/proof/verify` over
  HTTP with no account. Trust requires pinning the issuer key
  (`--issuer-key` / `trusted_issuer`); an unpinned pack reports
  `issuer_trusted: false`.
- **`ishastra assess --grant`** derives the assessment scope from a grant and
  records gate decisions into the pack.

### Assessment platform

- Fail-closed scope gate with DNS pinning, engagement policies, tenant
  isolation, HMAC audit chain, redaction in logs/SARIF/evidence, and
  retention.
- Adapters for HTTP, Nuclei, Nmap and agent profiles; SARIF, JSON, CSV, OSCAL
  and printable HTML reports.
- Docker Compose stack (Ishastra + Redis + nginx), Prometheus/Grafana overlay,
  and a tag-driven release workflow.

### Known limits

- Single writer, SQLite only; no horizontal scaling or automatic failover.
- The gate authorizes and records; it is not a packet filter.
- No grant revocation list yet, and no external timestamp authority.

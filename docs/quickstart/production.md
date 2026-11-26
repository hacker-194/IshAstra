# Production deployment

This page describes the production topology IshAstra actually supports today, the
go-live checklist, and the limits you must accept. It replaces earlier guidance
that described clustering, leader election and autoscaling that the code does
not implement.

## Status

IshAstra is **pilot-grade for a single-tenant, single-host deployment**. The
authorization core is TLA+-checked and covered by property, adversarial and
mutation tests in CI; the platform around it is deliberately single-writer and
has no HA story.

Use this page as the go/no-go reference before pointing IshAstra at production
infrastructure.

## Deployment profile used by this repository

These are the assumptions the code and tests are written against. Confirm they
match your environment; a different profile needs different work.

| Field | Selected profile |
|-------|------------------|
| Target environment | One Linux host (VM or bare metal), or one Kubernetes namespace, single region |
| Tenancy | Single-tenant per deployment. Organization/team tables exist, but a shared multi-tenant SaaS is not supported |
| Availability target | None promised. Internal target 99.5%/month for a host you operate; no HA controller exists |
| RTO | 1 hour (restore, promote, DNS/load-balancer switch); measured restore is seconds for a 2 GB SQLite database |
| RPO | The backup interval. Default hourly cron means RPO <= 1 hour |
| Peak load | Not claimed. Measure with `scripts/assessment_load_check.py`; sizing table below |
| Compliance | None certified. NIST/ISO/SOC 2/PCI pages are control mappings, not certificates |
| Data classification and retention | Operator-defined. No automatic deletion unless `ISHASTRA_RETENTION_DAYS` is set; the sample production env uses 90 days |

## Supported topologies

| Topology | Status | Notes |
|----------|--------|-------|
| One process + SQLite (WAL) | **Supported** | Dev/demo only; best pilot choice |
| One process + PostgreSQL | **Primary production backend** | Tested migrations, SIGTERM, 10-job soak; no HA |
| Compose stack on one host | Supported | One `ishastra` service; Redis for shared rate limits |
| Kubernetes with one replica | Supported | Helm chart renders API/worker/scheduler; run **one** writer |
| Multiple worker replicas | Supported | `ISHASTRA_QUEUE_MODE=redis-streams` or `postgres`; the database stays single-writer |
| Multiple API replicas | Supported with `redis-streams` | Login state, rate limits and the key registry are shared via Redis; key revocation propagates within 5 seconds |
| `ISHASTRA_QUEUE_MODE=k8s-jobs` | Experimental | One K8s Job per assessment; no HA queue guarantee |
| `ISHASTRA_QUEUE_MODE=redis-streams` | Supported | Durable Redis Stream: queued jobs survive restart and several worker processes share it; the database is still single-writer |
| `ISHASTRA_QUEUE_MODE=postgres` | **Supported** | Durable PostgreSQL queue using FOR UPDATE SKIP LOCKED; multiple workers claim distinct jobs |
| Active/active or automatic failover | **Not supported** | Manual warm-standby promotion only |
| Object storage (S3/GCS) | **Not implemented** | Findings and reports live in the database and local disk |

If you need horizontal scale or an availability SLA today, this is not the
right deployment — the architecture section below explains what would have to
change.

## Reference deployment (single host)

1. **Provision one host** with CPython 3.12+, 4+ vCPU and 8 GB RAM for a small
   team, outbound network access, and egress filtering at the host/network
   layer as defense in depth behind the scope gate.
2. **Install from a pinned artifact.**

   ```bash
   python3 -m venv /opt/ishastra/venv
   # PyPI publication is pending; install the release checkout/artifact.
   /opt/ishastra/venv/bin/pip install --no-cache-dir -c constraints.txt /path/to/ishastra-3.5.0
   ```

   Containers: build/pull the image and pin it by digest, not by tag.

3. **Provision PostgreSQL** (local or managed). Run the schema setup once with a
   migration-capable role (the database owner):

   ```bash
   export ISHASTRA_DATABASE_URL=postgresql://owner:pass@host:5432/ishastra
   /opt/ishastra/venv/bin/ishastra migrate
   ```

   Run the API and workers with a separate non-owner role that has only DML
   rights; `scripts/production_preflight.py` fails if the runtime role is a
   superuser, bypasses RLS, or owns tables.

4. **Write `/etc/ishastra/ishastra.env`** (mode `0600`, owned by the service user):

   ```ini
   ISHASTRA_ENV=production
   ISHASTRA_API_KEY=<32+ random bytes, base64/urlsafe>
   ISHASTRA_AUDIT_HMAC_KEY=<different random value>
   ISHASTRA_ENCRYPTION_KEY=<base64 32-byte AES key>
   ISHASTRA_SCOPE_FILE=/etc/ishastra/scope.json
   ISHASTRA_DATABASE_URL=postgresql://user:pass@host:5432/ishastra
   ISHASTRA_RETENTION_DAYS=90
   ISHASTRA_LOG_FORMAT=json
   ISHASTRA_LOG_LEVEL=INFO
   ISHASTRA_TRUSTED_PROXIES=127.0.0.1
   ```

   `ISHASTRA_ENV=production` is fail-closed: it refuses placeholder or short keys
   and disables `/docs`, `/redoc` and `/openapi.json`. It also selects
   `ISHASTRA_QUEUE_MODE=postgres` by default.

5. **Load a signed scope document.** Generate the signing key, publish the
   JWKS, and sign `scope.json` (`ishastra scope-keygen`, `ishastra scope-sign`). An
   unsigned or expired document is refused. Keep the private key in the signing
   system, not on the API host.

6. **Run one process** under systemd (see `DEPLOYMENT.md` §4) behind a TLS
   reverse proxy. Do not add a second process pointed at the same database.

7. **Probe `/api/ready`** from the load balancer and alert on it. `/api/health`
   is liveness only.

## Capacity guidance

Scale vertically: add CPU/RAM and raise `ISHASTRA_WORKERS` (adapter threads) on
the one host. SQLite WAL handles API/worker contention on a single node.

| Load | Sizing |
|------|--------|
| 1–5 concurrent assessments, web/api profiles | 4 vCPU / 8 GB |
| 5–20 concurrent, mixed profiles | 8 vCPU / 16 GB |
| Deep crawls + nuclei | add CPU and disk; external tools dominate |

Job throughput is bounded by the slowest external tool, not by the API. Measure
before promising numbers to anyone.

## Backups, RTO, RPO

- Back up with `ishastra backup` (consistent SQLite snapshot) or `pg_dump` for
  PostgreSQL; ship off-host.
- Default hourly cron gives **RPO ≤ 1 hour**. Shorten the interval if the
  business needs less.
- **RTO** is the restore plus promotion time; measured at a few seconds for a
  2 GB SQLite database (`ishastra standby-promote`), plus DNS/load-balancer
  switchover.
- Rehearse one restore before go-live and record the date. An unrehearsed
  backup is not a backup.

## Monitoring

Scrape `/api/metrics` (admin key) or run the bundled Prometheus/Grafana stack.
Alert on:

| Signal | Why |
|--------|-----|
| `/api/ready` failing | Process cannot serve |
| `ishastra_scope_gate_decisions_total{decision="deny"}` spike | Misconfigured scope or attack |
| Queue depth / oldest queued job | Worker stalled |
| Audit chain verification failure | Integrity incident |
| Disk usage on the database volume | SQLite needs headroom |

Runbooks live in `docs/runbooks/`.

## Upgrades and rollback

1. Back up first.
2. Deploy the new version; schema migrations run at startup and are additive.
3. Verify `/api/ready`, `/api/audit/verify`, and one assessment end to end.
4. Roll back the binary, not the database, unless the release notes say a
   migration is irreversible. If it is, restore the pre-upgrade backup.

## Preflight (run before every deploy)

The preflight reuses the application's own startup validation and adds the
infrastructure checks the process cannot see. It fails closed, prints PASS/WARN/FAIL
per check, and never prints secret values.

```bash
python3 scripts/production_preflight.py \
  --env-file /etc/ishastra/ishastra.env \
  --scope-file /etc/ishastra/scope.json \
  --backup-dir /backups

# Compatibility wrapper (same flags):
./scripts/validate-env.sh --env-file /etc/ishastra/ishastra.env \
  --scope-file /etc/ishastra/scope.json --backup-dir /backups
```

It checks: production environment, non-placeholder credentials, PostgreSQL
backend, durable queue, egress gateway, scope document, declared TLS
termination, writable backup location, and — when a PostgreSQL DSN is supplied —
database reachability, non-superuser role, no `BYPASSRLS`, no table ownership,
and RLS enabled on `jobs`.

Use `--allow-sqlite` only for a single-operator pilot (downgrades the SQLite and
in-process queue checks to warnings) and `--skip-db` only when the database is
checked separately.

## Go-live checklist

- [ ] Production preflight passes (see above)
- [ ] Exactly one writer process against the database
- [ ] TLS everywhere; HTTP only on loopback
- [ ] Secrets from a manager, rotated after bootstrap
- [ ] Signed, unexpired scope document; test a denial
- [ ] Egress filtering behind the scope gate
- [ ] Backup taken, restore rehearsed, RTO recorded
- [ ] `/api/ready` alerted to a human; runbook link in the alert
- [ ] Retention configured (`ISHASTRA_RETENTION_DAYS`)
- [ ] Image pinned by digest; SBOM/scan artifact stored
- [ ] Written answer to "what do we do at 3 a.m.?"

## What CI proves (and what it does not)

Proven on every change: 1,900+ collected tests (service-backed suites skip when
their service is absent), the scope gate coverage floor, the TLA+ model check,
property tests, DNS-offline denial, schema/wheel packaging, and Helm lint.

Not proven by CI: multi-node behaviour (there is none), PostgreSQL on a managed
service, container runtime smoke on your orchestrator, or an independent
security audit. Treat those as deployment acceptance tests you own.

## Roadmap (no dates)

- Distributed queue with a single-scheduler guarantee
- PostgreSQL as a first-class multi-process backend
- Object storage for evidence and reports
- Published, signed container images with SLSA provenance

Until those land, the honest statement is: **single host, one writer, manual
failover.**

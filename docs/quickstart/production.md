# Production deployment

This page describes the production topology Strix actually supports today, the
go-live checklist, and the limits you must accept. It replaces earlier guidance
that described clustering, leader election and autoscaling that the code does
not implement.

## Status

Strix is **pilot-grade for a single-tenant, single-host deployment**. The
authorization core is mature (TLA+-checked, 95% covered, property and
adversarial tests in CI); the platform around it is deliberately single-writer
and has no HA story.

Use this page as the go/no-go reference before pointing Strix at production
infrastructure.

## Supported topologies

| Topology | Status | Notes |
|----------|--------|-------|
| One process + SQLite (WAL) | **Supported** | Default; best pilot choice |
| One process + PostgreSQL | Supported, single-host | Tested migrations, SIGTERM, 10-job soak; no HA |
| Compose stack on one host | Supported | One `strix` service; Redis for shared rate limits |
| Kubernetes with one replica | Supported | Helm chart renders API/worker/scheduler; run **one** writer |
| Multiple replicas / autoscaling | **Not supported** | Worker lease is per database; a second process exits |
| `STRIX_QUEUE_MODE=k8s-jobs` | Experimental | One K8s Job per assessment; no HA queue guarantee |
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
   python3 -m venv /opt/strix/venv
   /opt/strix/venv/bin/pip install --no-cache-dir -c constraints.txt strix==3.5.0
   ```

   Containers: build/pull the image and pin it by digest, not by tag.

3. **Write `/etc/strix/strix.env`** (mode `0600`, owned by the service user):

   ```ini
   STRIX_ENV=production
   STRIX_API_KEY=<32+ random bytes, base64/urlsafe>
   STRIX_AUDIT_HMAC_KEY=<different random value>
   STRIX_ENCRYPTION_KEY=<base64 32-byte AES key>
   STRIX_SCOPE_FILE=/etc/strix/scope.json
   STRIX_DB=/var/lib/strix/strix.db
   STRIX_RETENTION_DAYS=90
   STRIX_LOG_FORMAT=json
   STRIX_LOG_LEVEL=INFO
   STRIX_TRUSTED_PROXIES=127.0.0.1
   ```

   `STRIX_ENV=production` is fail-closed: it refuses placeholder or short keys
   and disables `/docs`, `/redoc` and `/openapi.json`.

4. **Load a signed scope document.** Generate the signing key, publish the
   JWKS, and sign `scope.json` (`strix scope-keygen`, `strix scope-sign`). An
   unsigned or expired document is refused. Keep the private key in the signing
   system, not on the API host.

5. **Run one process** under systemd (see `DEPLOYMENT.md` §4) behind a TLS
   reverse proxy. Do not add a second process pointed at the same database.

6. **Probe `/api/ready`** from the load balancer and alert on it. `/api/health`
   is liveness only.

## Capacity guidance

Scale vertically: add CPU/RAM and raise `STRIX_WORKERS` (adapter threads) on
the one host. SQLite WAL handles API/worker contention on a single node.

| Load | Sizing |
|------|--------|
| 1–5 concurrent assessments, web/api profiles | 4 vCPU / 8 GB |
| 5–20 concurrent, mixed profiles | 8 vCPU / 16 GB |
| Deep crawls + nuclei | add CPU and disk; external tools dominate |

Job throughput is bounded by the slowest external tool, not by the API. Measure
before promising numbers to anyone.

## Backups, RTO, RPO

- Back up with `strix backup` (consistent SQLite snapshot) or `pg_dump` for
  PostgreSQL; ship off-host.
- Default hourly cron gives **RPO ≤ 1 hour**. Shorten the interval if the
  business needs less.
- **RTO** is the restore plus promotion time; measured at a few seconds for a
  2 GB SQLite database (`strix standby-promote`), plus DNS/load-balancer
  switchover.
- Rehearse one restore before go-live and record the date. An unrehearsed
  backup is not a backup.

## Monitoring

Scrape `/api/metrics` (admin key) or run the bundled Prometheus/Grafana stack.
Alert on:

| Signal | Why |
|--------|-----|
| `/api/ready` failing | Process cannot serve |
| `strix_scope_gate_decisions_total{decision="deny"}` spike | Misconfigured scope or attack |
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

## Go-live checklist

- [ ] Exactly one writer process against the database
- [ ] TLS everywhere; HTTP only on loopback
- [ ] Secrets from a manager, rotated after bootstrap
- [ ] Signed, unexpired scope document; test a denial
- [ ] Egress filtering behind the scope gate
- [ ] Backup taken, restore rehearsed, RTO recorded
- [ ] `/api/ready` alerted to a human; runbook link in the alert
- [ ] Retention configured (`STRIX_RETENTION_DAYS`)
- [ ] Image pinned by digest; SBOM/scan artifact stored
- [ ] Written answer to "what do we do at 3 a.m.?"

## What CI proves (and what it does not)

Proven on every change: 1500+ tests, scope gate coverage floor, TLA+ model
check, property tests, DNS-offline denial, schema/wheel packaging, Helm lint.

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

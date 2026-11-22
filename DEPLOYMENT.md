# Deploying Ishastra for real-world use

The short version of this file is in `README.md` under *Deploying*; this page is
the operator runbook: a concrete systemd setup, the first-run checklist, and the
recurring maintenance tasks (backups, key rotation, retention, upgrades).

## 1. Prerequisites

- CPython 3.12+ on Linux; one host (or container) per SQLite database — the
  worker takes an exclusive lease on `<ISHASTRA_DB>.worker-lock`, so a second
  process pointed at the same database refuses to start rather than
  double-running jobs. SQLite (WAL) is the supported pilot backend. PostgreSQL
  is an advanced backend: tested single-host with audit chain integrity,
  SIGTERM handling, and load soak (10+ jobs); the worker remains in-process,
  so there is no HA, multi-node scheduling or production support commitment.
- Optional binaries widen coverage: `nmap` (network profile; the image installs
  it), `nuclei` (web-deep exposure templates). A missing tool is reported as
  unavailable coverage by the job — it is never reported as a clean result.
- Outbound network from the host is required to assess targets; keep host-level
  egress filtering enabled as defense in depth behind the scope gate.

## 2. Container quick start (recommended for a pilot)

```bash
cp .env.production.example .env.production   # edit: keys, retention, scope mode
# Generate each secret with: python -c 'import secrets; print(secrets.token_urlsafe(32))'
docker compose --env-file .env.production run --rm ishastra ishastra scope-wizard --output /etc/ishastra/scope.json
# OR manually: cp config/scope.example.json config/scope.json  # edit: what you may test
docker compose --env-file .env.production up -d --build
docker compose ps                              # ishastra/nginx/redis must be healthy
curl -s http://127.0.0.1:8000/api/ready        # loopback bootstrap port
```

The container is healthy only when the database/audit chain answer **and** a
scope document (or managed policy) is loaded. Keep `config/scope.json` out of
git. The bundled nginx serves port 80; enable TLS with
`deploy/nginx/conf.d/tls.conf.example` before exposing it to the internet.
Optional Prometheus/Grafana:

```bash
mkdir -p secrets
printf '%s' "$ISHASTRA_API_KEY" > secrets/ishastra_api_key && chmod 600 secrets/ishastra_api_key
docker compose --env-file .env.production \
  -f docker-compose.yml -f docker-compose.monitoring.yml up -d
```

## 3. Install and configure without containers

```bash
python3 -m venv /opt/ishastra/venv
/opt/ishastra/venv/bin/pip install -c constraints.txt .
mkdir -p /etc/ishastra /var/lib/ishastra && chown ishastra /var/lib/ishastra
cp scope.example.json /etc/ishastra/scope.json   # edit: what you may test
```

`/etc/ishastra/ishastra.env` (mode 0600, owned by the service user):

```ini
ISHASTRA_ENV=production
ISHASTRA_API_KEY=<random, python -c 'import secrets; print(secrets.token_urlsafe(32))'>
ISHASTRA_AUDIT_HMAC_KEY=<a different random value>
ISHASTRA_WEBHOOK_SECRET=<another random value, if webhooks are used>
ISHASTRA_SCOPE_FILE=/etc/ishastra/scope.json
ISHASTRA_DB=/var/lib/ishastra/ishastra.db
ISHASTRA_SCOPE_MODE=auto
ISHASTRA_RETENTION_DAYS=90
ISHASTRA_LOG_FORMAT=json
ISHASTRA_LOG_LEVEL=INFO
```

`ISHASTRA_ENV=production` is a fail-closed startup gate: the service refuses to
start without a valid `ISHASTRA_API_KEY` and `ISHASTRA_AUDIT_HMAC_KEY`, and it forces
`/docs`, `/redoc` and `/openapi.json` off regardless of `ISHASTRA_DISABLE_DOCS`.
Placeholder or short secrets are refused at startup; a missing
`ISHASTRA_AUDIT_HMAC_KEY` starts with a loud warning (the audit chain is then only
tamper-evident against naive edits, not unforgeable).

## 4. Run under systemd

```ini
# /etc/systemd/system/ishastra.service
[Unit]
Description=Ishastra authorized assessment platform
After=network-online.target

[Service]
User=ishastra
EnvironmentFile=/etc/ishastra/ishastra.env
ExecStart=/opt/ishastra/venv/bin/ishastra --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=5
# Hardening: the process needs its own state dir and nothing else.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/ishastra
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

### 4.1. Create your scope document (one-time)

```bash
# Interactive wizard (recommended)
/opt/ishastra/venv/bin/ishastra scope-wizard --output /etc/ishastra/scope.json

# OR manually copy and edit the template
cp scope.example.json /etc/ishastra/scope.json
# Edit /etc/ishastra/scope.json with your authorized hosts, networks, and ports
```

`SIGTERM` is graceful and bounded: in-flight HTTP requests get up to 30 s,
running assessments are cancelled and marked `failed — interrupted by process
restart`, and the audit trail is flushed — so `systemctl restart` is safe and
prompt. Interrupted jobs are never left looking live or re-run silently.

## 5. Reverse proxy

Terminate TLS at nginx/Caddy/traefik and proxy to `127.0.0.1:8000`. List the
proxy's source address in `ISHASTRA_TRUSTED_PROXIES` so rate limiting counts real
client IPs — that variable is the only place forwarded headers are trusted, and
uvicorn itself never rewrites client addresses. The bundled UI is same-origin
and needs no CORS; set `ISHASTRA_CORS_ORIGINS` only for a separate dashboard
origin.

## 6. First-run checklist

1. `systemctl start ishastra`, then `curl -s localhost:8000/api/health` and
   `curl -s localhost:8000/api/ready` (both unauthenticated by design).
2. Open `http://<host>:8000/` through the proxy and confirm the UI loads.
3. Create your scope document (if not done already):
   ```bash
   # Interactive wizard (recommended)
   /opt/ishastra/venv/bin/ishastra scope-wizard --output /etc/ishastra/scope.json
   # OR edit /etc/ishastra/scope.json manually
   ```
4. Decide the authorization mode: leave `auto`/single-organization with one
   `scope.json`, or switch to `managed` and create per-tenant engagement
   policies via `POST /api/policies` (admin only). Every assessment is refused
   until a scope document or policy exists — that is by design. The global
   scope file is read at startup: restart the service after editing it. Managed
   policies take effect through the policy API without a restart.
5. Run the e2e smoke against the built-in lab to prove the deployment end to end:
   ```bash
   python -m ishastra.lab --report lab-eval.json
   ```
   (starts its own lab on 127.0.0.1; no external traffic).
6. Note the audit chain tip (`GET /api/audit/verify` or `/api/ready`) — record it
   off-host if chain continuity matters to you.

## 7. Recurring maintenance

- **Backups:** `sqlite3 /var/lib/ishastra/ishastra.db ".backup '/backups/ishastra-$(date +%F).db'"`
  gives a consistent snapshot (WAL mode). The database holds key hashes,
  findings, policies and the audit chain — restrict the backup's permissions
  like the live file (0600). In the container:
  `docker compose exec ishastra sqlite3 /var/lib/ishastra/ishastra.db ".backup '/var/lib/ishastra/ishastra-backup.db'"`,
  then `docker cp ishastra-ishastra-1:/var/lib/ishastra/ishastra-backup.db ./backups/`.
  Test restores quarterly on a separate host.
- **Retention:** with `ISHASTRA_RETENTION_DAYS=N`, finished jobs/findings and plain
  audit entries older than N days are pruned at startup and every 6 hours, and
  the file is vacuumed. The sealed audit chain is never pruned; it only grows
  with security events (key rotations, denials, policy changes) and is small.
  Setting the variable to `0` (default) keeps everything forever.
- **Key rotation:** rotate any key via the tenants API
  (`POST /api/keys/rotate/{tenant_id}`); restart with the new `ISHASTRA_API_KEY` env
  only if you need to re-adopt it as the bootstrap. Rotating
  `ISHASTRA_AUDIT_HMAC_KEY` changes how future chain entries are keyed — old
  entries remain verifiable only while the old key is known, so treat key
  rotation as a documented event and verify the chain before and after.
- **Upgrades:** pin to a tagged release; `pip install -c constraints.txt .` in
  the venv, `systemctl restart ishastra`. Schema migrations are versioned and run
  forward automatically at startup; back up the database first (see above).
  Jobs left queued/running by the old process are failed by the new one at
  startup, never resumed as if nothing happened.

## 8. Rollback procedure

If a release introduces regressions:

1. **Immediate rollback (same version, config change):** `systemctl restart ishastra`
   - Reads the same database; no migration reversal needed.
   - In-flight jobs are failed and marked `interrupted` — safe to retry.

2. **Code rollback (previous tagged release):**
   ```bash
   # In the venv, reinstall the previous tag
   # From the previous release checkout/artifact (PyPI publication pending)
   /opt/ishastra/venv/bin/pip install -c constraints.txt /path/to/ishastra-3.5.0
   systemctl restart ishastra
   ```
   - Schema migrations are **forward-only**. The database at the new version
     is compatible with the old code because we never drop columns/tables
     in a minor/patch release.
   - If a migration did run (rare in patches), restore the pre-upgrade backup:
     ```bash
     systemctl stop ishastra
     sqlite3 /var/lib/ishastra/ishastra.db ".restore '/backups/ishastra-YYYY-MM-DD.db'"
     systemctl start ishastra
     ```

3. **Audit chain continuity:** The chain is append-only. Rolling back code does
   not truncate it — verify with `GET /api/audit/verify` after restart.

## 9. RTO / RPO and Warm Standby Promotion

Ishastra is single-host by design. High availability is achieved by promoting a
warm standby, not by clustering.

Take a backup with `ishastra backup`. The artifact is verified immediately, with
the same checks a restore relies on, so a broken backup fails here rather than
at 3am during a failover:

```bash
ishastra backup --out /backups                      # ISHASTRA_DATABASE_URL / ISHASTRA_DB
ishastra backup --db "$ISHASTRA_DATABASE_URL" --out /backups
ishastra backup --verify /backups/ishastra-20260101T000000Z.dump
```

SQLite targets produce a consistent snapshot (`ishastra-*.db`); a PostgreSQL DSN
produces a `pg_dump` custom archive (`ishastra-*.dump`). The database password is
passed to `pg_dump`/`pg_restore` through `PGPASSWORD`, never on the command
line. Restoring is the standby promotion workflow, which is automated:

```bash
# On the standby host (with backups synced from primary):
ishastra standby-promote \
  --backup-dir /backups \
  --db-path /var/lib/ishastra/ishastra.db \
  --scope-file /etc/ishastra/scope.json
```

The command performs four sequential steps and reports timings for RTO measurement:

1. **Verify latest backup** — checks file exists, is a valid SQLite snapshot or `pg_dump` archive, has the required tables, and (SQLite) audit chain has entries.
2. **Restore database** — uses SQLite's backup API for an atomic, consistent snapshot; sets 0600 permissions.
3. **Acquire worker lease** — takes the exclusive `<db>.worker-lock`; fails fast if another process holds it (split-brain prevention).
4. **Run readiness checks** — verifies audit chain (HMAC-SHA256 when `ISHASTRA_AUDIT_HMAC_KEY` is set), scope/policy loaded, schema version, and at least one active admin API key.

Typical RTO on a modern SSD host with a 2 GB database: **< 5 seconds** (verify ~50 ms, restore ~3 s, lease ~5 ms, readiness ~1 s). RPO equals your backup interval — `deploy/cron/ishastra-backup` runs hourly (install it as `/etc/cron.hourly/ishastra-backup`; on Kubernetes set `backup.enabled: true` in the Helm chart), giving an RPO of ≤ 1 hour. Reduce the interval for tighter RPO; the backup is a consistent snapshot and does not block the running worker.

**Failover procedure (manual, ~30 s operator time):**
1. Detect primary failure (health check `/api/ready` fails).
2. Ensure backups are current on standby host (rsync/S3/NFS from primary).
3. Run `ishastra standby-promote` on standby.
4. Update DNS / load balancer to point to standby.
5. Verify `/api/ready` and audit chain continuity on the promoted host.

The promoted database is immediately operational — interrupted jobs are marked `failed — interrupted` at startup, never resumed silently. The audit chain verifies end-to-end, proving the restored state is tamper-free.

## 10. Scaling model and limits

Ishastra is deliberately single-writer per database:

1. **One process per `ISHASTRA_DB`.** `AssessmentWorker.start()` takes an exclusive
   lease; a second process pointed at the same database exits with
   `WorkerLeaseError` instead of silently double-running jobs. The compose stack
   therefore runs exactly one `ishastra` service. Do not add replicas.
2. **Scale vertically.** Increase CPU/RAM and `ISHASTRA_WORKERS` (adapter threads)
   on the one host. SQLite WAL handles the API and worker contention on a single
   node; it is not a multi-node database. With PostgreSQL, each process opens up
   to `ISHASTRA_PG_POOL_MAX` connections (default 5, clamped to 50): keep
   `ISHASTRA_PG_POOL_MAX × replicas` under the server's `max_connections`, or route
   clients through PgBouncer.
3. **No automated HA/failover.** Keep tested backups off-host (in Nepal, in a
   second availability zone/provider) and restore onto a new host. The audit
   chain is append-only and verifies after restore; jobs left running are marked
   failed at startup, never resumed silently.
4. **Redis** backs rate limiting and is required by the compose stack so limits
   survive a process restart/database reset. The default job queue is in-process.
   `ISHASTRA_QUEUE_MODE=redis-streams` puts one entry per job in a durable Redis
   Stream: queued work survives a restart (a killed process's queued rows are
   replayed on start, never silently dropped), and several worker processes can
   consume the same stream through a consumer group. The database is still the
   single writer and `claim_job` still guarantees one execution per job, so this
   scales workers, not database writers. `ISHASTRA_QUEUE_MODE=k8s-jobs` runs one
   Kubernetes Job per assessment; it is experimental and not an HA queue.
5. **Health checks:** `/api/health` and `/api/ready` are unauthenticated;
   `/api/monitor/status` and `/api/metrics` require the admin key. Probe
   `/api/ready` from the load balancer/proxy.
6. **Log aggregation:** Set `ISHASTRA_LOG_FORMAT=json` and ship logs to
   Loki/Elastic/Graylog. All requests share the same `request_id` middleware
   for trace correlation.
7. **PostgreSQL** is an advanced backend (tested single-host, no HA). The worker
   uses loop-aware asyncpg pools. Validated: schema migrations (v1-v20),
   SIGTERM soak test (no stale lock, audit chain intact, API verify passes),
   assessment load test (10 jobs, 0 failed). No HA, multi-node migration,
   or supported failover; use SQLite for a pilot unless you accept and test
   the single-host limitation.

## 11. Nepal launch readiness

The NRB, NTA and NCSP control mappings are produced from assessment evidence, not
from a separate document: `src/ishastra/compliance/nrb.py`, `nta.py` and
`ncsp.py` map findings onto each framework's controls, and
`GET /api/compliance/schedules/frequencies` lists the frameworks and review
cadences the API accepts. `scope.example.json` shows an authorization document
for an in-country target.

Licensing, in-country hosting approval and regulatory filing are outside this
repository and are not claimed here.

## 12. Database migrations and row-level security

There is no separate migration step to forget: the store applies its schema
chain on every connection.

- SQLite and PostgreSQL each carry an ordered statement list in
  `src/ishastra/core/store.py` (`MIGRATIONS`, `MIGRATIONS_PG`), keyed by a
  `schema_version` row in `settings`. Starting the service upgrades an existing
  database to the current schema.
- On PostgreSQL the MSSP tables are created from `MIGRATIONS_MSSP_PG`, and the
  RLS step (`src/ishastra/core/pg_rls.py`, tracked as `rls_applied`) creates the
  tenant helper functions, the policies and their indexes.
- `migrations/028_rls_enable.py` remains as the historical entry point and
  applies whatever is still pending.

Connect the application with a **non-superuser role**. PostgreSQL lets a
superuser bypass row-level security entirely, so a superuser connection
silently disables the tenant isolation you think you have.

```sql
CREATE ROLE ishastra_app LOGIN PASSWORD '...';
GRANT USAGE ON SCHEMA public TO ishastra_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ishastra_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ishastra_app;
```

## 13. Email invitations for organizations

Invitations are signed with `ISHASTRA_AUDIT_HMAC_KEY` and expire after 7 days; no
invitation state is stored.

1. Configure `ISHASTRA_SMTP_HOST`, `ISHASTRA_SMTP_FROM` and optionally credentials and
   `ISHASTRA_PUBLIC_BASE_URL` (used for the acceptance link).
2. `POST /api/v2/orgs/{org_id}/invite?email=...&role=...` sends the message.
   Without SMTP the API answers 503 rather than claiming success.
3. The invited tenant accepts with
   `POST /api/v2/orgs/invitations/accept?token=...`, which creates the
   membership for the calling API key's tenant.

## 14. Troubleshooting

- **`another Ishastra worker process already owns …worker-lock`** — a second
  process was pointed at the same `ISHASTRA_DB`, or a stale lock survived an
  unclean kill. Verify no `ishastra` process runs (`pgrep -af ishastra`), then remove
  the lock file before starting.
- **`ISHASTRA_API_KEY rejected; refusing startup`** — the env key failed
  validation while an older key is persisted; fix the env value. The process
  refuses to quietly keep the old key so a failed rotation cannot look
  successful.
- **Every assessment refused** — no scope document is loaded (global mode) or
  the tenant has no valid engagement policy (managed mode). Check
  `GET /api/scope` and the startup log line `scope document … rejected: …`.
- **Compose container is unhealthy** — the health check requires both readiness
  and `scope_configured`. Create `config/scope.json` (or a managed policy) before
  expecting green health; the container still serves the loopback API on
  `127.0.0.1:8000` for bootstrap.
- **`nmap unavailable` in job coverage** — the binary is missing in the
  container/host; install it or accept the reduced (never falsely clean)
  coverage.
- **`database is locked` in logs** — should not happen since 0.1.0 (write
  transactions take the write lock up front and contend via `busy_timeout`); if
  you still see it, file it with the surrounding log lines.

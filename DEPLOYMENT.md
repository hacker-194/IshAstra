# Deploying Strix for real-world use

The short version of this file is in `README.md` under *Deploying*; this page is
the operator runbook: a concrete systemd setup, the first-run checklist, and the
recurring maintenance tasks (backups, key rotation, retention, upgrades).

## 1. Prerequisites

- CPython 3.12+ on Linux; one host (or container) per database — the worker
  takes an exclusive lease on `<STRIX_DB>.worker-lock`, so a second process
  pointed at the same database refuses to start rather than double-running jobs.
  SQLite (WAL) is the supported backend. PostgreSQL is experimental and not
  supported for the threaded worker yet (asyncpg pools are event-loop bound).
- Optional binaries widen coverage: `nmap` (network profile; the image installs
  it), `nuclei` (web-deep exposure templates). A missing tool is reported as
  unavailable coverage by the job — it is never reported as a clean result.
- Outbound network from the host is required to assess targets; keep host-level
  egress filtering enabled as defense in depth behind the scope gate.

## 2. Container quick start (recommended for a pilot)

```bash
cp .env.production.example .env.production   # edit: keys, retention, scope mode
cp config/scope.example.json config/scope.json  # edit: what you may test
# Generate each secret with: python -c 'import secrets; print(secrets.token_urlsafe(32))'
docker compose --env-file .env.production up -d --build
docker compose ps                              # strix/nginx/redis must be healthy
curl -s http://127.0.0.1:8000/api/ready        # loopback bootstrap port
```

The container is healthy only when the database/audit chain answer **and** a
scope document (or managed policy) is loaded. Keep `config/scope.json` out of
git. The bundled nginx serves port 80; enable TLS with
`deploy/nginx/conf.d/tls.conf.example` before exposing it to the internet.
Optional Prometheus/Grafana:

```bash
mkdir -p secrets
printf '%s' "$STRIX_API_KEY" > secrets/strix_api_key && chmod 600 secrets/strix_api_key
docker compose --env-file .env.production \
  -f docker-compose.yml -f docker-compose.monitoring.yml up -d
```

## 3. Install and configure without containers

```bash
python3 -m venv /opt/strix/venv
/opt/strix/venv/bin/pip install -c constraints.txt .
mkdir -p /etc/strix /var/lib/strix && chown strix /var/lib/strix
cp scope.example.json /etc/strix/scope.json   # edit: what you may test
```

`/etc/strix/strix.env` (mode 0600, owned by the service user):

```ini
STRIX_API_KEY=<random, python -c 'import secrets; print(secrets.token_urlsafe(32))'>
STRIX_AUDIT_HMAC_KEY=<a different random value>
STRIX_WEBHOOK_SECRET=<another random value, if webhooks are used>
STRIX_SCOPE_FILE=/etc/strix/scope.json
STRIX_DB=/var/lib/strix/strix.db
STRIX_SCOPE_MODE=auto
STRIX_RETENTION_DAYS=90
STRIX_LOG_FORMAT=json
STRIX_LOG_LEVEL=INFO
```

Placeholder or short secrets are refused at startup; a missing
`STRIX_AUDIT_HMAC_KEY` starts with a loud warning (the audit chain is then only
tamper-evident against naive edits, not unforgeable).

## 4. Run under systemd

```ini
# /etc/systemd/system/strix.service
[Unit]
Description=Strix authorized assessment platform
After=network-online.target

[Service]
User=strix
EnvironmentFile=/etc/strix/strix.env
ExecStart=/opt/strix/venv/bin/strix --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=5
# Hardening: the process needs its own state dir and nothing else.
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/strix
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

`SIGTERM` is graceful and bounded: in-flight HTTP requests get up to 30 s,
running assessments are cancelled and marked `failed — interrupted by process
restart`, and the audit trail is flushed — so `systemctl restart` is safe and
prompt. Interrupted jobs are never left looking live or re-run silently.

## 5. Reverse proxy

Terminate TLS at nginx/Caddy/traefik and proxy to `127.0.0.1:8000`. List the
proxy's source address in `STRIX_TRUSTED_PROXIES` so rate limiting counts real
client IPs — that variable is the only place forwarded headers are trusted, and
uvicorn itself never rewrites client addresses. The bundled UI is same-origin
and needs no CORS; set `STRIX_CORS_ORIGINS` only for a separate dashboard
origin.

## 6. First-run checklist

1. `systemctl start strix`, then `curl -s localhost:8000/api/health` and
   `curl -s localhost:8000/api/ready` (both unauthenticated by design).
2. Open `http://<host>:8000/` through the proxy and confirm the UI loads.
3. Decide the authorization mode: leave `auto`/single-organization with one
   `scope.json`, or switch to `managed` and create per-tenant engagement
   policies via `POST /api/policies` (admin only). Every assessment is refused
   until a scope document or policy exists — that is by design. The global
   scope file is read at startup: restart the service after editing it. Managed
   policies take effect through the policy API without a restart.
4. Run the e2e smoke against the built-in lab to prove the deployment end to end:
   `python scripts/smoke_e2e.py` (starts its own lab; no external traffic).
5. Note the audit chain tip (`GET /api/audit/verify` or `/api/ready`) — record it
   off-host if chain continuity matters to you.

## 7. Recurring maintenance

- **Backups:** `sqlite3 /var/lib/strix/strix.db ".backup '/backups/strix-$(date +%F).db'"`
  gives a consistent snapshot (WAL mode). The database holds key hashes,
  findings, policies and the audit chain — restrict the backup's permissions
  like the live file (0600). In the container:
  `docker compose exec strix sqlite3 /var/lib/strix/strix.db ".backup '/var/lib/strix/strix-backup.db'"`,
  then `docker cp strix-strix-1:/var/lib/strix/strix-backup.db ./backups/`.
  Test restores quarterly on a separate host.
- **Retention:** with `STRIX_RETENTION_DAYS=N`, finished jobs/findings and plain
  audit entries older than N days are pruned at startup and every 6 hours, and
  the file is vacuumed. The sealed audit chain is never pruned; it only grows
  with security events (key rotations, denials, policy changes) and is small.
  Setting the variable to `0` (default) keeps everything forever.
- **Key rotation:** rotate any key via the tenants API
  (`POST /api/keys/rotate/{tenant_id}`); restart with the new `STRIX_API_KEY` env
  only if you need to re-adopt it as the bootstrap. Rotating
  `STRIX_AUDIT_HMAC_KEY` changes how future chain entries are keyed — old
  entries remain verifiable only while the old key is known, so treat key
  rotation as a documented event and verify the chain before and after.
- **Upgrades:** pin to a tagged release; `pip install -c constraints.txt .` in
  the venv, `systemctl restart strix`. Schema migrations are versioned and run
  forward automatically at startup; back up the database first (see above).
  Jobs left queued/running by the old process are failed by the new one at
  startup, never resumed as if nothing happened.

## 8. Rollback procedure

If a release introduces regressions:

1. **Immediate rollback (same version, config change):** `systemctl restart strix`
   - Reads the same database; no migration reversal needed.
   - In-flight jobs are failed and marked `interrupted` — safe to retry.

2. **Code rollback (previous tagged release):**
   ```bash
   # In the venv, reinstall the previous tag
   /opt/strix/venv/bin/pip install -c constraints.txt strix==3.4.0
   systemctl restart strix
   ```
   - Schema migrations are **forward-only**. The database at the new version
     is compatible with the old code because we never drop columns/tables
     in a minor/patch release.
   - If a migration did run (rare in patches), restore the pre-upgrade backup:
     ```bash
     systemctl stop strix
     sqlite3 /var/lib/strix/strix.db ".restore '/backups/strix-YYYY-MM-DD.db'"
     systemctl start strix
     ```

3. **Audit chain continuity:** The chain is append-only. Rolling back code does
   not truncate it — verify with `GET /api/audit/verify` after restart.

## 9. Scaling model and limits

Strix is deliberately single-writer per database:

1. **One process per `STRIX_DB`.** `AssessmentWorker.start()` takes an exclusive
   lease; a second process pointed at the same database exits with
   `WorkerLeaseError` instead of silently double-running jobs. The compose stack
   therefore runs exactly one `strix` service. Do not add replicas.
2. **Scale vertically.** Increase CPU/RAM and `STRIX_WORKERS` (adapter threads)
   on the one host. SQLite WAL handles the API and worker contention on a single
   node; it is not a multi-node database.
3. **No automated HA/failover.** Keep tested backups off-host (in Nepal, in a
   second availability zone/provider) and restore onto a new host. The audit
   chain is append-only and verifies after restore; jobs left running are marked
   failed at startup, never resumed silently.
4. **Redis** backs rate limiting and is required by the compose stack so limits
   survive a process restart/database reset. It is not a queue: the job queue is
   in-process.
5. **Health checks:** `/api/health` and `/api/ready` are unauthenticated;
   `/api/monitor/status` and `/api/metrics` require the admin key. Probe
   `/api/ready` from the load balancer/proxy.
6. **Log aggregation:** Set `STRIX_LOG_FORMAT=json` and ship logs to
   Loki/Elastic/Graylog. All requests share the same `request_id` middleware
   for trace correlation.
7. **PostgreSQL** is not a supported backend for this worker design. The code
   has an experimental API-only path, but worker threads own separate event
   loops and asyncpg pools are loop-bound; using it will fail jobs. Use SQLite.

## 10. Nepal launch readiness

See [`NEPAL_LAUNCH_READINESS.md`](NEPAL_LAUNCH_READINESS.md) for the
in-country deployment profile, NRB/NTA/NCSP evidence mapping, and the
legal/business prerequisites that are outside this repository's control.

## 11. Troubleshooting

- **`another Strix worker process already owns …worker-lock`** — a second
  process was pointed at the same `STRIX_DB`, or a stale lock survived an
  unclean kill. Verify no `strix` process runs (`pgrep -af strix`), then remove
  the lock file before starting.
- **`STRIX_API_KEY rejected; refusing startup`** — the env key failed
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
- **`database is locked` in logs** — should not happen since 3.5.0 (write
  transactions take the write lock up front and contend via `busy_timeout`); if
  you still see it, file it with the surrounding log lines.

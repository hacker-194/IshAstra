# Docker Compose deployment

This page documents the `docker-compose.yml` in this repository. Earlier
revisions of this page described `Dockerfile.api`, `Dockerfile.worker`,
`docker-compose.prod.yml`, MinIO and Alembic migrations — none of those exist.
If a guide tells you to run them, it is wrong.

Compose here is for **local development and a single-host pilot**, not for
horizontal scale.

## Services

| Service | Purpose | Port (loopback) |
|---------|---------|-----------------|
| `scope-gate` | The IshAstra API/worker process (FastAPI + in-process queue) | `127.0.0.1:8000` |
| `postgres` | Database (`ISHASTRA_DATABASE_URL`) | `127.0.0.1:5432` |
| `redis` | Shared rate-limit counters | `127.0.0.1:6379` |
| `nginx` | Reverse proxy on 80/443 | public |
| `prometheus` | Metrics scrape | `127.0.0.1:9090` |
| `grafana` | Dashboards (admin password from `GRAFANA_PASSWORD`) | `127.0.0.1:3000` |
| `jaeger` | OTLP tracing UI | `127.0.0.1:16686` |
| `keycloak` | Optional local IdP (`--profile sso`) | `127.0.0.1:8180` |

There is deliberately **one** IshAstra process: the worker takes an exclusive
lease on the database, so a second process would refuse to start. Scale with
`ISHASTRA_WORKERS`, not replicas.

## Run it

```bash
cp .env.production.example .env.production
# edit keys and scope path; generate secrets with:
#   python -c 'import secrets; print(secrets.token_urlsafe(32))'

# One-time scope setup
docker compose --env-file .env.production run --rm scope-gate \
  ishastra scope-wizard --output /etc/ishastra/scopes/scope.json

docker compose --env-file .env.production up -d --build
docker compose ps
curl -fsS http://127.0.0.1:8000/api/ready
```

Health endpoints are `/api/health` (liveness) and `/api/ready` (database,
audit chain, scope document, admin key). Both are unauthenticated; everything
else needs `Authorization: Bearer $ISHASTRA_API_KEY`.

## Configuration

Compose reads these from the environment / `.env.production`:

| Variable | Purpose |
|----------|---------|
| `POSTGRES_PASSWORD` | Database password (default is dev-only) |
| `GRAFANA_PASSWORD` | Grafana admin password (default `admin`, loopback only) |
| `ISHASTRA_API_KEY` | Admin API key |
| `ISHASTRA_AUDIT_HMAC_KEY` | Audit-chain sealing key |
| `ISHASTRA_ENCRYPTION_KEY` | AES-GCM key for secrets at rest |
| `ISHASTRA_SCOPE_DIR` / `ISHASTRA_SCOPE_JWKS` | Signed scope documents and public keys |

For anything reachable beyond localhost, set `ISHASTRA_ENV=production`, terminate
TLS at `nginx` (see `deploy/nginx/conf.d/tls.conf.example`), and keep the
database and Redis bound to loopback — the compose file already does.

## Operations

```bash
docker compose logs -f scope-gate     # JSON logs
docker compose exec postgres pg_dump -U ishastra ishastra | gzip > backup-$(date +%F).sql.gz
docker compose restart scope-gate     # SIGTERM is graceful and bounded
```

Migrations are applied by the application at startup; there is no Alembic
CLI. Back up before upgrading and verify `/api/ready` plus `/api/audit/verify`
afterwards.

## Limits

- Single host, single writer. No replicas, no HA, no autoscaling.
- The compose stack is not a supported multi-tenant SaaS topology.
- Compose's `deploy.resources` limits are honoured by `docker compose` v2 in
  recent versions but ignored by plain `docker run`.

For the production checklist and topology table, read
[Production deployment](../quickstart/production.md). For the operator runbook, read
[`DEPLOYMENT.md`](https://github.com/hacker-194/IshAstra/blob/main/DEPLOYMENT.md).

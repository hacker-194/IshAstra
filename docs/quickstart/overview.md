# Quick Start

Install IshAstra, create an authorization scope, and run your first assessment.

## Prerequisites

- Python 3.12+
- Git
- Docker 24+ with Compose v2 (optional, for the full local stack)

## 1. Run the demo

```bash
git clone https://github.com/hacker-194/IshAstra.git
cd IshAstra
python3 -m venv .venv && . .venv/bin/activate
pip install -c constraints.txt -e .
ishastra demo
```

The demo writes `.ishastra-demo/`, generates an admin API key and an Ed25519-signed scope limited to localhost, and prints the URL and key. Open `http://127.0.0.1:8000`, paste the key, and run a local assessment. It never reaches outside the demo directory.

## 2. Verify the API

```bash
curl -s http://127.0.0.1:8000/api/health
curl -s http://127.0.0.1:8000/api/ready
```

`/api/health` is liveness. `/api/ready` also checks the database and audit chain, and is the probe to use behind a load balancer.

## 3. Create an authorization scope

```bash
ishastra scope-wizard --output scope.json
```

The wizard writes a v2 scope document. A minimal document looks like this:

```json
{
  "version": 2,
  "program": "Example assessment",
  "authorized_by": "Security Team",
  "authorization_ref": "ENG-2026-001",
  "include": ["app.example.com"],
  "exclude": ["admin.example.com"],
  "authorized_networks": ["203.0.113.0/24"],
  "allowed_ports": [443],
  "allow_broad_networks": false,
  "expires_at": "2026-12-31T23:59:59Z"
}
```

- `include` / `exclude` match hostnames.
- `authorized_networks` is the CIDR set every resolved IP must fall inside.
- `allow_broad_networks: false` refuses `0.0.0.0/0` and `::/0`.
- `expires_at` bounds the authorization window.

Sign the document with `ishastra scope-sign` and configure `ISHASTRA_SCOPE_JWKS` if the deployment must reject unsigned scopes. See [Scope configuration](../scope-gate/configuration.md) for the full schema.

## 4. Run an assessment

```bash
ishastra assess run \
  --target https://app.example.com/ \
  --scope scope.json \
  --profile web \
  --output result.sarif
```

Profiles: `web`, `web-deep`, `api`, `api-deep`, `network`. The gate is re-checked inside every adapter, and the SARIF output is written only for an authorized target.

For asynchronous work:

```bash
ishastra assess submit --target https://app.example.com/ --scope scope.json --profile web
ishastra assess list
ishastra assess status <job-id>
```

Over HTTP, `POST /api/assess` queues the job (or runs inline with `wait: true`), `GET /api/assess/{job_id}` returns the job, and `GET /api/assess/{job_id}/sarif` returns the report.

## 5. Run the API server

```bash
export ISHASTRA_API_KEY="$(openssl rand -hex 32)"
export ISHASTRA_AUDIT_HMAC_KEY="$(openssl rand -base64 32)"
export ISHASTRA_ENCRYPTION_KEY="$(openssl rand -base64 32)"
ishastra serve --host 127.0.0.1 --port 8000
```

In production set `ISHASTRA_ENV=production`; startup then refuses placeholder or missing secrets and disables `/docs`. Copy `.env.example` to `.env` for the full list of settings.

## Docker Compose

```bash
cp .env.example .env
# Set POSTGRES_PASSWORD and GRAFANA_PASSWORD in .env
docker compose up -d
```

The base stack starts the API (`http://127.0.0.1:8000`), PostgreSQL, Redis, Prometheus (`:9090`), Grafana (`:3000`), Jaeger and nginx. Keycloak is behind the `sso` profile, and the host firewall is behind the `firewall` profile. See [Docker Compose](docker-compose.md) for ports, profiles, and the first-scan walkthrough.

## Kubernetes

```bash
helm install ishastra ./deploy/helm/ishastra \
  --namespace ishastra --create-namespace
```

The chart requires Kubernetes 1.25+ and a secret with `ISHASTRA_API_KEY`, `ISHASTRA_AUDIT_HMAC_KEY` and `ISHASTRA_ENCRYPTION_KEY`. See the [Helm guide](../deployment/helm.md).

## Next steps

- [Local development](local-dev.md): run from source and debug
- [Production deployment](production.md): supported topology and go-live checklist
- [Scope Gate concepts](../scope-gate/concepts.md): how decisions are made
- [API authentication](../api/authentication.md): keys and headers

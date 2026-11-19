# Kubernetes deployment

This page covers the Kubernetes path that exists: the Helm chart in
`deploy/helm/strix`. It replaces an earlier version of this document that
described HPA ranges, leader election and sidecar gateways the code does not
implement.

## Supported shape

| Item | Reality |
|------|---------|
| Writers per database | **One.** The worker holds an exclusive lease; a second process exits |
| Replicas | 1 API/worker process per database |
| Autoscaling | Not supported — HPA would start a second writer |
| Leader election | Not implemented |
| `k8s-jobs` queue | Experimental: one Kubernetes Job per assessment; no HA guarantee |
| Object storage | Not implemented; reports and evidence are stored by the database/host |

If you need several replicas, stop here: the application will refuse to start a
second worker, and there is no distributed queue to make it safe.

## Prerequisites

- Kubernetes 1.28+
- Helm 3.12+
- A PostgreSQL instance if you are not using SQLite (single writer either way)
- Secrets available as a Kubernetes `Secret` (External Secrets or Sealed
  Secrets are both wired up in `deploy/helm/strix`)
- An ingress controller with TLS (cert-manager recommended)

## Install

```bash
helm upgrade --install strix ./deploy/helm/strix \
  --namespace strix --create-namespace \
  -f ./deploy/helm/strix/values-prod.yaml \
  --set global.image.tag=3.5.0 \
  --set-file configMap.scopeJson=./scope.json \
  --wait --timeout 10m
```

`values-prod.yaml` intentionally sets one API replica and disables the HA
compatibility block. Do not raise `api.replicaCount`, `worker.replicaCount` or
re-enable `hpa` until a distributed queue ships.

## Required configuration

Create `strix-secrets` with at least:

| Key | Purpose |
|-----|---------|
| `STRIX_API_KEY` | Admin API key (32+ random bytes) |
| `STRIX_AUDIT_HMAC_KEY` | Audit-chain sealing key |
| `STRIX_ENCRYPTION_KEY` | Base64 32-byte AES key |
| `STRIX_SCOPE_FILE` / scope volume | Signed scope document and JWKS |

Also set `STRIX_ENV=production` and `STRIX_TRUSTED_PROXIES` for your ingress
range. Production mode disables `/docs`, `/redoc` and `/openapi.json` and
refuses placeholder secrets.

## Probes and rollout

- Liveness: `GET /api/health` (unauthenticated)
- Readiness: `GET /api/ready` (database, audit chain, scope document, admin key)
- Graceful shutdown: `terminationGracePeriodSeconds` ≥ 30; in-flight requests
  drain, running assessments are marked interrupted, audit is flushed

The chart's PodDisruptionBudget is `minAvailable: 1`; with one replica, a node
drain is a short outage, not a zero-downtime event.

## Secrets and scope

```bash
kubectl create secret generic strix-secrets -n strix \
  --from-literal=STRIX_API_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')" \
  --from-literal=STRIX_AUDIT_HMAC_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')" \
  --from-literal=STRIX_ENCRYPTION_KEY="$(python -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')"
```

Keep the Ed25519 private key out of the cluster; sign `scope.json` offline and
mount only the signed document plus JWKS.

## Upgrades

```bash
# Back up first (pg_dump or strix backup), then:
helm upgrade strix ./deploy/helm/strix -n strix -f values-prod.yaml --wait
curl -fsS https://strix.example.com/api/ready
curl -fsS -H "Authorization: Bearer $STRIX_API_KEY" https://strix.example.com/api/audit/verify
```

Roll back with `helm rollback strix -n strix`. Migrations are additive; restore
the pre-upgrade backup only if a release notes an irreversible change.

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| Pod crash-loops with `WorkerLeaseError` | More than one process points at the same database |
| `/api/ready` 503 | Scope document missing/expired, audit key absent, or no admin key |
| 401 on every route | `STRIX_API_KEY` missing from the pod environment |
| `k8s-jobs` jobs never start | ServiceAccount/RBAC for Job creation missing |

For capacity, backups and the go-live checklist see
[Production deployment](../quickstart/production.md) and
[`DEPLOYMENT.md`](../../DEPLOYMENT.md).

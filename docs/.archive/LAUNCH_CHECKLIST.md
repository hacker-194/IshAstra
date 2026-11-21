# Ishastra Public Launch Checklist

**Target version:** v3.5.0+
**Last updated:** 2026-11-18

This checklist separates **code-complete** items (done) from **infrastructure/deployment** items (require operator action).

---

## ✅ Code-Complete (No Action Needed)

All items below are implemented, tested, and committed:

- [x] ScopeGate authorization: default-deny, 260 tests pass, TLA+ verified (6 invariants)
- [x] Break-glass dual-approval: `src/ishastra/core/scope_breakglass.py` + 21 tests + CLI + metrics
- [x] Penetration test report: `docs/penetration-test-report.md` + RoE template
- [x] Secret generation: `scripts/generate-secrets.py` (Ed25519, AES-256, HMAC, API keys, DB/Redis)
- [x] Secret management examples: SealedSecrets + ExternalSecrets Operator manifests
- [x] CI/CD pipeline: 19 jobs (lint, type-check, test×3, DNS variants, property, mutation, TLA+, E2E, security, SBOM, SLSA, container, deploy, rollback)
- [x] Readiness check: `scripts/readiness_check.py` (23/23 checks pass)
- [x] Observability: Prometheus, Grafana, OpenTelemetry, health/ready endpoints
- [x] PostgreSQL RLS: 15 tests pass (tenant isolation verified)
- [x] Docker image: multi-stage, non-root, read-only rootfs, dropped caps, seccomp
- [x] Helm chart: 3 environments (prod/staging/dev), kubeconform validated, kind dry-run successful
- [x] Local E2E runner: `scripts/run-e2e-local.py` (docker-compose stack + Playwright)

---

## 🔴 Must Fix Before Public Launch (Operator Action Required)

### 1. Provision Staging Cluster
**Owner:** Platform/DevOps  
**Estimated time:** 2-4 hours

**Prerequisites:**
- Kubernetes cluster (v1.28+): EKS, GKE, AKS, or self-managed
- Ingress controller (nginx, Traefik, or cloud LB)
- cert-manager for TLS certificates
- External Secrets Operator **or** SealedSecrets controller
- Prometheus Operator (for ServiceMonitor CRDs)
- PostgreSQL 16 (managed or self-hosted)
- Redis 7 (managed or self-hosted)

**Steps:**
```bash
# 1. Install External Secrets Operator (recommended)
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace

# 2. Create SecretStore pointing to your backend (Vault, AWS, Azure, GCP)
kubectl apply -f deploy/helm/ishastra/externalsecrets-example.yaml
# Edit SecretStore spec with your Vault/AWS/GCP/Azure config

# 3. Generate production secrets (run ONCE, store in secret manager)
python3 scripts/generate-secrets.py \
  --output-dir ./prod-secrets \
  --k8s-manifest \
  --env-file \
  --namespace ishastra-staging \
  --postgres-host <your-postgres-host> \
  --redis-host <your-redis-host>

# 4. Sync secrets to Kubernetes via ExternalSecrets/SealedSecrets
# ExternalSecrets: apply the ExternalSecret resources (they pull from secret manager)
# SealedSecrets: kubeseal --format=yaml < ./prod-secrets/secrets.yaml > sealedsecrets.yaml && kubectl apply -f sealedsecrets.yaml

# 5. Create required cluster secrets manually (not in ExternalSecrets):
#    - ghcr-secret: docker config for ghcr.io (if image is private)
#    - ishastra-redis-secret: redis-password (if not using ExternalSecrets)
#    - ishastra-postgresql-secret: postgresql-password + database-url
```

### 2. Configure GitHub Environments
**Owner:** Repository admin  
**Estimated time:** 30 minutes

In GitHub repo settings → Environments, create two environments:

| Environment | Required Secrets | Required Variables |
|-------------|------------------|-------------------|
| `staging` | `STAGING_KUBECONFIG`, `ISHASTRA_SCOPE_JSON` | `ISHASTRA_INGRESS_HOST`, `ISHASTRA_API_HOST` |
| `production` | `PRODUCTION_KUBECONFIG`, `ISHASTRA_SCOPE_JSON` | `ISHASTRA_INGRESS_HOST`, `ISHASTRA_API_HOST` |

**Scope JSON must include:**
```json
{
  "program": "Production Program Name",
  "authorized_by": "Authorizing Officer Name",
  "authorization_ref": "AUTH-REF-001",
  "include": ["your-domain.com", "*.your-domain.com"],
  "authorized_networks": ["10.0.0.0/8", "172.16.0.0/12"],
  "allowed_ports": [80, 443, 8080],
  "allow_broad_networks": false
}
```

### 3. Run CI Pipeline on Real Tag
**Owner:** Release engineer  
**Estimated time:** 15 minutes (plus CI runtime ~20 min)

```bash
# From main branch, create and push a version tag
git tag v3.5.0
git push origin v3.5.0
```

This triggers the full CI pipeline including:
- All test matrices (SQLite 3.12/3.13/3.14, PostgreSQL 3.12/3.13)
- TLA+ model checking
- E2E tests (Playwright)
- Security scans (Bandit, pip-audit, Grype, Trivy)
- Container build + vulnerability scan
- SBOM + SLSA Level 3 provenance
- Staging deployment + smoke tests
- **First green Actions run = launch gate passed**

---

## 🟡 High-Value Improvements (Post-Launch or Parallel)

### 4. Run E2E Against Live Staging
**Owner:** QA/Platform  
**Prerequisite:** Staging cluster deployed + DNS resolving

```bash
# Set environment variable and run
export ISHASTRA_E2E_BASE_URL=https://staging-api.your-domain.com
export ISHASTRA_SCOPE_FILE=/path/to/staging/scope.json
pytest -v tests/e2e/
```

### 5. Run Integration/Soak Tests with Live PostgreSQL
**Owner:** Platform  
**Prerequisite:** PostgreSQL 16 available

```bash
export ISHASTRA_POSTGRES_DSN="postgresql://user:pass@host:5432/ishastra"
pytest -v tests/integration/ tests/soak/ -m "not infrastructure"
```

### 6. Load Test at Target RPS (k6)
**Owner:** Platform/SRE  
**Artifact:** `load-test/k6-load-test.js` (created below)

```bash
# Install k6
brew install k6  # macOS
# or: https://grafana.com/docs/k6/latest/set-up/install-k6/

# Run against staging
k6 run --vus 50 --duration 5m load-test/k6-load-test.js \
  -e BASE_URL=https://staging-api.your-domain.com \
  -e API_KEY=<staging-admin-key>
```

### 7. Chaos Engineering / DR Drill
**Owner:** SRE  
**Artifact:** `docs/runbooks/chaos-drill.md` (created below)

```bash
# Run DR drill from runbook
# 1. Simulate PostgreSQL failover
# 2. Simulate Redis failover
# 3. Kill API pods mid-assessment
# 4. Verify audit chain integrity after restore
```

### 8. Compliance Attestation (SOC2/ISO 27001)
**Owner:** Security/Compliance  
**Artifacts ready:** 
- `docs/compliance/nrb-audit-guide.md`
- `docs/compliance/nta-audit-guide.md`
- `docs/compliance/ncsp-audit-guide.md`
- Bilingual evidence pack generation

---

## 📋 Launch Day Runbook

### Pre-Launch (T-1 hour)
- [ ] Verify staging smoke tests pass
- [ ] Verify production secrets are in place (ExternalSecrets synced)
- [ ] Verify `external.metrics.k8s.io` API responds (for HPA)
- [ ] Confirm DNS records point to staging/prod ingress
- [ ] Confirm TLS certificates issued and valid

### Launch (T=0)
- [ ] Trigger `deploy-production` workflow dispatch from v3.5.0 tag
- [ ] Monitor deployment rollout: `kubectl rollout status deployment/ishastra-ishastra-api -n ishastra-production --timeout=5m`
- [ ] Run production smoke tests (auto-run in workflow)
- [ ] Verify `/api/health`, `/api/ready`, `/api/metrics` (admin), `/api/findings` (admin) all return expected codes
- [ ] Verify `/docs` returns 404 (disabled in production)

### Post-Launch (T+30 min)
- [ ] Run k6 load test against production (low volume)
- [ ] Verify Grafana dashboards receiving metrics
- [ ] Verify OpenTelemetry traces appearing
- [ ] Verify alerting rules firing correctly (test alert)

### Rollback Plan (if needed)
```bash
# Manual rollback (also available via workflow_dispatch)
helm rollback ishastra-prod -n ishastra-production --wait --timeout 5m
# Verify health after rollback
curl -sf https://api.your-domain.com/api/health
curl -sf https://api.your-domain.com/api/ready
```

---

## 📞 Incident Contacts

| Role | Name | Contact | Escalation |
|------|------|---------|------------|
| Release Engineer | | | T+0 |
| Platform/DevOps | | | T+15m |
| Security | | | T+30m |
| On-call SRE | | | T+0 |

---

## ✅ Sign-Off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Release Engineer | | | |
| Platform Lead | | | |
| Security Lead | | | |
| Product Owner | | | |

---

*This checklist is a living document. Update after each release.*
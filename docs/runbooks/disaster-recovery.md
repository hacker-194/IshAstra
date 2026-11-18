# Disaster Recovery Runbook

## Overview

This runbook covers full disaster recovery procedures for Strix platform.

**RTO (Recovery Time Objective): 4 hours**
**RPO (Recovery Point Objective): 1 hour**

---

## Alert Triggers

| Scenario | Severity | Detection |
|----------|----------|-----------|
| Regional outage | SEV-1 | Cloud provider status, monitoring alerts |
| Database corruption/loss | SEV-1 | `StrixAuditChainVerificationFailed`, data integrity checks |
| Kubernetes cluster loss | SEV-1 | All `up{job=~"strix|prometheus|redis"}` == 0 |
| Ransomware/encryption | SEV-1 | Unusual file encryption, ransom notes |
| Data center destruction | SEV-1 | Physical loss, cloud region unavailable |

---

## Backup Strategy

### What We Back Up

| Component | Frequency | Retention | Location |
|-----------|-----------|-----------|----------|
| SQLite Database (`strix.db`) | Hourly (WAL) + Daily full | 30 days daily, 1 year monthly | S3/GCS bucket `strix-backups/db` |
| Scope Configuration (`scope.json`) | On change + Daily | 90 days | S3/GCS bucket `strix-backups/config` |
| Kubernetes Manifests | On change (Git) | Permanent | Git repository |
| Secrets (encrypted) | On change | 90 days | Vault / Sealed Secrets |
| Redis RDB/AOF | Every 60s (AOF) | 7 days | S3/GCS bucket `strix-backups/redis` |
| Prometheus Data | Continuous (remote write) | 15 days | Thanos/Cortex or S3 |
| Grafana Dashboards | On change (Git) | Permanent | Git repository |

### Backup Verification

```bash
# Daily automated verification (cron job)
#!/bin/bash
# verify-backups.sh

LATEST_DB=$(aws s3 ls s3://strix-backups/db/ --recursive | sort | tail -n 1 | awk '{print $4}')
aws s3 cp s3://strix-backups/db/$LATEST_DB /tmp/verify.db

# Verify integrity
sqlite3 /tmp/verify.db "PRAGMA integrity_check;" | grep -q "ok" || exit 1

# Verify audit chain
STRIX_AUDIT_HMAC_KEY=$(vault kv get -field=STRIX_AUDIT_HMAC_KEY secret/strix)
sqlite3 /tmp/verify.db "SELECT verify_chain('$STRIX_AUDIT_HMAC_KEY');" | grep -q "valid" || exit 1

echo "Backup verification PASSED"
```

---

## Diagnosis Commands

### 1. Assess Damage Scope
```bash
# Check what's still running
kubectl get pods -A | grep -v Running

# Check persistent volumes
kubectl get pvc -A | grep -v Bound

# Check database accessibility
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "PRAGMA integrity_check;"

# Check backup availability
aws s3 ls s3://strix-backups/db/ --recursive | tail -5
```

### 2. Determine Recovery Strategy

| Scenario | Strategy | Estimated Time |
|----------|----------|----------------|
| Single pod failure | Kubernetes self-heals | < 2 min |
| Database corruption | Restore from backup | 30 min |
| Namespace deleted | Restore from Git + backup | 1 hour |
| Cluster lost | New cluster + restore | 2-4 hours |
| Region lost | Failover to DR region | 4 hours |

---

## Resolution Procedures

### Scenario 1: Database Corruption / Loss (Most Common)

#### Step 1: Stop Writers
```bash
# Scale down all writers
kubectl scale deployment strix-api -n strix --replicas=0
kubectl scale deployment strix-scheduler -n strix --replicas=0
kubectl scale deployment strix-worker -n strix --replicas=0  # if exists
```

#### Step 2: Identify Latest Good Backup
```bash
# List available backups
aws s3 ls s3://strix-backups/db/ --recursive --human-readable --summarize | tail -20

# Get latest verified backup
LATEST_BACKUP=$(aws s3 ls s3://strix-backups/db/verified/ --recursive | sort | tail -n 1 | awk '{print $4}')
echo "Restoring: $LATEST_BACKUP"
```

#### Step 3: Restore Database
```bash
# Download backup
aws s3 cp s3://strix-backups/db/verified/$LATEST_BACKUP /tmp/strix.db.restored

# Verify before restore
sqlite3 /tmp/strix.db.restored "PRAGMA integrity_check;"
sqlite3 /tmp/strix.db.restored "SELECT COUNT(*) FROM jobs; SELECT COUNT(*) FROM findings;"

# Copy to PVC (if using PVC)
kubectl cp /tmp/strix.db.restored strix/strix-api-0:/var/lib/strix/strix.db -c strix-api

# Or if using emptyDir, recreate PVC with backup
# (requires PVC recreation)
```

#### Step 4: Restore Scope Configuration
```bash
# Get latest scope backup
LATEST_SCOPE=$(aws s3 ls s3://strix-backups/config/ --recursive | sort | tail -n 1 | awk '{print $4}')
aws s3 cp s3://strix-backups/config/$LATEST_SCOPE /tmp/scope.json.restored

# Update ConfigMap
kubectl create configmap strix-config-restored --from-file=scope.json=/tmp/scope.json.restored -n strix --dry-run=client -o yaml | kubectl apply -f -
kubectl patch configmap strix-config -n strix -p "$(kubectl get configmap strix-config-restored -n strix -o json | jq -r '.data')"
```

#### Step 5: Restart Services
```bash
# Scale up
kubectl scale deployment strix-api -n strix --replicas=3
kubectl scale deployment strix-scheduler -n strix --replicas=1

# Wait for ready
kubectl rollout status deployment/strix-api -n strix --timeout=300s
kubectl rollout status deployment/strix-scheduler -n strix --timeout=300s
```

#### Step 6: Verify Recovery
```bash
# Health checks
curl -s http://strix.example.com/api/health
curl -s http://strix.example.com/api/ready

# Audit chain verification
curl -s -H "Authorization: Bearer $ADMIN_KEY" http://strix.example.com/api/audit/verify | jq .

# Functional test
curl -X POST http://strix.example.com/api/assess \
  -H "Authorization: Bearer $TEST_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "profile": "web", "wait": true}'
```

---

### Scenario 2: Kubernetes Cluster Loss / Region Failure

#### Step 1: Provision New Cluster (DR Region)
```bash
# Using Terraform/Cluster API
cd infrastructure/terraform/dr-region
terraform apply -auto-approve

# Or use managed Kubernetes (EKS/GKE/AKS)
# Ensure same version, CNI, CSI drivers
```

#### Step 2: Install Prerequisites
```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Install ingress-nginx
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install ingress-nginx ingress-nginx/ingress-nginx -n ingress-nginx --create-namespace

# Install monitoring stack
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack -n monitoring --create-namespace
```

#### Step 3: Deploy Strix via ArgoCD / Helm
```bash
# Option A: ArgoCD (preferred - declarative)
# ArgoCD applications already point to Git repo
# Just ensure ArgoCD is installed and synced
kubectl apply -k deploy/argocd/overlays/dr-region

# Option B: Helm directly
helm install strix ./deploy/helm/strix -n strix --create-namespace \
  -f deploy/helm/strix/values-dr.yaml \
  --set global.image.tag=3.5.0
```

#### Step 4: Restore Data
```bash
# Restore database (same as Scenario 1)
# Restore Redis (if needed - rate limiter state is recoverable)
# Restore secrets from Vault / Sealed Secrets

# Apply ExternalSecrets
kubectl apply -f deploy/argocd/secrets/external-secrets/
```

#### Step 5: Update DNS
```bash
# Update DNS to point to new cluster ingress
# Route53 / Cloudflare / Cloud DNS
aws route53 change-resource-record-sets --hosted-zone-id ZXXXXXXXX --change-batch file://dns-failover.json

# Verify DNS propagation
dig strix.example.com
```

#### Step 6: Verify Full Functionality
```bash
# Run smoke tests
kubectl exec -n strix strix-api-0 -- /usr/local/bin/pytest tests/smoke/ -v

# Verify monitoring
curl -s http://prometheus.monitoring.svc.cluster.local:9090/-/healthy
curl -s http://grafana.monitoring.svc.cluster.local:3000/api/health
```

---

### Scenario 3: Ransomware / Encryption Attack

#### Step 1: Isolate
```bash
# Immediately isolate affected systems
kubectl cordon <affected-nodes>
kubectl drain <affected-nodes> --ignore-daemonsets --delete-emptydir-data

# Block network access
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-egress
  namespace: strix
spec:
  podSelector: {}
  policyTypes:
  - Egress
EOF
```

#### Step 2: Assess Scope
```bash
# Check which PVs affected
kubectl get pv -o custom-columns=NAME:.metadata.name,STATUS:.status.phase,CLAIM:.spec.claimRef.name

# Check backup integrity (offline backups)
# Verify air-gapped backups not encrypted
```

#### Step 3: Recover from Clean Backups
```bash
# Follow Scenario 1/2 but verify backup timestamps PRE-DATE attack
# Use backup from before earliest detected encryption

# Rebuild cluster from scratch (don't trust compromised nodes)
# Terraform destroy + apply
```

#### Step 4: Forensic Preservation
```bash
# Snapshot compromised volumes for forensics
aws ec2 create-snapshot --volume-id vol-xxxx --description "Forensic snapshot $(date)"

# Preserve logs
kubectl logs -n strix -l app.kubernetes.io/name=strix --all-containers --tail=-1 > /forensics/strix-logs-$(date +%s).txt
```

---

## Escalation & SLA

| Scenario | RTO | RPO | Escalation |
|----------|-----|-----|------------|
| Database restore | 30 min | 1 hour | On-call → Platform Lead |
| Cluster rebuild | 2 hours | 1 hour | On-call → Platform Lead → VP Eng |
| Region failover | 4 hours | 1 hour | On-call → Platform Lead → VP Eng → CTO |
| Ransomware | 4-8 hours | 1 hour | On-call → Security → Legal → CISO → CEO |

**Contacts:**
- Platform On-Call: `platform-oncall@example.com`
- Platform Lead: `platform-lead@example.com`
- VP Engineering: `vp-eng@example.com`
- CISO: `ciso@example.com`
- Cloud Provider Support: AWS/GCP/Azure Enterprise Support

---

## Post-Incident Actions

1. **Root Cause Analysis** within 5 business days
2. **Backup Strategy Review** - verify RPO/RTO achievable
3. **DR Test Schedule** - quarterly full DR test
4. **Runbook Updates** - incorporate lessons learned
5. **Security Hardening** - if attack-related
6. **Compliance Reporting** - if regulated data involved

---

## DR Testing Checklist (Quarterly)

- [ ] Restore database from backup to staging
- [ ] Verify audit chain integrity after restore
- [ ] Deploy to DR region from scratch
- [ ] Test DNS failover
- [ ] Run full smoke test suite
- [ ] Verify monitoring/alerting in DR
- [ ] Document actual RTO/RPO achieved
- [ ] Update runbook with findings

---

## Grafana Dashboard Links

- **Backup Status**: `https://grafana.example.com/d/strix-backups/backup-status`
- **DR Readiness**: `https://grafana.example.com/d/strix-dr/dr-readiness`

**Key Panels:**
- Last Successful Backup Timestamp (stat)
- Backup Size Trends (time series)
- Backup Verification Status (table)
- DR Region Cluster Health (stat)
- RTO/RPO Compliance (gauge)
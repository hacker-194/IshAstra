# Secret Rotation Runbook

## Alert Triggers

| Alert | Severity | Source |
|-------|----------|--------|
| No direct alert | - | Scheduled rotation (90 days) |
| `StrixAuthFailureRateHigh` | warning | May indicate compromised key |
| Security incident | critical | Requires immediate rotation |

---

## Secrets Inventory

| Secret | Purpose | Rotation Period | Location |
|--------|---------|-----------------|----------|
| `STRIX_API_KEY` | Bootstrap admin access | 90 days | `strix-secrets` |
| `STRIX_AUDIT_HMAC_KEY` | Audit chain integrity | 90 days* | `strix-secrets` |
| `STRIX_WEBHOOK_SECRET` | Webhook signatures | 90 days | `strix-secrets` |
| `STRIX_ENCRYPTION_KEY` | Webhook secrets at rest | 90 days | `strix-secrets` |
| `redis-password` | Redis authentication | 90 days | `strix-redis-secret` |
| `postgresql-password` | PostgreSQL authentication | 90 days | `strix-postgresql-secret` |
| `grafana-admin-password` | Grafana admin access | 90 days | `strix-grafana-secret` |
| Tenant API keys | Tenant authentication | 90 days | Database |

*Audit HMAC key rotation requires chain re-hashing - see procedure below

---

## Symptoms & Impact

**Symptoms:**
- Scheduled rotation due (calendar)
- Suspected credential leak
- Security incident requiring key invalidation
- Compliance audit requirement

**Impact:**
- **SEV-3** (scheduled): Brief service restart, no downtime if done properly
- **SEV-1** (compromise): Immediate rotation required, potential data exposure

---

## Diagnosis Commands

### 1. Check Secret Ages
```bash
# Check Kubernetes secret creation timestamps
kubectl get secrets -n strix -o custom-columns=NAME:.metadata.name,CREATED:.metadata.creationTimestamp,AGE:.metadata.creationTimestamp

# Check secret data (not values)
kubectl get secret strix-secrets -n strix -o jsonpath='{.data}' | jq 'keys[]'

# Check ExternalSecret status (if using External Secrets Operator)
kubectl get externalsecret -n strix -o yaml
```

### 2. Verify Current Secret Values (Audit Only)
```bash
# Check secret exists and has data
kubectl get secret strix-secrets -n strix -o jsonpath='{.data.STRIX_API_KEY}' | base64 -d | wc -c

# List tenant API key ages
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "
SELECT prefix, created_at, revoked FROM api_keys ORDER BY created_at;
"

# Check webhook secret in use
kubectl exec -n strix strix-api-xxx -- env | grep STRIX_WEBHOOK
```

### 3. Check for Compromise Indicators
```bash
# Unusual auth patterns
kubectl logs -n strix -l app.kubernetes.io/name=strix,component=api --tail=1000 | grep -i "auth failure" | awk '{print $NF}' | sort | uniq -c | sort -rn

# Scope violations from same key
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "
SELECT actor, count(*) as violations FROM audit_log
WHERE action = 'scope_violation'
GROUP BY actor HAVING violations > 10;
"
```

---

## Resolution Procedures

### Standard Rotation (Scheduled - SEV-3)

#### 1. Prepare New Secrets
```bash
# Generate new secrets
API_KEY=$(openssl rand -base64 32 | tr -d '\n')
AUDIT_HMAC_KEY=$(openssl rand -base64 48 | tr -d '\n')
WEBHOOK_SECRET=$(openssl rand -base64 48 | tr -d '\n')
ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d '\n')
REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d '\n')
GRAFANA_PASSWORD=$(openssl rand -base64 24 | tr -d '\n')

# Store in secure location (password manager, vault)
echo "STRIX_API_KEY=$API_KEY" > /tmp/new-secrets.env
echo "STRIX_AUDIT_HMAC_KEY=$AUDIT_HMAC_KEY" >> /tmp/new-secrets.env
echo "STRIX_WEBHOOK_SECRET=$WEBHOOK_SECRET" >> /tmp/new-secrets.env
echo "STRIX_ENCRYPTION_KEY=$ENCRYPTION_KEY" >> /tmp/new-secrets.env
echo "redis-password=$REDIS_PASSWORD" >> /tmp/new-secrets.env
echo "postgresql-password=$POSTGRES_PASSWORD" >> /tmp/new-secrets.env
echo "grafana-admin-password=$GRAFANA_PASSWORD" >> /tmp/new-secrets.env
chmod 600 /tmp/new-secrets.env
```

#### 2. Rotate Application Secrets (Zero-Downtime)
```bash
# Update Kubernetes secret
kubectl create secret generic strix-secrets-new \
  --from-literal=STRIX_API_KEY="$API_KEY" \
  --from-literal=STRIX_AUDIT_HMAC_KEY="$AUDIT_HMAC_KEY" \
  --from-literal=STRIX_WEBHOOK_SECRET="$WEBHOOK_SECRET" \
  --from-literal=STRIX_ENCRYPTION_KEY="$ENCRYPTION_KEY" \
  -n strix --dry-run=client -o yaml | kubectl apply -f -

# Rollout restart to pick up new secrets
kubectl rollout restart deployment/strix-api deployment/strix-scheduler -n strix

# Verify pods restarted with new secrets
kubectl rollout status deployment/strix-api -n strix
kubectl rollout status deployment/strix-scheduler -n strix

# Verify application works
curl -s -H "Authorization: Bearer $API_KEY" http://strix.example.com/api/health

# Swap secret names
kubectl delete secret strix-secrets -n strix
kubectl patch secret strix-secrets-new -n strix -p '{"metadata":{"name":"strix-secrets"}}'
```

#### 3. Rotate Redis Password
```bash
# Update Redis password (requires Redis restart)
kubectl create secret generic strix-redis-secret-new \
  --from-literal=redis-password="$REDIS_PASSWORD" \
  -n strix --dry-run=client -o yaml | kubectl apply -f -

# Update Redis config (Bitnami chart)
kubectl patch secret strix-redis-secret -n strix -p "{\"data\":{\"redis-password\":\"$(echo -n $REDIS_PASSWORD | base64)\"}}"

# Restart Redis to pick up new password
kubectl rollout restart statefulset/redis-master -n strix

# Update Strix pods to use new password (via strix-secrets already updated)
kubectl rollout restart deployment/strix-api deployment/strix-scheduler -n strix
```

#### 4. Rotate PostgreSQL Password
```bash
# Update PostgreSQL user password
kubectl exec -n strix postgresql-0 -- psql -U postgres -c "ALTER USER strix WITH PASSWORD '$POSTGRES_PASSWORD';"

# Update Kubernetes secret
kubectl create secret generic strix-postgresql-secret-new \
  --from-literal=postgresql-password="$POSTGRES_PASSWORD" \
  -n strix --dry-run=client -o yaml | kubectl apply -f -

# Restart Strix to pick up new password
kubectl rollout restart deployment/strix-api deployment/strix-scheduler -n strix
```

#### 5. Rotate Grafana Password
```bash
# Update Grafana admin password
kubectl exec -n monitoring grafana-xxx -- grafana-cli admin reset-admin-password "$GRAFANA_PASSWORD"

# Update secret
kubectl create secret generic strix-grafana-secret-new \
  --from-literal=admin-user=admin \
  --from-literal=admin-password="$GRAFANA_PASSWORD" \
  -n strix --dry-run=client -o yaml | kubectl apply -f -
```

#### 6. Rotate Tenant API Keys
```bash
# Via API (bulk rotation script)
#!/bin/bash
for tenant in $(curl -s -H "Authorization: Bearer $ADMIN_KEY" http://strix.example.com/api/tenants | jq -r '.[] | .id'); do
  # Generate new key for tenant
  NEW_KEY=$(openssl rand -base64 32 | tr -d '\n')
  curl -X POST "http://strix.example.com/api/keys/rotate/$tenant" \
    -H "Authorization: Bearer $ADMIN_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"new_key\": \"$NEW_KEY\"}"
  
  # Notify tenant (send email with new key)
  echo "Tenant $tenant key rotated" | mail -s "Strix API Key Rotation" tenant@example.com
done
```

### Emergency Rotation (Compromise - SEV-1)

```bash
# 1. IMMEDIATELY revoke compromised keys
# If admin key compromised:
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "
UPDATE api_keys SET revoked = 1 WHERE prefix = 'sk_live_compromised';
"

# 2. Generate and apply new secrets (same as above but skip verification steps)
# 3. Force all pods to restart
kubectl rollout restart deployment/strix-api deployment/strix-scheduler deployment/strix-worker -n strix

# 4. Rotate Redis/PostgreSQL if infrastructure credentials compromised
# 5. Invalidate all sessions
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "DELETE FROM sessions;"

# 6. Notify security team and affected tenants
# See security-incident.md
```

### Audit HMAC Key Rotation (Special Procedure)

```bash
# WARNING: Rotating audit HMAC key invalidates existing audit chain verification
# Only rotate if key compromised or per policy with planned re-hashing

# 1. Generate new HMAC key
NEW_HMAC_KEY=$(openssl rand -base64 48 | tr -d '\n')

# 2. Stop all writers
kubectl scale deployment strix-api -n strix --replicas=0
kubectl scale deployment strix-scheduler -n strix --replicas=0

# 3. Re-hash audit chain with new key
kubectl exec -n strix strix-api-xxx -- /usr/local/bin/python -c "
from strix.audit import rehash_chain
import os
os.environ['STRIX_AUDIT_HMAC_KEY'] = '$NEW_HMAC_KEY'
rehash_chain('/var/lib/strix/strix.db')
"

# 4. Update secret
kubectl patch secret strix-secrets -n strix -p "{\"data\":{\"STRIX_AUDIT_HMAC_KEY\":\"$(echo -n $NEW_HMAC_KEY | base64)\"}}"

# 5. Restart services
kubectl scale deployment strix-api -n strix --replicas=3
kubectl scale deployment strix-scheduler -n strix --replicas=1

# 6. Verify audit chain
curl -s -H "Authorization: Bearer $ADMIN_KEY" http://strix.example.com/api/audit/verify | jq .
```

---

## Escalation & SLA

| Scenario | Response Time | Escalation Path |
|----------|---------------|-----------------|
| **Scheduled Rotation** | Planned window | Platform Team |
| **Suspected Compromise (SEV-1)** | 15 minutes | On-call → Security Lead → CISO |
| **Confirmed Compromise (SEV-1)** | 15 minutes | On-call → Security Lead → CISO → Legal |

**SLA Targets:**
- Scheduled rotation: Complete within 4-hour maintenance window
- Emergency rotation: Complete within 30 minutes
- Tenant notification: Within 1 hour of rotation

**Contacts:**
- Platform On-Call: `platform-oncall@example.com`
- Security Team: `security@example.com`
- CISO: `ciso@example.com`

---

## Post-Incident Actions

1. **Verify all services healthy** after rotation
2. **Update secret store** (Vault, 1Password, etc.) with new values
3. **Revoke old secrets** from all systems
4. **Audit access logs** for anomalous use of old secrets
5. **Update runbook** with any new procedures
6. **Schedule next rotation** (90 days from now)

---

## Grafana Dashboard Links

- **Secret Rotation Tracking**: `https://grafana.example.com/d/strix-secrets/secret-rotation`
- **Auth Metrics**: `https://grafana.example.com/d/strix-auth/auth-metrics`

**Key Panels:**
- Secret Age by Type (table)
- Rotation History (timeline)
- Auth Failure Rate Post-Rotation (time series)
- Active API Keys by Tenant (heatmap)
# Security Incident Runbook

## Alert Triggers

| Alert | Severity | Source |
|-------|----------|--------|
| `StrixAuditChainVerificationFailed` | critical | Audit chain tampering detected |
| `StrixAuditChainLengthAnomaly` | warning | Audit chain length decreased |
| `StrixAuthFailureBurst` | critical | Authentication failure burst |
| `StrixCriticalFindingsNew` | warning | New critical findings detected |
| Manual report | - | Tenant report, external researcher |

---

## Incident Classification

| Type | Examples | Initial Severity |
|------|----------|------------------|
| **Findings Exposure** | Unauthorized access to assessment results | SEV-1 |
| **Scope Bypass** | Scanning unauthorized targets | SEV-1 |
| **Credential Compromise** | API key leak, token theft | SEV-1 |
| **Audit Tampering** | Modified/deleted audit logs | SEV-1 |
| **Infrastructure Compromise** | Container escape, node access | SEV-1 |
| **Data Exfiltration** | Bulk findings download | SEV-1 |
| **Vulnerability in Strix** | RCE, SQLi, auth bypass in platform | SEV-1 |
| **Denial of Service** | Resource exhaustion, queue saturation | SEV-2 |

---

## Immediate Response (First 15 Minutes)

### 1. Acknowledge & Assemble
```bash
# Page on-call security engineer
# Create incident channel: #incident-YYYYMMDD-XXX
# Assign Incident Commander (IC)
# Assign Scribe (document everything)
```

### 2. Contain (Stop the Bleeding)
```bash
# If API key compromised - REVOKE IMMEDIATELY
curl -X POST http://strix.example.com/api/keys/revoke/<TENANT_ID> \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{"key_prefix": "sk_live_compromised"}'

# If active attack - BLOCK SOURCE IPs
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-attacker-$(date +%s)
  namespace: strix
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: strix
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 203.0.113.0/24  # ATTACKER IP
EOF

# If audit chain tampered - STOP WRITERS
kubectl scale deployment strix-api -n strix --replicas=0
kubectl scale deployment strix-scheduler -n strix --replicas=0

# Preserve forensic evidence
kubectl exec -n strix strix-api-xxx -- cp /var/lib/strix/strix.db /var/lib/strix/strix.db.forensic.$(date +%s)
```

### 3. Assess Impact
```bash
# Check what data was accessed
# 1. Audit log query for suspicious activity
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "
SELECT * FROM audit_log
WHERE timestamp > datetime('now', '-24 hours')
AND (actor = '<suspect_tenant>' OR action IN ('scope_violation', 'findings_export', 'key_rotation'))
ORDER BY timestamp DESC;
"

# 2. Check findings accessed
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "
SELECT f.*, j.target, j.tenant_id FROM findings f
JOIN jobs j ON f.job_id = j.id
WHERE j.tenant_id = '<suspect_tenant>'
AND f.created_at > datetime('now', '-24 hours');
"

# 3. Check webhook deliveries
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "
SELECT * FROM webhook_deliveries
WHERE created_at > datetime('now', '-24 hours')
AND status = 'delivered';
"
```

---

## Investigation Procedures

### Forensic Evidence Collection
```bash
# 1. Database snapshot
kubectl cp strix/strix-api-xxx:/var/lib/strix/strix.db /forensics/strix.db.$(date +%s)

# 2. Application logs (last 72 hours)
kubectl logs -n strix -l app.kubernetes.io/name=strix,component=api --since=72h > /forensics/api-logs.$(date +%s).txt
kubectl logs -n strix -l app.kubernetes.io/name=strix,component=scheduler --since=72h > /forensics/scheduler-logs.$(date +%s).txt

# 3. Kubernetes audit logs
kubectl get events -A --sort-by=.metadata.creationTimestamp > /forensics/k8s-events.$(date +%s).txt

# 4. Network flows (if available)
# VPC flow logs, CloudTrail, etc.

# 5. Access logs (ingress/nginx)
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx --since=72h > /forensics/ingress-logs.$(date +%s).txt
```

### Scope Bypass Investigation
```bash
# 1. Identify all scope violations
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "
SELECT actor, target, timestamp, user_agent FROM audit_log
WHERE action = 'scope_violation'
ORDER BY timestamp DESC;
"

# 2. Check if any violations resulted in completed scans
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "
SELECT j.id, j.target, j.state, j.tenant_id, j.created_at FROM jobs j
JOIN audit_log a ON j.tenant_id = a.actor
WHERE a.action = 'scope_violation'
AND j.state = 'completed'
AND j.created_at > a.timestamp;
"

# 3. Determine if findings generated from unauthorized scans
# If YES: Invalidate findings, notify affected parties
```

### Credential Compromise Investigation
```bash
# 1. Check key usage patterns
kubectl exec -n strix strix-api-xxx -- sqlite3 /var/lib/strix/strix.db "
SELECT k.prefix, k.tenant_id, k.last_used, k.created_at,
       COUNT(a.id) as api_calls
FROM api_keys k
LEFT JOIN audit_log a ON a.actor = k.tenant_id
WHERE k.revoked = 0
GROUP BY k.id
ORDER BY api_calls DESC;
"

# 2. Check for anomalous geolocation/IP
# Requires logging client IPs in audit_log

# 3. Rotate all keys for affected tenant (see secret-rotation.md)
```

### Audit Chain Tampering Investigation
```bash
# 1. Verify current chain state
curl -s -H "Authorization: Bearer $ADMIN_KEY" http://strix.example.com/api/audit/verify | jq .

# 2. Check secret presence and review secret-manager version history; never print
# the environment or secret value.
kubectl get secret strix-secrets -n strix \
  -o 'jsonpath={.data.STRIX_AUDIT_HMAC_KEY}' | grep -q .

# 3. If the API is unavailable and the database is SQLite, verify a forensic
# copy with scripts/operational_check.py in a protected maintenance environment.
# For PostgreSQL, use the application's supported verification path.

# 4. If tampered: restore from last known-good backup
# See disaster-recovery.md
```

---

## Communication Templates

### Internal SEV-1 Alert
```
[SEV-1] Strix Security Incident
Time: <ISO8601 timestamp>
Type: <Findings Exposure / Scope Bypass / Credential Compromise / etc.>
Impact: <Number of tenants affected, data exposed>
Confirmed: <Yes/No/Investigating>
Actions Taken: <Containment steps>
IC: <Name>
Scribe: <Name>
Channel: #incident-YYYYMMDD-XXX
War Room: <Video conference link>
```

### Customer Notification (If Data Exposed)
```
Subject: Security Incident Notification - Strix Assessment Platform

Date: <Date>
Incident ID: INC-YYYYMMDD-XXX

We detected a security incident on <date> affecting your account.

What happened:
<Brief description - e.g., "An unauthorized party gained access to assessment findings for target X using compromised API credentials.">

What data was involved:
- Assessment findings for: <target(s)>
- Time period: <date range>
- Data types: <vulnerability details, evidence, etc.>

What we've done:
- Revoked compromised credentials
- Invalidated any unauthorized findings
- Initiated forensic investigation
- Notified law enforcement (if applicable)

What you should do:
- Rotate your API keys immediately
- Review any webhook deliveries from the affected period
- Contact us if you notice unusual activity

We take this seriously and are implementing additional safeguards.
Contact: security@example.com | +1-XXX-XXX-XXXX
```

### Regulatory Notification (If Required)
```
Per <GDPR Art. 33 / CCPA / SOX / etc.> notification requirement:

Incident: <Description>
Personal Data Involved: <Yes/No - Details>
Number of Data Subjects: <Number>
Likely Consequences: <Assessment>
Measures Taken: <Containment, investigation, notification>
DPO Contact: dpo@example.com
```

---

## Eradication & Recovery

### 1. Remove Threat Actor Access
```bash
# Revoke all compromised credentials
# Rotate all secrets (see secret-rotation.md)
# Block attacker IPs at network level
# Patch exploited vulnerabilities
```

### 2. Restore Integrity
```bash
# If audit chain tampered: restore from backup + re-hash
# If findings corrupted: delete unauthorized findings
# If database corrupted: restore from backup
```

### 3. Verify Clean State
```bash
# Full health check
curl -s http://strix.example.com/api/health
curl -s http://strix.example.com/api/ready
curl -s -H "Authorization: Bearer $ADMIN_KEY" http://strix.example.com/api/audit/verify

# No unauthorized access in last 24h
# All scope gates functioning
# All tenant keys rotated
```

---

## Post-Incident Actions (Within 5 Business Days)

1. **Root Cause Analysis (RCA)**
   - Timeline reconstruction
   - Root cause identification
   - Contributing factors

2. **Action Items**
   - Technical fixes (patches, config changes)
   - Process improvements (monitoring, response)
   - Security enhancements (MFA, key rotation, etc.)

3. **Documentation**
   - Update runbooks
   - Update architecture decision records
   - Create incident report

4. **Notifications**
   - Affected customers
   - Regulators (if required)
   - Insurance (if applicable)

5. **Retrospective**
   - Blameless postmortem
   - Action item tracking
   - Follow-up review in 30 days

---

## Escalation & SLA

| Phase | Time Limit | Owner |
|-------|------------|-------|
| Detection → Acknowledgment | 15 min | On-call |
| Acknowledgment → Containment | 30 min | IC |
| Containment → Assessment | 2 hours | IC + Security Team |
| Assessment → Customer Notification | 4 hours | IC + Legal |
| Customer Notification → RCA Complete | 5 business days | Security Lead |
| RCA → Action Items Complete | 30 days | Platform Lead |

**Contacts:**
- Security On-Call: `security-oncall@example.com` (PagerDuty)
- Platform On-Call: `platform-oncall@example.com`
- Legal: `legal@example.com`
- CISO: `ciso@example.com`
- Law Enforcement: (as needed)

---

## Grafana Dashboard Links

- **Security Overview**: `https://grafana.example.com/d/strix-security/security-overview`
- **Audit Chain**: `https://grafana.example.com/d/strix-audit/audit-chain`
- **Auth Failures**: `https://grafana.example.com/d/strix-auth/auth-failures`

**Key Panels:**
- Audit Chain Verification Status (stat)
- Scope Violations by Tenant (time series)
- Auth Failure Rate by Reason (bar chart)
- Findings Access Patterns (heatmap)
- API Key Usage Anomalies (table)
- Webhook Delivery Status (time series)
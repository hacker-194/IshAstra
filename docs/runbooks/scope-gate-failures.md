# Scope Gate Failures Runbook

## Alert Triggers

| Alert | Severity | Source |
|-------|----------|--------|
| `IshAstraAuthFailureRateHigh` | warning | Auth failures > 10/s |
| `IshAstraAuthFailureBurst` | critical | Auth failures > 50/min |
| No direct alert | - | Scope violations logged in application |

---

## Symptoms & Impact

**Symptoms:**
- HTTP 403 responses from `/api/assess` with "Target not within authorized scope"
- Logs show `ScopeGate: Target https://evil.com rejected`
- Repeated violations from same API key/tenant
- Audit log entries with `action: "scope_violation"`

**Impact:**
- **SEV-1** (confirmed bypass): Unauthorized targets scanned, findings exposed
- **SEV-2** (repeated violations): Potential credential compromise or misconfiguration
- **SEV-3** (isolated violations): Misconfigured tenant scope, no breach

---

## Diagnosis Commands

### 1. Check Scope Violation Logs
```bash
# Search application logs for scope violations
kubectl logs -n ishastra -l app.kubernetes.io/name=ishastra,component=api --tail=500 | grep -i "scope violation"

# Check audit log for violations
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "
SELECT * FROM audit_log
WHERE action = 'scope_violation'
ORDER BY timestamp DESC LIMIT 20;
"

# Check by tenant
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "
SELECT actor, target, count(*) as violations
FROM audit_log
WHERE action = 'scope_violation'
GROUP BY actor
ORDER BY violations DESC;
"
```

### 2. Verify Scope Configuration
```bash
# View current scope.json
kubectl exec -n ishastra ishastra-api-xxx -- cat /etc/ishastra/scope.json | jq .

# Check scope mode
kubectl exec -n ishastra ishastra-api-xxx -- env | grep ISHASTRA_SCOPE_MODE

# Validate scope syntax
kubectl exec -n ishastra ishastra-api-xxx -- /usr/local/bin/python -c "
from ishastra.scope import Scope
import json
with open('/etc/ishastra/scope.json') as f:
    scope = Scope(**json.load(f))
print('Scope valid:', scope)
print('Include:', scope.include)
print('Exclude:', scope.exclude)
print('Networks:', scope.authorized_networks)
"
```

### 3. Test Scope Gate Logic
```bash
# Test allowed target
curl -X POST http://ishastra.example.com/api/assess \
  -H "Authorization: Bearer $TENANT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://allowed.example.com", "profile": "web"}'

# Test blocked target (should return 403)
curl -X POST http://ishastra.example.com/api/assess \
  -H "Authorization: Bearer $TENANT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://evil.com", "profile": "web"}'

# Test with debug to see scope decision
curl -X POST http://ishastra.example.com/api/assess \
  -H "Authorization: Bearer $TENANT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://test.example.com", "profile": "web", "debug": true}'
```

### 4. Check API Key & Tenant Status
```bash
# List API keys for tenant
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "
SELECT id, name, prefix, revoked, created_at FROM api_keys WHERE tenant_id = 'acme-corp';
"

# Check for compromised key patterns
kubectl logs -n ishastra -l app.kubernetes.io/name=ishastra,component=api --tail=1000 | grep "scope violation" | awk '{print $NF}' | sort | uniq -c | sort -rn
```

---

## Resolution Procedures

### Immediate Mitigation (SEV-1/SEV-2)

#### 1. Revoke Compromised API Key
```bash
# Via API (requires admin key)
curl -X POST http://ishastra.example.com/api/keys/revoke/<TENANT_ID> \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key_prefix": "sk_live_abc123"}'

# Or via database directly
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "
UPDATE api_keys SET revoked = 1 WHERE prefix = 'sk_live_abc123';
"
```

#### 2. Block Malicious Source IPs
```bash
# Add to network policy deny list
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-malicious-ips
  namespace: ishastra
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: ishastra
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 203.0.113.0/24  # Attacker IP
EOF
```

#### 3. Tighten Scope Temporarily
```bash
# Restrict scope to known good targets only
kubectl exec -n ishastra ishastra-api-xxx -- cat > /etc/ishastra/scope.json.emergency <<'SCOPE'
{
  "program": "Emergency Restricted Scope",
  "authorized_by": "Security Team",
  "authorization_ref": "INC-2024-XXXX",
  "include": ["app.example.com", "api.example.com"],
  "exclude": [],
  "authorized_networks": ["10.0.0.0/8"],
  "allowed_ports": [443],
  "allow_broad_networks": false,
  "auth": {"users": []}
}
SCOPE

# Apply (requires pod restart or SIGHUP)
kubectl exec -n ishastra ishastra-api-xxx -- cp /etc/ishastra/scope.json.emergency /etc/ishastra/scope.json
kubectl rollout restart deployment/ishastra-api -n ishastra
```

### Root Cause Resolution

#### Cause 1: Overly Broad Scope Configuration
```bash
# Audit scope for wildcard issues
kubectl exec -n ishastra ishastra-api-xxx -- /usr/local/bin/python -c "
from ishastra.scope import Scope
import json
with open('/etc/ishastra/scope.json') as f:
    scope = Scope(**json.load(f))

# Check for overly broad patterns
for pattern in scope.include:
    if pattern.count('*') > 1 or pattern == '*':
        print(f'WARNING: Overly broad pattern: {pattern}')

for net in scope.authorized_networks:
    if net in ['0.0.0.0/0', '::/0']:
        print(f'WARNING: Open network: {net}')
"

# Fix: Restrict scope to specific domains/networks
# Update ConfigMap
kubectl edit configmap ishastra-config -n ishastra
```

#### Cause 2: Credential Leak / Compromise
```bash
# 1. Rotate all keys for affected tenant
curl -X POST http://ishastra.example.com/api/keys/rotate/<TENANT_ID> \
  -H "Authorization: Bearer $ADMIN_KEY"

# 2. Force re-authentication
kubectl exec -n ishastra ishastra-api-xxx -- sqlite3 /var/lib/ishastra/ishastra.db "
DELETE FROM sessions WHERE tenant_id = 'acme-corp';
"

# 3. Notify tenant
# Send incident notification per security-incident.md runbook
```

#### Cause 3: Scope Validation Bug
```bash
# Check IshAstra version for known scope bugs
kubectl exec -n ishastra ishastra-api-xxx -- /usr/local/bin/ishastra --version

# Test edge cases
kubectl exec -n ishastra ishastra-api-xxx -- /usr/local/bin/python -m pytest tests/test_scope.py -v

# If bug confirmed, apply hotfix or upgrade
# See upgrade-ishastra.md
```

#### Cause 4: Tenant Misconfiguration
```bash
# Review tenant scope with tenant
# Provide guidance on proper scope configuration

# Example secure scope:
# {
#   "include": ["app.company.com", "api.company.com"],
#   "exclude": ["staging.company.com", "dev.company.com"],
#   "authorized_networks": ["10.0.0.0/8", "172.16.0.0/12"],
#   "allowed_ports": [443, 8443],
#   "allow_broad_networks": false
# }
```

### Recovery Verification
```bash
# 1. Verify scope gate blocks unauthorized
curl -X POST http://ishastra.example.com/api/assess \
  -H "Authorization: Bearer $TENANT_KEY" \
  -d '{"target": "https://evil.com", "profile": "web"}'
# Expect 403

# 2. Verify authorized targets still work
curl -X POST http://ishastra.example.com/api/assess \
  -H "Authorization: Bearer $TENANT_KEY" \
  -d '{"target": "https://app.example.com", "profile": "web"}'
# Expect 202

# 3. Monitor for further violations
# PromQL: sum(rate(ishastra_scope_gate_decisions_total{decision="blocked"}[5m]))  # expect 0
```

---

## Escalation & SLA

| Severity | Response Time | Escalation Path |
|----------|---------------|-----------------|
| **Confirmed Bypass (SEV-1)** | 15 minutes | On-call → Security Lead → CISO |
| **Repeated Violations (SEV-2)** | 30 minutes | On-call → Security Team |
| **Misconfiguration (SEV-3)** | 4 hours | On-call → Platform Team |

**SLA Targets:**
- Scope violation detection: < 1 minute
- Key revocation: < 5 minutes
- Tenant notification: < 1 hour (if data exposed)

**Contacts:**
- Platform On-Call: `platform-oncall@example.com`
- Security Team: `security@example.com`
- CISO: `ciso@example.com`

---

## Post-Incident Actions

1. **Forensic analysis** - determine if unauthorized scans completed
2. **Findings review** - invalidate findings from unauthorized scans
3. **Tenant notification** - if data exposed (per security-incident.md)
4. **Scope configuration audit** - all tenants
5. **Credential rotation** - affected and related keys
6. **Detection improvement** - add more granular scope violation alerts

---

## Grafana Dashboard Links

- **IshAstra Security**: `https://grafana.example.com/d/ishastra-security/security-overview`
- **Auth Failures**: `https://grafana.example.com/d/ishastra-auth/auth-failures`

**Key Panels:**
- Scope Violations by Tenant (time series)
- Auth Failure Rate by Reason (bar chart)
- Top Violating IPs (table)
- API Key Usage by Tenant (heatmap)
- Scope Gate Decisions (allowed/blocked) (pie chart)
---

## Revocation incident

Use when an authorization was issued to the wrong party, an engagement ended
early, or a signed scope document may have leaked.

```python
from ishastra.core.scope import revoke_scope

# A signed document must be re-signed: revocation changes signed fields.
revoke_scope(
    "scope.json",
    revoked_by="sec-lead@example.com",
    reason="engagement ended early (ticket SEC-412)",
    private_key="scope-signing-key.pem",
    kid="2026-12",
)
```

1. **Revoke before investigating.** A running job is stopped at its next adapter
   boundary: `bound` re-checks the snapshot and `is_valid()` refuses a revoked
   scope.
2. **Re-publish the document.** A verifier that still has the old copy is fine:
   it was signed with an older `issued_at`, and `ISHASTRA_SCOPE_MAX_AGE_SECONDS`
   (default 24h) refuses it as stale once the limit passes. Do not raise that
   limit to keep a verifier working.
3. **Retire the key if the private key itself leaked.** Remove the `kid` from
   the JWKS, publish the new set, and sign with the replacement `kid`. A
   document signed by a retired `kid` fails with "not in the configured key
   set", not a silent fallback to unsigned.
4. **Confirm the refusals are visible.** `ishastra_scope_gate_decisions_total{decision="blocked",reason="revoked"}`
   must move; a revocation nobody observes is a revocation nobody trusts.
5. **Leave the trail.** The revocation is auditable from the document itself
   (`revoked`, `revoked_at`, `revoked_by`, `revocation_reason`) and from the
   `security_denied` audit event emitted for each refused call.

## Emergency allowlisting

Temporary widening while an incident is live. It is never a permanent edit.

1. **Mint a short-lived document, not a wider one.**
   `ishastra scope-sign --scope scope.json --key scope-signing-key.pem --kid 2026-12 --expires-in 2h`
   stamps `expires_at`; the gate refuses the scope after it, with no cleanup
   step to remember.
2. **Add exact hosts, never networks.** `include` entries are single hostnames
   or `*.domain`; `authorized_networks` makes internal ranges reachable and a
   broad entry (anything wider than /8) needs `allow_broad_networks`, which is
   a deliberate second decision, not a convenience flag.
3. **Record the approval.** `authorized_by` and `authorization_ref` are signed
   fields: put the incident ticket there so the document itself says who
   approved the widening and why.
4. **End it explicitly.** Revoke the temporary document (see above). If it is
   forgotten, the freshness bound still retires it; that is a backstop, not the
   plan.
5. **Never** restore access by disabling signature verification or removing
   `ISHASTRA_SCOPE_JWKS`: that turns a scoped incident into a global one.

## `policy_unavailable` denials

`reason="policy_unavailable"` means the gate refused because a policy it must
enforce had no usable data source: `ISHASTRA_SCOPE_JIT_URL` unreachable or answering
non-200, or `allowed_asns` / `allowed_countries` set without a working lookup.
This is the fail-closed state working as designed. Check the decision point and
the intel tables first; restoring them clears the denials. Do not clear the
policy to make the denials stop.

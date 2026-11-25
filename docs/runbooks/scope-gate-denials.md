# Runbook: High Scope Gate Denial Rate

# Runbook: High Scope Gate Denial Rate

**Alert**: `IshAstraScopeGateDenialsHigh`
**Severity**: Warning
**Team**: Platform

## Symptoms

- `rate(scope_gate_denials_total[5m]) > 10`
- Assessments failing with "Target not authorized by scope"
- Increased 422 Unprocessable Entity responses

## Investigation Steps

### 1. Check Denial Breakdown

```bash
# By layer
kubectl exec -n ishastra-system deploy/ishastra-api -- curl -s localhost:8000/metrics | grep scope_gate_layer

# By scope
kubectl exec -n ishastra-system deploy/ishastra-api -- curl -s localhost:8000/metrics | grep scope_gate_denials | sort -k2 -nr | head -20
```

### 2. Check Recent Assessment Failures

```bash
kubectl logs -n ishastra-system -l app=ishastra-worker --tail=500 | grep -i "denied\|scope_gate" | head -20
```

### 3. Verify Scope Configuration

```bash
# List active scopes
ishastra scope list --status active

# Show the active policy the caller is judged against
curl -s http://localhost:8000/api/scope -H "Authorization: Bearer $KEY"

# Test specific target
ishastra scope test --scope scope_prod_001 --url https://target.example.com
```

## Common Causes & Fixes

| Cause | Diagnosis | Fix |
|-------|-----------|-----|
| Misconfigured CIDR | Layer 2 denials, IP not in authorized_networks | Update scope authorized_networks |
| Host not in include_hosts | Layer 1 denials, host suffix mismatch | Add host to include_hosts or fix wildcard |
| Host in exclude_hosts | Layer 1 denials, explicit block | Remove from exclude_hosts |
| Port not allowed | Layer 1 denials, port not in allowed_ports | Add port to allowed_ports |
| DNS resolution failure | Layer 2 denials, DNS timeout/error | Check DNS resolver config, increase timeout |
| Expired scope | All layers, scope status != active | Activate or extend scope expiry |

## Escalation

1. **15 min**: Platform on-call
2. **1 hour**: Security team (if production assessments affected)

## Post-Incident

- [ ] Document scope configuration change
- [ ] Add test case for denied target pattern
- [ ] Review scope change approval process

## Related

- [Scope Gate Concepts](../scope-gate/concepts.md)
- [Scope Gate Configuration](../scope-gate/configuration.md)
- [Monitoring](../deployment/monitoring.md)
# Runbook: API Down

# Runbook: Strix API Down

**Alert**: `StrixAPIDown`
**Severity**: Critical
**Team**: Platform

## Symptoms

- API health endpoint returns 5xx or times out
- `up{job="strix-api"} == 0` for > 2 minutes
- Users report unable to access Strix API
- Dashboard shows API pods as NotReady

## Investigation Steps

### 1. Check Pod Status

```bash
kubectl get pods -n strix-system -l app=strix-api
kubectl describe pod -n strix-system -l app=strix-api
kubectl logs -n strix-system -l app=strix-api --tail=100
```

### 2. Check Deployment Status

```bash
kubectl get deployment strix-api -n strix-system
kubectl rollout status deployment/strix-api -n strix-system
```

### 3. Check Resource Constraints

```bash
kubectl top pods -n strix-system -l app=strix-api
kubectl describe node | grep -A 5 "Allocated resources"
```

### 4. Check Dependencies

```bash
# Database connectivity
kubectl exec -n strix-system deploy/strix-api -- curl -s http://localhost:8000/health/detailed

# Redis connectivity
kubectl exec -n strix-system deploy/strix-api -- redis-cli -h strix-redis ping

# Scope Gate self-test
kubectl exec -n strix-system deploy/strix-api -- strix scope-gate test --scope scope_prod_001
```

## Common Causes & Fixes

| Cause | Diagnosis | Fix |
|-------|-----------|-----|
| OOM Killed | `kubectl describe pod` shows `OOMKilled` | Increase memory limit in Helm values |
| CrashLoopBackOff | Container exits immediately | Check logs for panic/error |
| Database unavailable | Health check shows DB error | Check PostgreSQL pod, connections |
| Redis unavailable | Health check shows Redis error | Check Redis pod, connection pool |
| Config error | Logs show config validation failure | Check ConfigMap/Secret values |
| Image pull error | `ImagePullBackOff` in events | Verify GHCR credentials, image tag |

## Escalation

1. **5 min**: Platform on-call
2. **15 min**: Platform lead + Security lead
3. **30 min**: Engineering director

## Post-Incident

- [ ] Update runbook with new findings
- [ ] Add monitoring for root cause indicator
- [ ] Schedule postmortem within 48 hours

## Related

- [Kubernetes Deployment](../deployment/kubernetes.md)
- [Monitoring](../deployment/monitoring.md)
- [Worker OOM Runbook](worker-oom.md)
- [DB Connections Runbook](db-connections.md)
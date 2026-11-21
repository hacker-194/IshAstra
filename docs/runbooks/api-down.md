# Runbook: API Down

# Runbook: Ishastra API Down

**Alert**: `IshastraAPIDown`
**Severity**: Critical
**Team**: Platform

## Symptoms

- API health endpoint returns 5xx or times out
- `up{job="ishastra-api"} == 0` for > 2 minutes
- Users report unable to access Ishastra API
- Dashboard shows API pods as NotReady

## Investigation Steps

### 1. Check Pod Status

```bash
kubectl get pods -n ishastra-system -l app=ishastra-api
kubectl describe pod -n ishastra-system -l app=ishastra-api
kubectl logs -n ishastra-system -l app=ishastra-api --tail=100
```

### 2. Check Deployment Status

```bash
kubectl get deployment ishastra-api -n ishastra-system
kubectl rollout status deployment/ishastra-api -n ishastra-system
```

### 3. Check Resource Constraints

```bash
kubectl top pods -n ishastra-system -l app=ishastra-api
kubectl describe node | grep -A 5 "Allocated resources"
```

### 4. Check Dependencies

```bash
# Database connectivity
kubectl exec -n ishastra-system deploy/ishastra-api -- curl -s http://localhost:8000/health/detailed

# Redis connectivity
kubectl exec -n ishastra-system deploy/ishastra-api -- redis-cli -h ishastra-redis ping

# Scope Gate self-test
kubectl exec -n ishastra-system deploy/ishastra-api -- ishastra scope-gate test --scope scope_prod_001
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
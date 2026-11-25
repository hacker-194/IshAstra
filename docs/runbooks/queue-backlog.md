# Runbook: Assessment Queue Backlog

# Runbook: Assessment Queue Backlog

**Alert**: `IshAstraQueueDepthHigh`
**Severity**: Warning
**Team**: Platform

## Symptoms

- `ishastra_queue_depth > 1000` for > 10 minutes
- Assessments stuck in "pending" status
- Increased time-to-completion for assessments

## Investigation Steps

### 1. Check Queue Status

```bash
# Queue depth
kubectl exec -n ishastra-system deploy/ishastra-api -- curl -s localhost:8000/metrics | grep ishastra_queue_depth

# Pending assessments
ishastra assessment list --status pending --limit 20

# Worker count
kubectl get pods -n ishastra-system -l app=ishastra-worker
```

### 2. Check Worker Health

```bash
# Worker logs
kubectl logs -n ishastra-system -l app=ishastra-worker --tail=200

# Worker resource usage
kubectl top pods -n ishastra-system -l app=ishastra-worker

# Active tasks per worker
kubectl exec -n ishastra-system deploy/ishastra-api -- curl -s localhost:8000/metrics | grep ishastra_worker_active_tasks
```

### 3. Check Scheduler

```bash
# Scheduler status
kubectl get pods -n ishastra-system -l app=ishastra-scheduler
kubectl logs -n ishastra-system -l app=ishastra-scheduler --tail=100
```

## Common Causes & Fixes

| Cause | Diagnosis | Fix |
|-------|-----------|-----|
| Insufficient workers | Queue depth high, few workers | Scale worker deployment: `kubectl scale deployment ishastra-worker --replicas=N` |
| Workers OOM killed | `container_oom_kills_total` increasing | Increase memory limit in Helm values |
| Long-running assessments | High `ishastra_assessment_duration_seconds` | Check adapter timeouts, reduce scope |
| Scheduler not triggering | No new assessments from cron | Check scheduler logs and worker lease ownership |
| Redis queue issues | Queue depth metric not updating | Check Redis connectivity, memory |

## Scaling Workers

```bash
# Manual scale
kubectl scale deployment ishastra-worker -n ishastra-system --replicas=10

# Or via Helm
helm upgrade ishastra ./kubernetes/helm/ishastra -n ishastra-system --set worker.replicas=10

# Enable HPA (if not enabled)
# Do not autoscale: one process owns the database lease. Add CPU/RAM or raise
# ISHASTRA_WORKERS instead (see docs/quickstart/production.md).
```

## Escalation

1. **30 min**: Platform on-call
2. **2 hours**: Platform lead

## Post-Incident

- [ ] Review worker autoscaling configuration
- [ ] Update capacity planning
- [ ] Document root cause

## Related

- [Kubernetes Deployment](../deployment/kubernetes.md)
- [Helm Deployment](../deployment/helm.md)
- [Monitoring](../deployment/monitoring.md)
- [Worker OOM Runbook](worker-oom.md)
# Runbook: Assessment Queue Backlog
# Supersedes: No previous runbook existed
# Linked from: docs/deployment/monitoring.md (PrometheusRule StrixQueueDepthHigh)
# User instruction: "update all"

# Runbook: Assessment Queue Backlog

**Alert**: `StrixQueueDepthHigh`
**Severity**: Warning
**Team**: Platform

## Symptoms

- `strix_queue_depth > 1000` for > 10 minutes
- Assessments stuck in "pending" status
- Increased time-to-completion for assessments

## Investigation Steps

### 1. Check Queue Status

```bash
# Queue depth
kubectl exec -n strix-system deploy/strix-api -- curl -s localhost:8000/metrics | grep strix_queue_depth

# Pending assessments
strix assessment list --status pending --limit 20

# Worker count
kubectl get pods -n strix-system -l app=strix-worker
```

### 2. Check Worker Health

```bash
# Worker logs
kubectl logs -n strix-system -l app=strix-worker --tail=200

# Worker resource usage
kubectl top pods -n strix-system -l app=strix-worker

# Active tasks per worker
kubectl exec -n strix-system deploy/strix-api -- curl -s localhost:8000/metrics | grep strix_worker_active_tasks
```

### 3. Check Scheduler

```bash
# Scheduler status
kubectl get pods -n strix-system -l app=strix-scheduler
kubectl logs -n strix-system -l app=strix-scheduler --tail=100
```

## Common Causes & Fixes

| Cause | Diagnosis | Fix |
|-------|-----------|-----|
| Insufficient workers | Queue depth high, few workers | Scale worker deployment: `kubectl scale deployment strix-worker --replicas=N` |
| Workers OOM killed | `container_oom_kills_total` increasing | Increase memory limit in Helm values |
| Long-running assessments | High `strix_assessment_duration_seconds` | Check adapter timeouts, reduce scope |
| Scheduler not triggering | No new assessments from cron | Check scheduler logs and worker lease ownership |
| Redis queue issues | Queue depth metric not updating | Check Redis connectivity, memory |

## Scaling Workers

```bash
# Manual scale
kubectl scale deployment strix-worker -n strix-system --replicas=10

# Or via Helm
helm upgrade strix ./kubernetes/helm/strix -n strix-system --set worker.replicas=10

# Enable HPA (if not enabled)
kubectl autoscale deployment strix-worker -n strix-system --min=3 --max=20 --cpu-percent=70
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
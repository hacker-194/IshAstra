# Runbook: Worker OOM Killed

# Runbook: Worker OOM Killed

**Alert**: `IshAstraWorkerOOMKilled`
**Severity**: Critical
**Team**: Platform

## Symptoms

- `increase(container_oom_kills_total{container="worker"}[10m]) > 0`
- Worker pods restarting frequently
- Assessments failing with worker lost errors
- Queue backlog increasing

## Investigation Steps

### 1. Identify Affected Workers

```bash
# Check OOM events
kubectl get events -n ishastra-system --field-selector reason=OOMKilling

# Pod status
kubectl get pods -n ishastra-system -l app=ishastra-worker -o wide

# Recent logs
kubectl logs -n ishastra-system -l app=ishastra-worker --previous --tail=100
```

### 2. Check Memory Usage

```bash
# Current memory usage
kubectl top pods -n ishastra-system -l app=ishastra-worker

# Memory limits
kubectl get deployment ishastra-worker -n ishastra-system -o yaml | grep -A 5 "resources:"

# Container memory metrics
kubectl exec -n ishastra-system deploy/ishastra-api -- curl -s localhost:8000/metrics | grep container_memory
```

### 3. Analyze Memory Patterns

```bash
# Check for memory leaks in worker logs
kubectl logs -n ishastra-system -l app=ishastra-worker --tail=500 | grep -i "memory\|oom\|alloc"

# Check adapter memory usage
kubectl logs -n ishastra-system -l app=ishastra-worker --tail=500 | grep -E "adapter.*memory|memory.*adapter"
```

## Common Causes & Fixes

| Cause | Diagnosis | Fix |
|-------|-----------|-----|
| Memory limit too low | Usage near limit, OOM on spike | Increase `worker.resources.limits.memory` in Helm values |
| Memory leak | Steady increase over time | Profile with `pprof`, check adapter cleanup |
| Large assessment | Single assessment uses too much | Add per-assessment memory limits, chunk targets |
| Adapter memory | Specific adapter (nuclei, crawler) | Limit concurrent adapter runs, reduce batch size |
| Redis queue buildup | Queue holding too many items | Increase worker count, reduce queue retention |

## Immediate Mitigation

```bash
# Increase memory limit (temporary)
kubectl patch deployment ishastra-worker -n ishastra-system -p '{"spec":{"template":{"spec":{"containers":[{"name":"worker","resources":{"limits":{"memory":"4Gi"}}]}}}}'

# Scale up workers to distribute load
kubectl scale deployment ishastra-worker -n ishastra-system --replicas=15

# Drain problematic pods
kubectl delete pod -n ishastra-system -l app=ishastra-worker --field-selector status.phase=Running
```

## Permanent Fix

```yaml
# In values.yaml or values-prod.yaml
worker:
  resources:
    limits:
      memory: "4Gi"  # Increase from 2Gi
    requests:
      memory: "2Gi"
  replicas: 5
  env:
    # Limit concurrent adapters per worker
    ISHASTRA_WORKER_MAX_CONCURRENT_ADAPTERS: "2"
    # Limit targets per assessment
    ISHASTRA_WORKER_MAX_TARGETS_PER_ASSESSMENT: "50"
```

## Escalation

1. **Immediate**: Platform on-call
2. **15 min**: Platform lead (if multiple workers affected)

## Post-Incident

- [ ] Profile memory usage with `py-spy` or `cargo-profiler`
- [ ] Add memory limit alerts at 80% threshold
- [ ] Document root cause and fix
- [ ] Update capacity planning

## Related

- [Kubernetes Deployment](../deployment/kubernetes.md)
- [Helm Deployment](../deployment/helm.md)
- [Monitoring](../deployment/monitoring.md)
- [Queue Backlog Runbook](queue-backlog.md)
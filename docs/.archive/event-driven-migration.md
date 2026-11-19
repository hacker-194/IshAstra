# Migration Guide: Polling to Event-Driven Architecture

> **Note:** the Celery transport described as "legacy" below was removed; the
> queue is now in-process or Kubernetes Jobs.

This guide documents the migration from Strix's legacy synchronous polling architecture to the new event-driven architecture.

## Overview

### Legacy Architecture (v3.4 and earlier)
```
Client → POST /assessments → Queue (in-process or k8s-jobs) → Worker → Database → Webhook
                                    ↓
                              Client polls GET /assessments/{id}
```

### New Event-Driven Architecture (v3.5+)
```
Client → POST /assessments → Event: assessment.submitted → Event Bus
                                              ↓
                    ┌──────────────────────────┼──────────────────────────┐
                    ↓                          ↓                          ↓
            Assessment Handler           Projections                  Webhook Consumer
            (K8s Job)                    (Findings,                   (Retry + DLQ)
                                         Compliance,
                                         History, Metrics)
```

## Migration Phases

### Phase 1: Dual-Write (Backward Compatibility)
**Duration:** 1-2 weeks  
**Risk:** Low

Both systems run simultaneously. The HTTP API writes to both:
1. Legacy queue (in-process or k8s-jobs)
2. New event bus (for new consumers)

```python
# In assessments.py router - dual write
async def create_assessment(request: AssessRequest) -> AssessmentResponse:
    # Legacy: enqueue to Celery
    job_id = await queue.enqueue_assessment(...)

    # New: publish event
    event = create_assessment_submitted_event(...)
    await event_bus.publish(event)

    return AssessmentResponse(job_id=job_id, ...)
```

**Configuration:**
```yaml
# values.yaml
legacy:
  queue:
    enabled: true
eventBus:
  enabled: true
  backend: "redis"
```

### Phase 2: Consumer Migration
**Duration:** 1-2 weeks  
**Risk:** Medium

Migrate consumers one at a time:

1. **Webhook Consumer** - New webhook delivery with retry/DLQ
2. **Findings Dashboard** - New projection replaces polling queries
3. **Compliance Reports** - New projection
4. **Assessment History** - New projection
5. **Metrics** - New projection replaces custom metrics endpoints

Each consumer:
- Subscribes to relevant event types
- Builds its own read model
- Exposes query API

### Phase 3: Producer Cutover
**Duration:** 1 week  
**Risk:** Medium

Switch API to event-only:
- Remove Celery enqueue
- Publish `assessment.submitted` event
- Return `job_id` immediately (async)

```python
# New assessments.py router - event only
async def create_assessment(request: AssessRequest) -> AssessmentResponse:
    job_id = generate_job_id()
    event = create_assessment_submitted_event(job_id=job_id, ...)
    await event_bus.publish(event)
    return AssessmentResponse(job_id=job_id, ...)
```

### Phase 4: Legacy Removal
**Duration:** 1 week  
**Risk:** Low

Remove legacy code:
- Celery worker deployment
- Polling endpoints (`GET /assessments/{id}/status`)
- Legacy queue configuration
- Old database indexes for polling

## API Changes

### Breaking Changes

| Legacy Endpoint | New Approach |
|-----------------|--------------|
| `POST /assessments` (sync wait) | `POST /assessments` (returns immediately) |
| `GET /assessments/{id}/status` (poll) | Webhook / SSE / GraphQL subscription |
| `GET /assessments/{id}/findings` | `GET /findings?job_id={id}` (projection) |
| `GET /compliance/report` | `GET /compliance/report` (projection) |

### New Endpoints

```
# Event-driven assessment submission
POST   /api/v1/assessments              # Returns job_id immediately
GET    /api/v1/assessments/{job_id}     # Assessment record from projection
GET    /api/v1/assessments/{job_id}/events  # Event history (debug)

# Findings dashboard (projection)
GET    /api/v1/findings                 # Filtered, paginated findings
GET    /api/v1/findings/{fingerprint}   # Single finding details
GET    /api/v1/findings/stats           # Dashboard statistics
GET    /api/v1/findings/trends          # Time-series trends

# Compliance reports (projection)
GET    /api/v1/compliance/report        # Full compliance report
GET    /api/v1/compliance/report/csv    # CSV export

# Assessment history (projection)
GET    /api/v1/history/assessments      # Paginated history
GET    /api/v1/history/assessments/{job_id}
GET    /api/v1/history/metrics          # Aggregated metrics

# Real-time updates
GET    /api/v1/events/stream            # Server-Sent Events
WS     /api/v1/events/ws                # WebSocket
```

### Webhook Payload Changes

**Legacy:**
```json
{
  "job_id": "abc123",
  "status": "completed",
  "findings": [...]
}
```

**New:**
```json
{
  "event_id": "evt_abc123",
  "event_type": "assessment.completed",
  "timestamp": 1699999999.123,
  "tenant_id": "tenant_1",
  "trace_id": "trace_abc",
  "correlation_id": "corr_abc",
  "payload": {
    "job_id": "abc123",
    "state": "completed",
    "verdict": "pass",
    "findings_count": 5,
    "findings_by_severity": {"critical": 1, "high": 2, "medium": 2},
    "finished_at": 1699999999.123,
    "duration_ms": 45000
  }
}
```

## Deployment Migration

### Helm Values Changes

**Legacy values.yaml:**
```yaml
redis:
  enabled: true
postgresql:
  enabled: true
worker:
  replicaCount: 3
api:
  replicaCount: 2
```

**New values-eventbus.yaml:**
```yaml
eventBus:
  backend: "redis"
  redis:
    enabled: true

eventPublisher:
  enabled: true
  replicaCount: 2

eventConsumers:
  assessmentHandler:
    enabled: true
    replicaCount: 1
  findingsProjection:
    enabled: true
    replicaCount: 1
  complianceProjection:
    enabled: true
    replicaCount: 1
  historyProjection:
    enabled: true
    replicaCount: 1
  metricsProjection:
    enabled: true
    replicaCount: 1
  webhookConsumer:
    enabled: true
    replicaCount: 2

schemaRegistry:
  enabled: true
  replicaCount: 1
```

### Migration Steps

1. **Deploy event bus infrastructure:**
   ```bash
   helm upgrade strix ./deploy/helm/strix -f values.yaml -f values-eventbus.yaml
   ```

2. **Verify event bus health:**
   ```bash
   kubectl get pods -l app.kubernetes.io/part-of=strix-event-bus
   kubectl logs -l app=strix-event-publisher
   ```

3. **Enable dual-write in API:**
   ```yaml
   # ConfigMap or values
   api:
     env:
       - name: EVENT_BUS_ENABLED
         value: "true"
       - name: LEGACY_QUEUE_ENABLED
         value: "true"
   ```

4. **Migrate consumers one by one:**
   ```bash
   # Enable webhook consumer
   kubectl scale deployment strix-webhook-consumer --replicas=2

   # Verify webhook deliveries
   kubectl logs -l app=strix-webhook-consumer
   ```

5. **Cutover API to event-only:**
   ```yaml
   api:
     env:
       - name: EVENT_BUS_ENABLED
         value: "true"
       - name: LEGACY_QUEUE_ENABLED
         value: "false"
   ```

6. **Remove legacy worker:**
   ```bash
   kubectl scale deployment strix-worker --replicas=0
   # After verification:
   helm upgrade strix ./deploy/helm/strix -f values.yaml -f values-eventbus.yaml --set worker.enabled=false
   ```

## Data Migration

### Existing Assessments

Assessments in progress during migration:
1. Legacy workers complete them normally
2. Events are published for completed assessments
3. Projections backfill from event log

### Backfilling Projections

```bash
# Replay events to build projections
kubectl exec -it strix-event-bus-0 -- python -m strix.events.replay \
  --from-timestamp 1699999999 \
  --event-types assessment.completed,finding.created \
  --projection findings_dashboard
```

### Webhook Configurations

Existing webhook configs in database are automatically picked up by the new webhook consumer on startup.

## Testing Strategy

### Contract Tests

```python
# tests/test_event_contracts.py
def test_assessment_submitted_schema():
    event = create_assessment_submitted_event(...)
    assert validate_event(event, "assessment.submitted")

def test_finding_created_schema():
    event = create_finding_created_event(...)
    assert validate_event(event, "finding.created")
```

### Integration Tests

```python
# tests/test_event_flow.py
async def test_assessment_flow():
    # Submit assessment
    resp = await client.post("/assessments", json={...})
    job_id = resp.json()["job_id"]

    # Wait for completion event
    event = await wait_for_event("assessment.completed", job_id=job_id)
    assert event.payload.verdict in ("pass", "fail")

    # Verify findings projection
    findings = await client.get(f"/findings?job_id={job_id}")
    assert len(findings.json()) == event.payload.findings_count
```

### Load Tests

```bash
# Simulate assessment load
hey -n 1000 -c 50 -m POST \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target": "https://example.com", "profile": "quick"}' \
  https://api.strix.example.com/assessments
```

## Rollback Plan

If issues arise:

1. **Immediate (minutes):**
   ```bash
   # Re-enable legacy queue
   kubectl set env deployment/strix-api LEGACY_QUEUE_ENABLED=true
   kubectl scale deployment strix-worker --replicas=3
   ```

2. **Short-term (hours):**
   ```bash
   # Disable event consumers
   kubectl scale deployment strix-webhook-consumer --replicas=0
   kubectl scale deployment strix-findings-projection --replicas=0
   # ... other projections
   ```

3. **Full rollback (if needed):**
   ```bash
   helm rollback strix <previous-revision>
   ```

## Monitoring During Migration

### Key Metrics to Watch

| Metric | Legacy | New | Alert Threshold |
|--------|--------|-----|-----------------|
| Assessment submission latency | <500ms | <200ms | >1s |
| Assessment completion time | N/A | <5min | >10min |
| Webhook delivery success rate | 99% | 99.9% | <99% |
| Event bus lag (consumer lag) | N/A | <100 | >1000 |
| Projection freshness | N/A | <5s | >30s |
| DLQ size | N/A | 0 | >10 |

### Dashboards

Import Grafana dashboards from `deploy/helm/strix/grafana/dashboards/`:
- `strix-event-bus-overview.json`
- `strix-assessment-pipeline.json`
- `strix-webhook-delivery.json`
- `strix-projection-health.json`

## Troubleshooting

### Common Issues

**1. Events not appearing in projections**
```bash
# Check consumer group lag
redis-cli XINFO GROUPS strix:events:assessment.submitted
redis-cli XINFO CONSUMERS strix:events:assessment.submitted projection-findings_dashboard

# Check consumer logs
kubectl logs -l app=strix-findings-projection
```

**2. Webhooks not delivered**
```bash
# Check DLQ
redis-cli LRANGE strix:dlq:webhook 0 10

# Check consumer logs
kubectl logs -l app=strix-webhook-consumer
```

**3. Assessment handler not creating jobs**
```bash
# Check handler logs
kubectl logs -l app=strix-assessment-handler

# Check K8s job creation
kubectl get jobs -n strix -l strix/job-type=assessment
```

**4. Schema validation failures**
```bash
# Check schema registry
kubectl logs -l app=strix-schema-registry

# Validate event manually
python -m strix.events.schemas validate --event-file event.json
```

## Timeline Summary

| Phase | Duration | Key Deliverable |
|-------|----------|-----------------|
| 1. Dual-Write | 1-2 weeks | API writes to both queue and event bus |
| 2. Consumer Migration | 1-2 weeks | All projections and webhook consumer running |
| 3. Producer Cutover | 1 week | API publishes events only |
| 4. Legacy Removal | 1 week | Celery removed 2026-11-18; polling endpoints still to remove |
| **Total** | **4-6 weeks** | **Full event-driven architecture** |

## Success Criteria

- [ ] All assessments complete via event-driven pipeline
- [ ] Webhook delivery success rate > 99.9%
- [ ] Projection query latency < 100ms (p95)
- [ ] Event bus consumer lag < 100 messages
- [ ] Zero data loss during migration
- [ ] All existing webhook integrations work without changes
- [ ] Dashboard and compliance reports match legacy data
- [ ] Rollback tested and documented

## Support

For migration issues:
- Check `#strix-migration` Slack channel
- Review runbooks in `docs/runbooks/`
- Contact platform team for infrastructure issues
# Job Orchestration Architecture

# Job Orchestration Architecture

How Ishastra manages assessment workflows, scheduling, and worker pools.

## Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Job Orchestration System                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │   Scheduler     │    │   Job Queue     │    │  Worker Pool    │         │
│  │  (Cron/Interval)│───▶│  (Priority +    │◀───│  (Threaded/     │         │
│  │  Single writer  │    │   In-Process)   │    │   Async)        │         │
│  └─────────────────┘    └────────┬────────┘    └────────┬────────┘         │
│                                   │                      │                  │
│                                   ▼                      │                  │
│  ┌──────────────────────────────────────────────────────────────────┐      │
│  │                    Job Lifecycle                                  │      │
│  │  CREATED → QUEUED → RUNNING → COMPLETED/FAILED → ARCHIVED       │      │
│  │       │         │        │              │                        │      │
│  │       ▼         ▼        ▼              ▼                        │      │
│  │   Persist   Persist  Scope Bind   Results + Proof               │      │
│  │   to DB     to DB    ContextVar    Chain                        │      │
│  └──────────────────────────────────────────────────────────────────┘      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Job Queue

### In-Memory Queue (Development)

**File**: `src/ishastra/core/queue.py` — `InMemoryQueue`

```python
class InMemoryQueue:
    def __init__(self):
        self._queues: dict[Priority, asyncio.Queue] = {
            Priority.CRITICAL: asyncio.Queue(),
            Priority.HIGH: asyncio.Queue(),
            Priority.NORMAL: asyncio.Queue(),
            Priority.LOW: asyncio.Queue(),
        }
        self._dead_letter: asyncio.Queue = asyncio.Queue()

    async def enqueue(self, job: Job, priority: Priority = Priority.NORMAL):
        await self._queues[priority].put(job)

    async def dequeue(self) -> Job:
        # Priority order: CRITICAL > HIGH > NORMAL > LOW
        for priority in Priority:
            try:
                return self._queues[priority].get_nowait()
            except asyncio.QueueEmpty:
                continue
        raise QueueEmpty()
```

### Redis Queue (Production)

**File**: `src/ishastra/core/queue.py` — `RedisQueue`

```python
class RedisQueue:
    def __init__(self, redis: Redis, prefix: str = "ishastra:queue"):
        self.redis = redis
        self.prefix = prefix
        self._lua_enqueue = redis.register_script(ENQUEUE_SCRIPT)
        self._lua_dequeue = redis.register_script(DEQUEUE_SCRIPT)

    async def enqueue(self, job: Job, priority: Priority = Priority.NORMAL):
        # Lua script for atomic priority queue
        await self._lua_enqueue(
            keys=[f"{self.prefix}:{priority.name}"],
            args=[job.model_dump_json(), job.id]
        )

    async def dequeue(self) -> Job:
        # Atomic dequeue from highest priority non-empty queue
        result = await self._lua_dequeue(keys=[f"{self.prefix}:{p.name}" for p in Priority])
        if result:
            return Job.model_validate_json(result)
        raise QueueEmpty()
```

### Priority Levels

| Priority | Value | Use Case | SLA |
|----------|-------|----------|-----|
| CRITICAL | 0 | Break-glass, incident response | < 1 min |
| HIGH | 1 | On-demand assessments, retries | < 5 min |
| NORMAL | 2 | Scheduled assessments | < 30 min |
| LOW | 3 | Background scans, maintenance | < 4 hours |

---

## Worker Pool

### Threaded Worker (Sync Adapters)

**File**: `src/ishastra/core/worker.py` — `ThreadedWorkerPool`

```python
class ThreadedWorkerPool:
    def __init__(
        self,
        queue: JobQueue,
        max_workers: int = 10,
        scope_gate: ScopeGate,
        adapter_registry: AdapterRegistry,
    ):
        self.queue = queue
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.scope_gate = scope_gate
        self.adapter_registry = adapter_registry
        self._running = False

    async def start(self):
        self._running = True
        asyncio.create_task(self._dispatch_loop())

    async def _dispatch_loop(self):
        while self._running:
            try:
                job = await self.queue.dequeue()
                # Run in thread pool (for sync adapters)
                self.executor.submit(self._run_job, job)
            except QueueEmpty:
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Dispatch error: {e}")
                await asyncio.sleep(5)

    def _run_job(self, job: Job):
        # Bind scope for this thread
        with ScopeContext(job.scope):
            asyncio.run(self._execute_job(job))

    async def _execute_job(self, job: Job):
        job.status = JobStatus.RUNNING
        job.started_at = datetime.utcnow()
        await job.save()

        try:
            for adapter_name in job.adapters:
                adapter_class = self.adapter_registry.get(adapter_name)
                config = AdapterConfig(
                    scope=job.scope,
                    target=job.target,
                    options=job.adapter_options.get(adapter_name, {}),
                    scope_gate=self.scope_gate,
                )
                adapter = adapter_class(config)

                async for finding in adapter.run():
                    finding.job_id = job.id
                    finding.assessment_id = job.assessment_id
                    await finding.save()

            job.status = JobStatus.COMPLETED
        except Exception as e:
            job.status = JobStatus.FAILED
            job.error = str(e)
            # Retry logic
            if job.retry_count < job.max_retries:
                job.retry_count += 1
                await self.queue.enqueue(job, priority=Priority.HIGH)
            else:
                await self.queue.dead_letter(job)
        finally:
            job.completed_at = datetime.utcnow()
            await job.save()
```

### Async Worker (Async Adapters)

**File**: `src/ishastra/core/worker.py` — `AsyncWorkerPool`

```python
class AsyncWorkerPool:
    def __init__(
        self,
        queue: JobQueue,
        max_concurrent: int = 50,
        scope_gate: ScopeGate,
        adapter_registry: AdapterRegistry,
    ):
        self.queue = queue
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.scope_gate = scope_gate
        self.adapter_registry = adapter_registry

    async def start(self):
        # Start N concurrent workers
        workers = [asyncio.create_task(self._worker(i)) for i in range(self.max_concurrent)]
        await asyncio.gather(*workers)

    async def _worker(self, worker_id: int):
        while True:
            try:
                job = await self.queue.dequeue()
                async with self.semaphore:
                    await self._execute_job(job, worker_id)
            except QueueEmpty:
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
                await asyncio.sleep(5)
```

---

## Scheduler

### Cron + Interval Scheduler

**File**: `src/ishastra/core/scheduler.py` — `ComplianceScheduler`

```python
class ComplianceScheduler:
    def __init__(
        self,
        queue: JobQueue,
        db: Database,
        leader_election: LeaderElection,
    ):
        self.queue = queue
        self.db = db
        self.leader_election = leader_election
        self._tasks: dict[str, asyncio.Task] = {}

    async def start(self):
        # Only run scheduler if leader
        if await self.leader_election.acquire("scheduler"):
            asyncio.create_task(self._scheduler_loop())

    async def _scheduler_loop(self):
        while True:
            # Load scheduled assessments
            schedules = await self.db.fetch_scheduled_assessments()

            for schedule in schedules:
                if self._should_run(schedule):
                    job = self._create_job(schedule)
                    await self.queue.enqueue(job, priority=schedule.priority)
                    await self._update_next_run(schedule)

            await asyncio.sleep(60)  # Check every minute

    def _should_run(self, schedule: Schedule) -> bool:
        now = datetime.utcnow()
        if schedule.cron:
            return croniter.match(schedule.cron, now)
        if schedule.interval:
            return now >= schedule.next_run
        return False
```

### Scheduling and the single-writer rule

Schedules are polled by the one process that owns the worker lease. There is no
leader election and no distributed lock: a second process pointed at the same
`ISHASTRA_DB` exits instead of double-running jobs (see
[`DEPLOYMENT.md`](https://github.com/hacker-194/IshAstra/blob/master/DEPLOYMENT.md) §10).

Do not run a second scheduler against one database, and do not treat
`k8s-jobs` as an HA queue — it is experimental. For more throughput, raise
`ISHASTRA_WORKERS` (adapter threads) on the same host rather than adding replicas.

---

## Job Lifecycle

### States

```
CREATED
   │
   ▼ (enqueue)
QUEUED
   │
   ▼ (worker picks up)
RUNNING ──────────────────▶ FAILED
   │                            │
   │ (success)                  │ (retry < max)
   ▼                            ▼
COMPLETED                  QUEUED (HIGH priority)
   │
   ▼ (after retention)
ARCHIVED
```

### Job Model

```python
@dataclass
class Job:
    id: str                          # UUID
    assessment_id: str               # Parent assessment
    scope_id: str                    # Scope document
    target: str                      # Target URL
    adapters: list[str]              # Adapter names
    adapter_options: dict            # Per-adapter config
    priority: Priority = Priority.NORMAL
    status: JobStatus = JobStatus.CREATED
    retry_count: int = 0
    max_retries: int = 3
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    metadata: dict = field(default_factory=dict)
```

---

## Retry & Dead Letter

### Exponential Backoff

```python
RETRY_DELAYS = [60, 300, 1800, 3600]  # 1m, 5m, 30m, 1h

async def _retry_job(self, job: Job):
    delay = RETRY_DELAYS[min(job.retry_count, len(RETRY_DELAYS) - 1)]
    job.next_retry_at = datetime.utcnow() + timedelta(seconds=delay)
    await asyncio.sleep(delay)
    await self.queue.enqueue(job, priority=Priority.HIGH)
```

### Dead Letter Queue

```python
async def _move_to_dlq(self, job: Job, reason: str):
    dlq_entry = DeadLetterEntry(
        job=job,
        reason=reason,
        failed_at=datetime.utcnow(),
        retry_count=job.retry_count,
    )
    await self.queue.dead_letter.put(dlq_entry)

    # Alert
    await self._alert_dlq(dlq_entry)
```

### DLQ Monitoring

```bash
# Check DLQ
curl -H "Authorization: Bearer $KEY" \
  http://localhost:8000/api/v1/admin/dlq

# Reprocess DLQ entry
curl -X POST -H "Authorization: Bearer $KEY" \
  http://localhost:8000/api/v1/admin/dlq/{entry_id}/retry
```

---

## Scaling

### Scaling

Ishastra does not support autoscaling. One process owns the database's worker lease,
so a second replica exits instead of sharing work. Raise `ISHASTRA_WORKERS`
(adapter threads) and add CPU/RAM on the same host; do not apply the HPA
manifests that older revisions of this page suggested.
### Queue Depth Metric

```python
# Prometheus metric exposed by queue
queue_depth = Gauge(
    "strix_queue_depth",
    "Number of jobs in queue",
    ["priority"]
)

async def _update_metrics(self):
    for priority in Priority:
        count = await self._count_priority(priority)
        queue_depth.labels(priority=priority.name).set(count)
```

---

## Monitoring

### Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `strix_jobs_total` | Jobs by status | Failed > 10/min |
| `strix_job_duration_seconds` | Job runtime | p99 > 30 min |
| `strix_queue_depth` | Queue depth by priority | NORMAL > 1000 |
| `strix_worker_utilization` | Worker busy % | > 90% for 10m |
| `strix_dlq_size` | Dead letter queue | > 0 |

### Grafana Dashboard

Import `deploy/monitoring/grafana/dashboards/job-orchestration.json`

---

## Configuration

### Worker Config

```yaml
# values.yaml
worker:
  type: "async"  # or "threaded"
  maxConcurrent: 50
  maxRetries: 3
  retryDelays: [60, 300, 1800, 3600]
  deadLetter:
    enabled: true
    maxSize: 10000
  resources:
    limits:
      cpu: "2000m"
      memory: "4Gi"
    requests:
      cpu: "500m"
      memory: "1Gi"
```

### Scheduler Config

```yaml
scheduler:
  enabled: true
  leaderElection:
    enabled: true
    lockName: "ishastra-scheduler"
    ttl: 30
  checkInterval: 60
  timezone: "UTC"
```

---

## Testing

### Unit Tests

```bash
pytest tests/unit/test_worker.py -v
pytest tests/unit/test_scheduler.py -v
pytest tests/unit/test_queue.py -v
```

### Integration Tests

```bash
pytest tests/integration/test_job_lifecycle.py -v
```

### Load Tests

```bash
# Simulate 1000 concurrent assessments
k6 run load-test/job-orchestration.js
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| Jobs stuck in QUEUED | Worker process not running | Check the single service and `/api/ready` |
| Jobs FAILED repeatedly | Adapter error, Scope Gate | Check logs, scope config |
| Scheduler not running | Process not running | Check the service logs; there is no leader election |
| High queue depth | Adapter threads saturated | Raise `ISHASTRA_WORKERS`, add CPU/RAM |
| DLQ growing | Permanent failures | Investigate root cause |

### Debug Commands

```bash
# Check queue status
kubectl exec -n ishastra-system deploy/ishastra-api -- python -c "
from ishastra.core.queue import get_queue
q = get_queue()
print('Critical:', q._queues['CRITICAL'].qsize())
print('High:', q._queues['HIGH'].qsize())
print('Normal:', q._queues['NORMAL'].qsize())
print('Low:', q._queues['LOW'].qsize())
"

# Check worker status
kubectl get pods -n ishastra-system -l app=ishastra-worker

# Check scheduler leader
redis-cli GET ishastra:leader:ishastra-scheduler:heartbeat
```

---

## Related

- [Scope Gate](../scope-gate/concepts.md)
- [Adapters](../adapters/built-in.md)
- [Deployment](../deployment/kubernetes.md)
- [API: Assessments](../api/assessments.md)
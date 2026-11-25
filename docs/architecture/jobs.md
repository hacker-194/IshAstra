# Job Orchestration Architecture

How IshAstra accepts an assessment, queues it, runs it, and records the result.

## Request path

```
POST /api/assess
      │
      ▼
Scope Gate validates the target against the caller's policy
      │
      ▼
Job row persisted in the database (state=queued)
      │
      ▼
Queue implementation selected by ISHASTRA_QUEUE_MODE
      │
      ▼
Worker runs adapters, writes findings, emits a verdict
```

With `"wait": true` the request runs the job inline and returns the finished
record. Otherwise the API returns `202` with a `poll_url`.

## Queue modes

`ISHASTRA_QUEUE_MODE` selects the implementation
(`src/ishastra/core/queue.py`):

| Mode | Default | Behaviour |
|------|---------|-----------|
| `inprocess` | Yes | Threads inside the API process. A restart loses queued work. |
| `redis-streams` | No | One durable stream entry per job; queued work survives a restart and several worker processes can share the stream. |
| `sqlite` | No | Durable SQLite-backed queue shared through database locking. |
| `postgres` | No | Durable PostgreSQL queue using `FOR UPDATE SKIP LOCKED`; several processes claim distinct jobs. |
| `k8s-jobs` | No | One Kubernetes Job per assessment. Experimental; see the Helm notes. |

An unknown value is rejected at startup rather than silently falling back to the
in-process queue.

## Workers

- `AssessmentWorker` runs jobs with `ISHASTRA_WORKERS` adapter threads and an
  optional queue bound (`ISHASTRA_QUEUE_MAX`).
- `ishastra worker gateway` runs a dedicated worker for the Redis Streams queue
  when the API and workers are separate processes.
- The database is single-writer: one process holds the worker lease. A second
  process pointed at the same database exits instead of competing for jobs.
  Scale with threads, or with a multi-process queue mode, not with a second
  lease holder.

## Job record

The `jobs` table stores the durable record:

| Column | Meaning |
|--------|---------|
| `id` | Job identifier |
| `tenant`, `project` | Ownership |
| `target`, `profile` | What was assessed |
| `actor`, `policy` | Who requested it and under which policy |
| `state` | Lifecycle state (`queued`, `running`, `completed`, `failed`, …) |
| `verdict` | Assessment outcome |
| `error` | Failure detail, empty on success |
| `started_at`, `finished_at`, `created_at` | Timestamps |
| `coverage` | Adapter coverage recorded for the run |

Findings are keyed by `job_id` plus a stable fingerprint, so the same issue seen
across runs is aggregated rather than duplicated.

## Scheduler

`Scheduler` (`src/ishastra/core/scheduler.py`) runs recurring assessments from
the persisted schedules.

- It uses APScheduler jobs backed by the schedule rows.
- Leadership is a database lease (`distributed_leases`). Only the lease holder
  schedules assessments; followers run system jobs only.
- The lease is renewed periodically. If renewal fails, the instance stops its
  scheduled jobs instead of double-running them.
- Schedules are managed through `/api/schedules` and the compliance schedule
  routes.

## Retries

A failed job is retried explicitly:

```http
POST /api/assess/{job_id}/retry
```

There is no automatic exponential-backoff scheduler and no dead-letter queue.
The failure is visible on the job record (`state`, `error`, `attempts`) and via
`GET /api/assess/{job_id}`.

## Metrics

`/api/metrics` exports:

| Metric | Labels |
|--------|--------|
| `ishastra_jobs_total` | `state`, `tenant` |
| `ishastra_jobs_active` | `tenant` |
| `ishastra_job_duration_seconds` | `profile`, `tenant` |
| `ishastra_job_queue_duration_seconds` | `profile` |
| `ishastra_job_state_transitions_total` | `from`, `to` |
| `ishastra_queue_depth` | `mode` |
| `ishastra_workers_total` | `mode` |
| `ishastra_worker_busy` | `mode` |

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Jobs stay `queued` | No worker or lease holder | Check the process and `/api/ready` |
| Jobs fail repeatedly | Adapter error or Scope Gate denial | Read the job `error` and the gate audit log |
| Scheduler idle | Another instance holds the lease, or no active schedules | Check `GET /api/scheduler/status` and `/api/schedules` |
| Growing queue depth | Worker slots saturated | Raise `ISHASTRA_WORKERS`, or move to a multi-process queue mode |

## Related

- [Scope Gate](../scope-gate/concepts.md)
- [Assessments API](../api/assessments.md)
- [Deployment](../deployment/kubernetes.md)
- [Monitoring](../deployment/monitoring.md)

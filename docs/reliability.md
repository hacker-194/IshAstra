# Reliability: measured behaviour and known limits

This page records what was actually measured on one machine, how the queue modes
behave when a process dies, and what is **not** proven. It is a baseline, not a
capacity commitment.

## Measurement environment

- 12 vCPU (`11th Gen Intel Core i5-11400H @ 2.70GHz`), Linux
- Python 3.14.4, SQLite temporary database, loopback detection lab
- Commit `a6360d1` plus the Phase 1–3 branch changes
- Single machine, single API process; no tuning

Reproduce with:

```bash
python scripts/benchmark_scope_gate.py --requests 20000
python scripts/load_check.py --requests 500 --concurrency 20
python scripts/assessment_load_check.py --jobs 20 --submit-concurrency 4 --workers 4
```

## Results

| Workload | Throughput | p50 | p95 | p99 | Max |
|---|---|---|---|---|---|
| Scope gate `check()` (DNS stubbed) | **18,863 ops/s** | <0.1 ms | 0.1 ms | 0.2 ms | 0.3 ms |
| Scope gate `destination()` (DNS stubbed) | **16,318 ops/s** | 0.1 ms | 0.1 ms | 0.2 ms | 0.3 ms |
| `GET /api/health` over HTTP, concurrency 20 | **510 req/s** | 37.4 ms | 57.4 ms | 69.2 ms | — |
| End-to-end assessment, 4 workers | **39.4 jobs/s** | 464 ms | 504 ms | 508 ms | — |

- HTTP run: 500 requests, 20 concurrent, **0 errors**.
- Assessment run: 20 jobs, all `completed`, wall time 0.51 s.
- The scope-gate figures stub DNS deliberately, so they measure the policy
  engine, not the resolver. Real DNS adds its own latency.
- End-to-end latency is dominated by the assessment itself (adapters, finding
  writes), not by the gate: the gate accounts for well under 1 ms of the
  ~464 ms job.

## Queue behaviour

| Mode | Durability | Concurrency | On worker death |
|---|---|---|---|
| `inprocess` (default) | None — queued jobs are lost on restart | Threads in one process | Lost |
| `sqlite` | Durable; survives restart | Several processes via database locking | Reclaimable |
| `redis-streams` | Durable stream entry per job | Several consumers in one group | Idle entries reclaimed with `XAUTOCLAIM` after the visibility window |
| `postgres` | Durable row claimed with `FOR UPDATE SKIP LOCKED` | Several processes claim distinct jobs | Row reclaimable |
| `k8s-jobs` | One Kubernetes Job per assessment | Fleet | Kubernetes retries the Job (experimental) |

Delivery is at-least-once: a duplicate Redis entry or a reclaimed message is
skipped because `store.claim_job` only moves a job out of `queued` once. A job
is therefore not executed twice by a duplicate message, but a crash after the
job row is claimed does not automatically resume it.

### Single writer

The database has one writer lease. A second worker process pointed at the same
database exits with `WorkerLeaseError` instead of competing for jobs. Scale with
threads, or with `redis-streams`/`postgres`/`k8s-jobs`, not with two lease
holders. A stale lock file from a dead PID is removed on startup.

## Health and readiness

- `GET /api/health` — liveness; returns `{"status": "healthy", ...}`.
- `GET /api/ready` — readiness; checks the dependencies the worker needs.

## What is tested

- Queue selection and unknown-mode rejection: `tests/unit/test_queue.py`.
- Redis stream consumption and reclaim: `tests/unit/test_redis_queue.py`.
- Single-writer/read-only store behaviour: `tests/unit/test_store_read_only.py`.
- Worker lifecycle and lease: `tests/unit/test_worker_manager.py`.
- Scheduling: `tests/unit/test_scheduler.py`.
- Store generation guard (stale pool after reconfigure): `tests/unit/test_store.py`.

The five suites above (40 tests) pass locally.

## Not measured / not claimed

- No Postgres or Redis throughput run on this machine; those modes were
  exercised functionally by tests and CI, not benchmarked.
- No sustained soak, no multi-node run, no chaos test during an active scan.
- The assessment benchmark uses the loopback lab; real targets add network time.
- Numbers vary with CPU, database, adapter mix, and finding volume. Treat the
  table as an order-of-magnitude baseline.

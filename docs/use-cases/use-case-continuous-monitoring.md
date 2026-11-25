# Use case: continuous monitoring (in-process queue mode)

## Goal

Run IshAstra on a recurring schedule as a background daemon, re-assessing
targets at defined intervals and appending new findings to an audit chain.

## Preconditions

- IshAstra deployment with `ISHASTRA_ENV=production`.
- Redis is available (or the in-process queue for single-node use).
- Operator has a long-lived capability token or rotates tokens via the key‑gen
  workflow.
- Egress gateway is running if any external tool adapters are configured.

## Steps

1. **Start IshAstra in listener mode**:

   ```bash
   ISHASTRA_ENV=production \
   ISHASTRA_QUEUE_MODE=inprocess \
   ishastra serve --port 8080
   ```
   This starts the FastAPI server with a durable in-process job queue.
2. **Schedule periodic assessments** — Use cron, systemd timer, or a CI
   pipeline to POST new assessment jobs to the API:
   `POST /api/v1/scope-assess` with a capability token and target list.
3. **Each assessment** produces a signed evidence bundle that is appended to
   the audit chain. The chain receipt is stored in a persistent backend
   (SQLite by default; PostgreSQL with `--db-url`).
4. **Retrieve findings** — `GET /api/v1/findings` or `ishastra scope-list`
   lists all findings, grouped by engagement/tenant.

## CI job snippet (scheduled GitHub Actions)

```yaml
name: Continuous monitoring
on:
  schedule:
    - cron: '0 2 * * *'  # daily at 02:00 UTC
jobs:
  monitor:
    runs-on: ubuntu-latest
    env:
      ISHASTRA_ENV: production
      ISHASTRA_QUEUE_MODE: inprocess
      ISHASTRA_GATEWAY_URL: http://127.0.0.1:8080
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v1
      - name: Install IshAstra
        run: pip install -e .[dev]
      - name: Start IshAstra daemon
        run: |
          ishastra serve --port 8080 &
          sleep 5  # wait for startup
      - name: Schedule a daily assessment
        run: |
          python - <<'PY'
import json, subprocess, os, time
os.environ.update({
    "ISHASTRA_ENV": "production",
    "ISHASTRA_QUEUE_MODE": "inprocess",
    "ISHASTRA_GATEWAY_URL": "http://127.0.0.1:8080"
})
# start server in background
proc = subprocess.Popen(
    ["ishastra", "serve", "--port", "8080"],
    env=os.environ)
time.sleep(5)  # wait for server to be ready
# submit assessment
jwt = "eyJhbGciOiJFZERTQSJ9..."  # valid token for the engagement
r = subprocess.run(
    ["curl", "-sS", "-X", "POST",
     "-H", "Authorization: Bearer jwt",
     "-H", "Content-Type: application/json",
     "-d", json.dumps({"targets": ["https://example.com"]})],
    env={**os.environ, "ISHASTRA_ENV": "production",
         "ISHASTRA_GATEWAY_URL": "http://127.0.0.1:8080"})
assert r.returncode == 0, f"assessment POST failed: {r.stdout} {r.stderr}"
# wait for job completion
time.sleep(3)
# verify evidence was appended
subprocess.run(["ishastra", "scope-list"], check=True)
PY
      - name: Stop daemon
        if: always()
        run: |
          pkill -f "ishastra serve" || true
```
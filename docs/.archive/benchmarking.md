# Strix Benchmarking Guide

This document describes how to run load/stress tests against the Strix API using the k6-based benchmarking framework.

## Overview

The benchmarking framework includes:

- **k6 test script** (`scripts/benchmark.js`) - Defines 5 test scenarios with realistic load patterns
- **Python runner** (`scripts/benchmark.py`) - Wrapper to execute k6, parse results, and generate reports
- **GitHub Actions workflow** (`.github/workflows/benchmark.yml`) - CI integration for automated runs
- **JSON output** - Machine-readable results for CI/CD integration
- **Markdown reports** - Human-readable summaries with threshold assessments

## Quick Start

### Prerequisites

1. **Install k6** (load testing tool):
   ```bash
   # Ubuntu/Debian
   sudo apt-get update && sudo apt-get install -y gnupg2 curl
   curl -fsSL https://dl.k6.io/key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/k6-archive-keyring.gpg
   echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
   sudo apt-get update && sudo apt-get install -y k6
   
   # macOS
   brew install k6
   
   # Verify
   k6 version
   ```

2. **Install Strix dependencies**:
   ```bash
   pip install -e ".[dev]" -c constraints.txt
   ```

### Run a Smoke Test (Local Development)

```bash
# Start Strix API in one terminal
export STRIX_API_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
export STRIX_AUDIT_HMAC_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
export STRIX_DB=/tmp/strix-bench.db
export STRIX_SCOPE_FILE=scope.example.json
export STRIX_LOG_LEVEL=WARNING
export STRIX_REDIS_REQUIRED=0
strix serve --host 127.0.0.1 --port 8000

# In another terminal, run the smoke test
python scripts/benchmark.py --scenario smoke
```

### Run Against a Deployed Instance

```bash
python scripts/benchmark.py \
  --scenario load \
  --base-url https://strix-staging.example.com \
  --api-key $STRIX_API_KEY \
  --tenant-id my-tenant \
  --output load-test-results.json
```

## Scenarios

| Scenario | Description | VUs | Duration | Use Case |
|----------|-------------|-----|----------|----------|
| **smoke** | Quick validation | 1 | 30s | Pre-deployment check, CI gate |
| **load** | Sustained realistic load | 50 (ramped) | 5m | Capacity planning, regression |
| **stress** | Find breaking point | 200 (ramped) | 10m | Breaking point, limits |
| **soak** | Long-running stability | 100 | 1h | Memory leaks, degradation |
| **spike** | Sudden traffic burst | 500 | 50s | Auto-scaling, circuit breakers |

### Scenario Details

#### Smoke Test
- **Purpose**: Verify basic API functionality under minimal load
- **Endpoints tested**: `/api/health`, `/api/ready`, `/api/assess` (list), `/api/findings` (list)
- **Thresholds**: P95 < 500ms, P99 < 1000ms, Error rate < 1%
- **Run time**: ~30 seconds

#### Load Test
- **Purpose**: Simulate realistic sustained traffic
- **Ramp**: 0 → 10 → 25 → 50 VUs over 3.5 minutes, hold 50 VUs for 1 minute
- **Traffic mix**: 40% health checks, 30% list assessments, 15% list findings, 15% create assessments
- **Thresholds**: P95 < 2s, P99 < 5s, Error rate < 1%, Success rate > 95%
- **Run time**: ~5 minutes

#### Stress Test
- **Purpose**: Find the system's breaking point
- **Ramp**: 0 → 50 → 100 → 150 → 200 VUs over 6 minutes, hold 200 VUs for 1 minute
- **Traffic mix**: More write-heavy (assessment creation), includes error paths
- **Thresholds**: P95 < 5s, P99 < 10s, Error rate < 1%, Success rate > 90%
- **Run time**: ~10 minutes

#### Soak Test
- **Purpose**: Detect memory leaks, connection leaks, degradation over time
- **Constant load**: 100 VUs for 1 hour
- **Traffic mix**: Read-heavy, longer think times
- **Thresholds**: P95 < 2s, P99 < 5s, Error rate < 1%, Success rate > 95%
- **Run time**: ~1 hour

#### Spike Test
- **Purpose**: Test auto-scaling, circuit breakers, sudden traffic bursts
- **Ramp**: 0 → 500 VUs in 10s, hold 30s, ramp down in 10s
- **Traffic**: Health checks only (simulates monitoring flood)
- **Thresholds**: P95 < 10s, P99 < 15s, Error rate < 1%, Success rate > 85%
- **Run time**: ~50 seconds

## Command Reference

```bash
python scripts/benchmark.py [OPTIONS]

Options:
  --scenario SCENARIO     Benchmark scenario: smoke, load, stress, soak, spike, all (default: smoke)
  --base-url URL          Target API base URL (default: http://localhost:8000)
  --api-key KEY           API key for authenticated endpoints
  --tenant-id ID          Tenant ID for multi-tenant testing (default: test-tenant)
  --output FILE           Output JSON file (default: benchmark-results.json)
  --k6-script FILE        Path to k6 script (default: scripts/benchmark.js)
  --install-k6            Attempt to install k6 if not found
  --no-report             Skip generating markdown report
  -h, --help              Show this help message
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BASE_URL` | Target API URL | `http://localhost:8000` |
| `STRIX_API_KEY` | API key for auth | `test-admin-key-123456` |
| `TENANT_ID` | Tenant identifier | `test-tenant` |

## Output Files

### JSON Results (`benchmark-results.json`)

Machine-readable format for CI/CD integration:

```json
{
  "timestamp": "2026-01-15T10:30:00.000Z",
  "base_url": "http://localhost:8000",
  "scenarios": {
    "smoke": {
      "vus": 1,
      "iterations": 150,
      "avg_duration": 45.2,
      "p95_duration": 120.5,
      "p99_duration": 280.1,
      "error_rate": 0.000
    }
  },
  "overall": {
    "total_requests": 150,
    "failed_requests": 0,
    "avg_duration": 45.2,
    "p95_duration": 120.5,
    "p99_duration": 280.1
  }
}
```

### Markdown Report (`benchmark-results.md`)

Human-readable summary with threshold assessment:

```markdown
# Strix Benchmark Results

## Scenario Results

### SMOKE
- **Status**: ✅ PASS
- **P95**: 120ms (threshold: 500ms)
- **P99**: 280ms (threshold: 1000ms)
- **Error Rate**: 0.00% (threshold: 1.00%)
```

## Interpreting Results

### Key Metrics

| Metric | What It Means | Healthy Range |
|--------|---------------|---------------|
| **P50 (median)** | Typical response time | < 100ms (health), < 500ms (assess) |
| **P95** | 95th percentile - most users' experience | Per scenario thresholds |
| **P99** | 99th percentile - worst typical experience | Per scenario thresholds |
| **Error Rate** | Failed requests / total requests | < 1% |
| **Throughput** | Requests per second sustained | Depends on scenario |

### Threshold Assessment

Each scenario has predefined thresholds. The report shows ✅ PASS or ❌ FAIL for each:

- **Smoke**: Strict thresholds - should always pass in healthy system
- **Load**: Realistic production thresholds
- **Stress**: Lenient - expected to approach limits
- **Soak**: Same as load but over extended time
- **Spike**: Most lenient - tests burst handling

### Common Failure Patterns

| Pattern | Likely Cause | Investigation |
|---------|--------------|---------------|
| High P99, normal P95 | Occasional GC pauses, lock contention | Check logs for long requests |
| Rising latency over time (soak) | Memory leak, connection pool exhaustion | Monitor memory, DB connections |
| High error rate at ramp-up | Cold starts, connection pool warmup | Increase pool sizes, pre-warm |
| 503 errors under load | Queue full, worker unavailable | Check `STRIX_WORKERS`, `STRIX_QUEUE_MAX` |
| 429 errors | Rate limiting | Adjust `STRIX_RATE_LIMIT_*` settings |

## CI/CD Integration

### GitHub Actions

The workflow at `.github/workflows/benchmark.yml` supports:

1. **Manual trigger** with scenario selection:
   - Go to Actions → Benchmark → Run workflow
   - Select scenario, optionally provide external URL/API key

2. **Artifacts uploaded**:
   - `benchmark-results-<scenario>.json` - Machine-readable results
   - `benchmark-results-<scenario>.md` - Human-readable report
   - `k6-raw-output-<scenario>` - Raw k6 summary exports

3. **Threshold enforcement**: Job fails if any scenario misses thresholds

4. **PR Comments**: Results posted as comment on workflow_dispatch (when run from PR)

### Using Results in Pipeline

```yaml
# Example: Fail deployment if smoke test regresses
- name: Run smoke benchmark
  run: python scripts/benchmark.py --scenario smoke --output results.json

- name: Check P95 regression
  run: |
    python -c "
import json
with open('results.json') as f:
    data = json.load(f)
p95 = data['scenarios']['smoke']['p95_duration']
# Fail if P95 > 200ms (2x baseline)
assert p95 < 200, f'P95 regression: {p95}ms > 200ms'
"
```

## Running in Different Environments

### Local Development
```bash
# Quick smoke test
python scripts/benchmark.py --scenario smoke

# Full load test (ensure API is running)
python scripts/benchmark.py --scenario load
```

### Staging/Pre-Production
```bash
# Run against deployed staging
python scripts/benchmark.py \
  --scenario load \
  --base-url https://strix-staging.example.com \
  --api-key $STAGING_API_KEY \
  --tenant-id staging-tenant
```

### Production (Read-Only)
```bash
# Only run read-only scenarios against production
python scripts/benchmark.py \
  --scenario smoke \
  --base-url https://strix.example.com \
  --api-key $PROD_API_KEY \
  --tenant-id prod-tenant
```

## Customizing Scenarios

### Modify Thresholds

Edit `scripts/benchmark.js` thresholds section:

```javascript
thresholds: {
  'http_req_duration{scenario:load}': ['p(95)<3000', 'p(99)<8000'],  // Relaxed
  'http_req_failed': ['rate<0.05'],  // Allow 5% errors
  // ...
}
```

### Add Custom Endpoints

Add new groups in scenario functions:

```javascript
export function loadTest() {
  // ... existing code ...
  
  // Add custom endpoint test
  group('Custom Endpoint', () => {
    const res = authRequest('GET', `${BASE_URL}/api/custom-endpoint`);
    checkResponse(res, { 'status is 200': (r) => r.status === 200 }, 'custom');
  });
}
```

### Adjust Traffic Mix

Modify the probability distribution in scenario functions:

```javascript
export function loadTest() {
  const scenario = Math.random();
  
  if (scenario < 0.5) {  // 50% health checks
    // ...
  } else if (scenario < 0.8) {  // 30% list assessments
    // ...
  }
  // ...
}
```

## Troubleshooting

### k6 Not Found
```bash
python scripts/benchmark.py --install-k6 --scenario smoke
```

### Connection Refused
- Ensure Strix API is running on the target URL
- Check `BASE_URL` includes correct protocol (http/https)
- Verify firewall/network allows connection

### Authentication Failures
- Verify `STRIX_API_KEY` is correct and has appropriate permissions
- Check tenant exists and API key belongs to it
- For local testing, use the same key that started the server

### High Latency / Timeouts
- Check Strix logs for errors
- Verify database is not locked (SQLite contention)
- Check Redis connection if `STRIX_REDIS_REQUIRED=1`
- Increase `STRIX_WORKERS` for higher concurrency

### Out of Memory (Soak Test)
- Monitor memory usage: `docker stats` or `htop`
- Check for connection leaks in application
- Consider reducing VUs or duration for initial runs

## Best Practices

1. **Always run smoke test first** - Catches basic issues quickly
2. **Run load test before releases** - Regression detection
3. **Run stress test quarterly** - Capacity planning
4. **Run soak test monthly** - Stability verification
5. **Compare trends** - Store results and track P95/P99 over time
6. **Test in staging first** - Never run stress/spike against production
7. **Use realistic data** - Test targets should resemble production workloads
8. **Monitor resources** - Watch CPU, memory, disk, network during tests

## Related Documentation

- [API Documentation](API_DOCUMENTATION.md) - Endpoint reference
- [Deployment Guide](../DEPLOYMENT.md) - Production deployment
- [Configuration](configuration.md) - Environment variables
- [Production Readiness](production-readiness.md) - Operational considerations
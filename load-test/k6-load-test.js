// Strix k6 Load Test Script
//
// Usage:
//   k6 run --vus 50 --duration 5m load-test/k6-load-test.js \
//     -e BASE_URL=https://staging-api.your-domain.com \
//     -e API_KEY=<admin-api-key>
//
// Scenarios:
//   - smoke: 1 VU, 30s (quick validation)
//   - load: 50 VU, 5m (sustained load)
//   - stress: 100 VU, 2m (breaking point)
//   - soak: 20 VU, 30m (endurance)
//
// Thresholds (adjust for your SLOs):
//   - http_req_duration p95 < 500ms
//   - http_req_failed < 1%
//   - checks pass rate > 99%

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const authFailures = new Rate('auth_failures');
const scopeDenials = new Rate('scope_denials');
const assessmentLatency = new Trend('assessment_latency');
const assessmentStarted = new Counter('assessments_started');
const assessmentCompleted = new Counter('assessments_completed');

// Configuration from environment
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const API_KEY = __ENV.API_KEY || '';
const TENANT_ID = __ENV.TENANT_ID || '';

// Test profiles to exercise
const PROFILES = ['web', 'api', 'web-deep'];
const TARGETS = [
  'http://httpbin.org/get',
  'http://httpbin.org/headers',
  'http://httpbin.org/ip',
];

// Headers
function authHeaders() {
  return {
    'Authorization': `Bearer ${API_KEY}`,
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  };
}

// Scenario configurations
export const options = {
  scenarios: {
    smoke: {
      executor: 'constant-vus',
      vus: 1,
      duration: '30s',
      tags: { test_type: 'smoke' },
    },
    load: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 10 },
        { duration: '1m', target: 25 },
        { duration: '2m', target: 50 },
        { duration: '1m', target: 25 },
        { duration: '30s', target: 0 },
      ],
      tags: { test_type: 'load' },
    },
    stress: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 50 },
        { duration: '1m', target: 100 },
        { duration: '30s', target: 150 },
        { duration: '30s', target: 0 },
      ],
      tags: { test_type: 'stress' },
    },
    soak: {
      executor: 'constant-vus',
      vus: 20,
      duration: '30m',
      tags: { test_type: 'soak' },
    },
  },

  thresholds: {
    'http_req_duration{test_type:smoke}': ['p(95)<500'],
    'http_req_duration{test_type:load}': ['p(95)<1000'],
    'http_req_duration{test_type:stress}': ['p(95)<2000'],
    'http_req_duration{test_type:soak}': ['p(95)<1500'],

    'http_req_failed{test_type:smoke}': ['rate<0.01'],
    'http_req_failed{test_type:load}': ['rate<0.02'],
    'http_req_failed{test_type:stress}': ['rate<0.05'],
    'http_req_failed{test_type:soak}': ['rate<0.01'],

    'auth_failures': ['rate<0.01'],
    'scope_denials': ['rate<0.10'],
    'checks': ['rate>0.99'],
  },

  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
};

export function setup() {
  const healthRes = http.get(`${BASE_URL}/api/health`, { timeout: '10s' });
  check(healthRes, { 'health endpoint responds': (r) => r.status === 200 });

  if (API_KEY) {
    const authRes = http.get(`${BASE_URL}/api/health`, {
      headers: authHeaders(),
      timeout: '10s'
    });
    check(authRes, { 'authenticated health check': (r) => r.status === 200 });
  }

  return { baseUrl: BASE_URL };
}

export default function (data) {
  const baseUrl = data.baseUrl;
  const headers = authHeaders();

  group('Health Checks', () => {
    const healthRes = http.get(`${baseUrl}/api/health`, { timeout: '5s' });
    check(healthRes, { 'GET /api/health = 200': (r) => r.status === 200 });

    const readyRes = http.get(`${baseUrl}/api/ready`, { timeout: '5s' });
    check(readyRes, { 'GET /api/ready = 200': (r) => r.status === 200 });
  });

  sleep(1);

  if (API_KEY) {
    group('Authenticated Reads', () => {
      const findingsRes = http.get(`${baseUrl}/api/findings?limit=10`, {
        headers,
        timeout: '10s'
      });
      const findingsOk = check(findingsRes, {
        'GET /api/findings = 200': (r) => r.status === 200
      });
      authFailures.add(findingsRes.status === 401);

      const assetsRes = http.get(`${baseUrl}/api/assets?limit=10`, {
        headers,
        timeout: '10s'
      });
      check(assetsRes, {
        'GET /api/assets = 200': (r) => r.status === 200
      });
      authFailures.add(assetsRes.status === 401);

      const metricsRes = http.get(`${baseUrl}/api/metrics`, {
        headers,
        timeout: '10s'
      });
      check(metricsRes, {
        'GET /api/metrics = 200': (r) => r.status === 200
      });
      authFailures.add(metricsRes.status === 401);
    });

    sleep(1);

    group('Assessment Lifecycle', () => {
      const target = TARGETS[Math.floor(Math.random() * TARGETS.length)];
      const profile = PROFILES[Math.floor(Math.random() * PROFILES.length)];

      const assessPayload = JSON.stringify({
        target: target,
        profile: profile,
        options: {
          max_depth: 2,
          rate_limit: 10,
        },
      });

      const startRes = http.post(`${baseUrl}/api/assess`, assessPayload, {
        headers,
        timeout: '30s'
      });

      const startOk = check(startRes, {
        'POST /api/assess = 202': (r) => r.status === 202,
        'returns job_id': (r) => {
          try {
            const body = JSON.parse(r.body);
            return body.job_id !== undefined;
          } catch {
            return false;
          }
        },
      });

      authFailures.add(startRes.status === 401);
      scopeDenials.add(startRes.status === 403);

      if (!startOk) {
        sleep(2);
        return;
      }

      assessmentStarted.add(1);
      const jobId = JSON.parse(startRes.body).job_id;

      let completed = false;
      let attempts = 0;
      const maxAttempts = 30;

      while (!completed && attempts < maxAttempts) {
        sleep(2);
        attempts++;

        const statusRes = http.get(`${baseUrl}/api/assess/${jobId}`, {
          headers,
          timeout: '10s'
        });

        if (statusRes.status === 200) {
          const status = JSON.parse(statusRes.body);
          if (['completed', 'failed', 'cancelled'].includes(status.state)) {
            completed = true;
            assessmentLatency.add(attempts * 2000);

            if (status.state === 'completed') {
              assessmentCompleted.add(1);
            }

            check(statusRes, {
              'assessment reached terminal state': () => true,
              `terminal state is ${status.state}`: () => ['completed', 'failed', 'cancelled'].includes(status.state),
            });
          }
        } else if (statusRes.status === 404) {
          completed = true;
        }
      }

      if (!completed) {
        check(null, { 'assessment completed within timeout': () => false });
      }
    });
  }

  sleep(Math.random() * 3 + 1);
}

export function teardown(data) {
  console.log('Load test completed');
}
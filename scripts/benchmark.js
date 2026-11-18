// Strix Load/Stress Testing Scenarios for k6
// Run with: k6 run --out json=results.json scripts/benchmark.js

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { SharedArray } from 'k6/data';

// Custom metrics
const assessSuccessRate = new Rate('assess_success_rate');
const assessLatency = new Trend('assess_latency');
const healthLatency = new Trend('health_latency');
const findingsLatency = new Trend('findings_latency');
const errors = new Counter('errors');

// Test configuration via environment variables
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const API_KEY = __ENV.STRIX_API_KEY || 'test-admin-key-123456';
const TENANT_ID = __ENV.TENANT_ID || 'test-tenant';

// Headers for authenticated requests
const authHeaders = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
  'Accept': 'application/json',
};

// Headers for unauthenticated requests
const publicHeaders = {
  'Accept': 'application/json',
};

// Test data
const testTargets = [
  'https://httpbin.org/get',
  'https://httpbin.org/headers',
  'https://httpbin.org/ip',
];

const profiles = ['web', 'api'];

// Scenario configurations
export const options = {
  scenarios: {
    // Smoke test: 1 VU, 30s - quick validation
    smoke: {
      executor: 'constant-vus',
      vus: 1,
      duration: '30s',
      exec: 'smokeTest',
      tags: { scenario: 'smoke' },
    },
    // Load test: 50 VU, 5m, ramp up - sustained load
    load: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 10 },
        { duration: '1m', target: 25 },
        { duration: '2m', target: 50 },
        { duration: '1m', target: 50 },
        { duration: '30s', target: 0 },
      ],
      exec: 'loadTest',
      tags: { scenario: 'load' },
    },
    // Stress test: 200 VU, 10m, find breaking point
    stress: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '1m', target: 50 },
        { duration: '2m', target: 100 },
        { duration: '3m', target: 150 },
        { duration: '2m', target: 200 },
        { duration: '1m', target: 200 },
        { duration: '1m', target: 0 },
      ],
      exec: 'stressTest',
      tags: { scenario: 'stress' },
    },
    // Soak test: 100 VU, 1h - sustained load over time
    soak: {
      executor: 'constant-vus',
      vus: 100,
      duration: '1h',
      exec: 'soakTest',
      tags: { scenario: 'soak' },
    },
    // Spike test: sudden 500 VU burst
    spike: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 500 },
        { duration: '30s', target: 500 },
        { duration: '10s', target: 0 },
      ],
      exec: 'spikeTest',
      tags: { scenario: 'spike' },
    },
  },
  thresholds: {
    // Global thresholds (apply to all scenarios)
    'http_req_duration{scenario:smoke}': ['p(95)<500', 'p(99)<1000'],
    'http_req_duration{scenario:load}': ['p(95)<2000', 'p(99)<5000'],
    'http_req_duration{scenario:stress}': ['p(95)<5000', 'p(99)<10000'],
    'http_req_duration{scenario:soak}': ['p(95)<2000', 'p(99)<5000'],
    'http_req_duration{scenario:spike}': ['p(95)<10000', 'p(99)<15000'],
    'http_req_failed': ['rate<0.01'], // <1% failure rate
    'assess_success_rate{scenario:smoke}': ['rate>0.99'],
    'assess_success_rate{scenario:load}': ['rate>0.95'],
    'assess_success_rate{scenario:stress}': ['rate>0.90'],
    'assess_success_rate{scenario:soak}': ['rate>0.95'],
    'assess_success_rate{scenario:spike}': ['rate>0.85'],
  },
  // Export results as JSON for CI
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)', 'p(99.9)'],
};

// Setup: runs once before all scenarios
export function setup() {
  // Verify API is reachable
  const healthCheck = http.get(`${BASE_URL}/api/health`, { headers: publicHeaders });
  if (healthCheck.status !== 200) {
    throw new Error(`Health check failed: ${healthCheck.status}`);
  }

  // Verify readiness
  const readyCheck = http.get(`${BASE_URL}/api/ready`, { headers: publicHeaders });
  if (readyCheck.status !== 200) {
    throw new Error(`Readiness check failed: ${readyCheck.status}`);
  }

  console.log(`API at ${BASE_URL} is healthy and ready`);
  return { baseUrl: BASE_URL, apiKey: API_KEY };
}

// Teardown: runs once after all scenarios
export function teardown(data) {
  console.log('Benchmark completed');
}

// Helper: make authenticated request
function authRequest(method, url, payload = null, params = {}) {
  const headers = { ...authHeaders, ...params.headers };
  const options = { headers, ...params };
  if (payload) {
    options.body = JSON.stringify(payload);
  }
  return http.request(method, url, options);
}

// Helper: make public request
function publicRequest(method, url, params = {}) {
  const headers = { ...publicHeaders, ...params.headers };
  return http.request(method, url, { headers, ...params });
}

// Helper: check response and record metrics
function checkResponse(response, checks, metricName) {
  const success = check(response, checks);
  if (metricName) {
    if (success) {
      if (metricName === 'assess') assessSuccessRate.add(1);
      else if (metricName === 'health') healthLatency.add(response.timings.duration);
      else if (metricName === 'findings') findingsLatency.add(response.timings.duration);
    } else {
      assessSuccessRate.add(0);
      errors.add(1);
    }
  }
  return success;
}

// Smoke test: quick validation of core endpoints
export function smokeTest() {
  group('Health Check', () => {
    const res = publicRequest('GET', `${BASE_URL}/api/health`);
    checkResponse(res, {
      'status is 200': (r) => r.status === 200,
      'response has version': (r) => r.json('version') !== undefined,
    }, 'health');
  });

  group('Readiness Check', () => {
    const res = publicRequest('GET', `${BASE_URL}/api/ready`);
    checkResponse(res, {
      'status is 200': (r) => r.status === 200,
      'ready is true': (r) => r.json('ready') === true,
    }, 'health');
  });

  group('List Assessments (auth)', () => {
    const res = authRequest('GET', `${BASE_URL}/api/assess?page_size=5`);
    checkResponse(res, {
      'status is 200 or 401': (r) => r.status === 200 || r.status === 401,
    }, 'assess');
  });

  group('List Findings (auth)', () => {
    const res = authRequest('GET', `${BASE_URL}/api/findings?page_size=5`);
    checkResponse(res, {
      'status is 200 or 401': (r) => r.status === 200 || r.status === 401,
    }, 'findings');
  });

  sleep(1);
}

// Load test: sustained realistic load
export function loadTest() {
  const scenario = Math.random();

  if (scenario < 0.4) {
    // 40% - Health/Readiness checks (unauthenticated)
    group('Health Check', () => {
      const res = publicRequest('GET', `${BASE_URL}/api/health`);
      checkResponse(res, { 'status is 200': (r) => r.status === 200 }, 'health');
    });
    group('Readiness Check', () => {
      const res = publicRequest('GET', `${BASE_URL}/api/ready`);
      checkResponse(res, { 'status is 200': (r) => r.status === 200 }, 'health');
    });
  } else if (scenario < 0.7) {
    // 30% - List assessments (authenticated)
    group('List Assessments', () => {
      const res = authRequest('GET', `${BASE_URL}/api/assess?page_size=20`);
      checkResponse(res, { 'status is 200': (r) => r.status === 200 }, 'assess');
    });
  } else if (scenario < 0.85) {
    // 15% - List findings (authenticated)
    group('List Findings', () => {
      const res = authRequest('GET', `${BASE_URL}/api/findings?page_size=20`);
      checkResponse(res, { 'status is 200': (r) => r.status === 200 }, 'findings');
    });
  } else {
    // 15% - Create assessment (authenticated) - using wait=true for inline
    group('Create Assessment (inline)', () => {
      const target = testTargets[Math.floor(Math.random() * testTargets.length)];
      const profile = profiles[Math.floor(Math.random() * profiles.length)];
      const payload = {
        target,
        profile,
        wait: true,
        timeout: 30,
      };
      const res = authRequest('POST', `${BASE_URL}/api/assess`, payload);
      const success = checkResponse(res, {
        'status is 200 or 202 or 400 or 403': (r) => [200, 202, 400, 403].includes(r.status),
      }, 'assess');
      if (success && res.status === 200) {
        assessLatency.add(res.timings.duration);
      }
    });
  }

  sleep(Math.random() * 2 + 0.5); // 0.5-2.5s think time
}

// Stress test: push to limits
export function stressTest() {
  const scenario = Math.random();

  if (scenario < 0.3) {
    // 30% - Health checks
    group('Health Check', () => {
      const res = publicRequest('GET', `${BASE_URL}/api/health`);
      checkResponse(res, { 'status is 200': (r) => r.status === 200 }, 'health');
    });
  } else if (scenario < 0.55) {
    // 25% - List assessments
    group('List Assessments', () => {
      const res = authRequest('GET', `${BASE_URL}/api/assess?page_size=50`);
      checkResponse(res, { 'status is 200': (r) => r.status === 200 }, 'assess');
    });
  } else if (scenario < 0.75) {
    // 20% - List findings
    group('List Findings', () => {
      const res = authRequest('GET', `${BASE_URL}/api/findings?page_size=50`);
      checkResponse(res, { 'status is 200': (r) => r.status === 200 }, 'findings');
    });
  } else if (scenario < 0.9) {
    // 15% - Create assessments (queued, not inline)
    group('Create Assessment (queued)', () => {
      const target = testTargets[Math.floor(Math.random() * testTargets.length)];
      const profile = profiles[Math.floor(Math.random() * profiles.length)];
      const payload = {
        target,
        profile,
        wait: false,
        timeout: 120,
      };
      const res = authRequest('POST', `${BASE_URL}/api/assess`, payload);
      checkResponse(res, {
        'status is 202 or 400 or 403 or 503': (r) => [202, 400, 403, 503].includes(r.status),
      }, 'assess');
    });
  } else {
    // 10% - Get specific assessment
    group('Get Assessment', () => {
      const res = authRequest('GET', `${BASE_URL}/api/assess/invalid-id`);
      checkResponse(res, { 'status is 404': (r) => r.status === 404 }, 'assess');
    });
  }

  sleep(Math.random() * 1 + 0.2); // 0.2-1.2s think time
}

// Soak test: sustained load over long period
export function soakTest() {
  // Similar to load test but with longer think times
  const scenario = Math.random();

  if (scenario < 0.5) {
    group('Health Check', () => {
      const res = publicRequest('GET', `${BASE_URL}/api/health`);
      checkResponse(res, { 'status is 200': (r) => r.status === 200 }, 'health');
    });
    group('Readiness Check', () => {
      const res = publicRequest('GET', `${BASE_URL}/api/ready`);
      checkResponse(res, { 'status is 200': (r) => r.status === 200 }, 'health');
    });
  } else if (scenario < 0.8) {
    group('List Assessments', () => {
      const res = authRequest('GET', `${BASE_URL}/api/assess?page_size=20`);
      checkResponse(res, { 'status is 200': (r) => r.status === 200 }, 'assess');
    });
  } else {
    group('List Findings', () => {
      const res = authRequest('GET', `${BASE_URL}/api/findings?page_size=20`);
      checkResponse(res, { 'status is 200': (r) => r.status === 200 }, 'findings');
    });
  }

  sleep(Math.random() * 5 + 2); // 2-7s think time
}

// Spike test: sudden burst
export function spikeTest() {
  // All requests are health checks during spike
  group('Health Check (spike)', () => {
    const res = publicRequest('GET', `${BASE_URL}/api/health`);
    checkResponse(res, { 'status is 200': (r) => r.status === 200 }, 'health');
  });

  // Minimal sleep during spike
  sleep(0.05);
}

// Handle summary for JSON output
export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    baseUrl: BASE_URL,
    scenarios: {},
    overall: {
      totalRequests: data.metrics.http_reqs?.values?.count || 0,
      failedRequests: data.metrics.http_req_failed?.values?.passes || 0,
      avgDuration: data.metrics.http_req_duration?.values?.avg || 0,
      p95Duration: data.metrics.http_req_duration?.values['p(95)'] || 0,
      p99Duration: data.metrics.http_req_duration?.values['p(99)'] || 0,
    },
  };

  // Per-scenario breakdown
  for (const [scenarioName, scenarioData] of Object.entries(data.scenarios || {})) {
    summary.scenarios[scenarioName] = {
      vus: scenarioData.metrics.vus?.values?.max || 0,
      iterations: scenarioData.metrics.iterations?.values?.count || 0,
      avgDuration: scenarioData.metrics.http_req_duration?.values?.avg || 0,
      p95Duration: scenarioData.metrics.http_req_duration?.values['p(95)'] || 0,
      p99Duration: scenarioData.metrics.http_req_duration?.values['p(99)'] || 0,
      failedRate: scenarioData.metrics.http_req_failed?.values?.rate || 0,
    };
  }

  return {
    'stdout': textSummary(data, { indent: ' ', enableColors: true }),
    'results.json': JSON.stringify(summary, null, 2),
  };
}
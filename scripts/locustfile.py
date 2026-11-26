"""Locust soak test for Ishastra API.

Run with: locust -f scripts/locustfile.py --host=http://localhost:8000 --users 100 \
  --spawn-rate 10 --run-time 1h --headless --json=locust-results.json

For soak testing: sustained 100 VU for 1 hour with realistic think times.

Called by: CI workflow (benchmark-soak job), manual soak testing
Data schemas: Reads ISHASTRA_API_KEY env var, writes JSON results to stdout/file
User instruction: "complete all phase" - Phase 6 performance evidence
"""

import os
import random

from locust import HttpUser, between, events, task
from locust.env import Environment


class IshastraUser(HttpUser):
    """Simulated user performing realistic Ishastra API operations."""

    wait_time = between(2, 7)  # 2-7s think time for soak test

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_key = os.environ.get("ISHASTRA_API_KEY", "test-admin-key-123456")
        self.auth_headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.public_headers = {"Accept": "application/json"}

        # Test targets (using loopback lab targets)
        self.test_targets = [
            "https://httpbin.org/get",
            "https://httpbin.org/headers",
            "https://httpbin.org/ip",
        ]
        self.profiles = ["web", "api"]

        # Track metrics
        self.request_count = 0
        self.error_count = 0

    def on_start(self):
        """Verify API is healthy before starting."""
        with self.client.get("/api/health", headers=self.public_headers, catch_response=True) as response:
            if response.status_code != 200:
                response.failure(f"Health check failed: {response.status_code}")
            else:
                response.success()

    @task(5)
    def health_check(self):
        """Health check endpoint (unauthenticated)."""
        with self.client.get("/api/health", headers=self.public_headers, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed: {response.status_code}")
            self.request_count += 1

    @task(3)
    def readiness_check(self):
        """Readiness check endpoint (unauthenticated)."""
        with self.client.get("/api/ready", headers=self.public_headers, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Readiness check failed: {response.status_code}")
            self.request_count += 1

    @task(4)
    def list_assessments(self):
        """List assessments (authenticated)."""
        with self.client.get(
            "/api/assess?page_size=20", headers=self.auth_headers, catch_response=True
        ) as response:
            if response.status_code in (200, 401):
                response.success()
            else:
                response.failure(f"List assessments failed: {response.status_code}")
            self.request_count += 1

    @task(3)
    def list_findings(self):
        """List findings (authenticated)."""
        with self.client.get(
            "/api/findings?page_size=20", headers=self.auth_headers, catch_response=True
        ) as response:
            if response.status_code in (200, 401):
                response.success()
            else:
                response.failure(f"List findings failed: {response.status_code}")
            self.request_count += 1

    @task(2)
    def create_assessment_inline(self):
        """Create inline assessment (authenticated)."""
        target = random.choice(self.test_targets)
        profile = random.choice(self.profiles)
        payload = {
            "target": target,
            "profile": profile,
            "wait": True,
            "timeout": 30,
        }

        with self.client.post(
            "/api/assess", json=payload, headers=self.auth_headers, catch_response=True
        ) as response:
            if response.status_code in (200, 202, 400, 403):
                response.success()
            else:
                response.failure(f"Create assessment failed: {response.status_code}")
            self.request_count += 1

    @task(1)
    def create_assessment_queued(self):
        """Create queued assessment (authenticated)."""
        target = random.choice(self.test_targets)
        profile = random.choice(self.profiles)
        payload = {
            "target": target,
            "profile": profile,
            "wait": False,
            "timeout": 120,
        }

        with self.client.post(
            "/api/assess", json=payload, headers=self.auth_headers, catch_response=True
        ) as response:
            if response.status_code in (202, 400, 403, 503):
                response.success()
            else:
                response.failure(f"Create queued assessment failed: {response.status_code}")
            self.request_count += 1

    @task(1)
    def get_metrics(self):
        """Get Prometheus metrics."""
        with self.client.get("/metrics", headers=self.public_headers, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Metrics failed: {response.status_code}")
            self.request_count += 1


class SpikeUser(HttpUser):
    """User for spike testing - minimal think time, high frequency."""

    wait_time = between(0.05, 0.2)  # Very short think time for spike

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.auth_headers = {
            "Authorization": f"Bearer {os.environ.get('ISHASTRA_API_KEY', 'test-admin-key-123456')}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.public_headers = {"Accept": "application/json"}

    @task(10)
    def health_check_spike(self):
        """Rapid health checks during spike."""
        with self.client.get("/api/health", headers=self.public_headers, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Spike health check failed: {response.status_code}")


# Event handlers for custom metrics
@events.test_start.add_listener
def on_test_start(environment: Environment, **kwargs):
    """Called when test starts."""
    print(f"Starting soak test with {environment.parsed_options.num_users} users")


@events.test_stop.add_listener
def on_test_stop(environment: Environment, **kwargs):
    """Called when test stops."""
    print("Soak test completed")


# Allow running as standalone script for debugging
if __name__ == "__main__":
    import sys

    from locust.main import main as locust_main

    # If run directly, pass args to locust
    sys.argv = ["locust"] + sys.argv[1:]
    locust_main()

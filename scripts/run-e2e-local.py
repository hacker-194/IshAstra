#!/usr/bin/env python3
"""
Run E2E tests locally against docker-compose stack.

Usage:
    python3 scripts/run-e2e-local.py [--compose-file docker-compose.yml] [--scope scope.json]

This script:
1. Starts the docker-compose stack (or uses running one)
2. Waits for health checks
3. Runs the E2E test suite against the local API
4. Outputs results
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path


def run_cmd(cmd: list[str], cwd: Path | None = None, env: dict | None = None) -> subprocess.CompletedProcess:
    """Run command and return result."""
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(cmd, cwd=cwd, env=merged_env, capture_output=True, text=True)


def wait_for_service(url: str, timeout: int = 120, interval: int = 5) -> bool:
    """Wait for a service to become healthy."""
    import urllib.error
    import urllib.request

    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            pass
        time.sleep(interval)
    return False


def main():
    parser = argparse.ArgumentParser(description="Run Strix E2E tests locally")
    parser.add_argument(
        "--compose-file",
        default="docker-compose.yml",
        help="Docker compose file (default: docker-compose.yml)",
    )
    parser.add_argument(
        "--scope",
        default="examples/scopes/default.json",
        help="Scope file for tests (default: examples/scopes/default.json)",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="Base URL for API (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="Don't start docker-compose, assume it's already running",
    )
    parser.add_argument(
        "--no-stop",
        action="store_true",
        help="Don't stop docker-compose after tests",
    )
    parser.add_argument(
        "--test-path",
        default="tests/e2e",
        help="Path to E2E tests (default: tests/e2e)",
    )
    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    compose_file = project_root / args.compose_file
    scope_file = project_root / args.scope

    if not compose_file.exists():
        print(f"error: compose file not found: {compose_file}", file=sys.stderr)
        return 1
    if not scope_file.exists():
        print(f"error: scope file not found: {scope_file}", file=sys.stderr)
        return 1

    # Generate secrets for local dev
    print("Generating local development secrets...")
    result = run_cmd(
        [
            sys.executable,
            "scripts/generate-secrets.py",
            "--output-dir",
            ".env.secrets",
            "--env-file",
            "--k8s-manifest",
        ],
        cwd=project_root,
    )
    if result.returncode != 0:
        print(f"error generating secrets: {result.stderr}", file=sys.stderr)
        return 1

    # Source the env file
    env_file = project_root / ".env.secrets" / ".env.secrets"
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key] = value.strip('"')

    # Start docker-compose
    if not args.no_start:
        print("Starting docker-compose stack...")
        result = run_cmd(["docker-compose", "-f", str(compose_file), "up", "-d", "--build"], cwd=project_root)
        if result.returncode != 0:
            print(f"error starting docker-compose: {result.stderr}", file=sys.stderr)
            return 1

        # Wait for services
        print("Waiting for services to be healthy...")
        services = [
            (f"{args.base_url}/api/health", "ScopeGate API"),
            ("http://localhost:9090/-/healthy", "Prometheus"),
            ("http://localhost:3000/api/health", "Grafana"),
            ("http://localhost:16686/", "Jaeger"),
        ]
        for url, name in services:
            print(f"  Waiting for {name}...")
            if not wait_for_service(url):
                print(f"  ✗ {name} failed to become healthy", file=sys.stderr)
                if not args.no_stop:
                    run_cmd(["docker-compose", "-f", str(compose_file), "down"], cwd=project_root)
                return 1
            print(f"  ✓ {name} is healthy")

    # Set required environment variables for E2E tests
    os.environ["STRIX_E2E_BASE_URL"] = args.base_url
    os.environ["STRIX_SCOPE_FILE"] = str(scope_file)

    # Run E2E tests
    print(f"\nRunning E2E tests from {args.test_path}...")
    result = run_cmd(
        [
            sys.executable,
            "-m",
            "pytest",
            args.test_path,
            "-v",
            "--tb=short",
            "-x",
        ],
        cwd=project_root,
    )

    # Stop docker-compose
    if not args.no_stop:
        print("\nStopping docker-compose stack...")
        run_cmd(["docker-compose", "-f", str(compose_file), "down", "-v"], cwd=project_root)

    if result.returncode == 0:
        print("\n✓ All E2E tests passed!")
    else:
        print("\n✗ E2E tests failed")
        print(result.stdout)
        print(result.stderr, file=sys.stderr)

    return result.returncode


if __name__ == "__main__":
    sys.exit(main())

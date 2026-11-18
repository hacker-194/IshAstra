#!/usr/bin/env python3
"""HTTP load smoke benchmark for a real uvicorn process.

This is a single-process, single-machine baseline, not a capacity proof. It
starts Strix with a temporary database, drives the unauthenticated health
endpoint at a fixed concurrency, and prints latency percentiles and throughput.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

API_KEY = "load-check-admin-key-123456"
AUDIT_KEY = "load-check-audit-key-123456"


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


async def _wait_for_health(client: httpx.AsyncClient, base_url: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            response = await client.get(f"{base_url}/api/health")
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0.2)
    raise RuntimeError("API did not become healthy within the timeout")


async def _drive(base_url: str, requests: int, concurrency: int) -> tuple[list[float], int, float]:
    semaphore = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    errors = 0

    async with httpx.AsyncClient(timeout=10.0) as client:
        await _wait_for_health(client, base_url)

        async def one() -> None:
            nonlocal errors
            async with semaphore:
                started = time.perf_counter()
                try:
                    response = await client.get(f"{base_url}/api/health")
                    if response.status_code != 200:
                        errors += 1
                except httpx.HTTPError:
                    errors += 1
                finally:
                    latencies.append((time.perf_counter() - started) * 1000)

        started = time.perf_counter()
        await asyncio.gather(*(one() for _ in range(requests)))
        wall_seconds = time.perf_counter() - started

    return latencies, errors, wall_seconds


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--port", type=int, default=8099)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="strix-load-") as tmp:
        env = os.environ.copy()
        env.update(
            {
                "STRIX_API_KEY": API_KEY,
                "STRIX_AUDIT_HMAC_KEY": AUDIT_KEY,
                "STRIX_DB": str(Path(tmp) / "load.db"),
                "STRIX_SCOPE_FILE": str(repo_root / "scope.example.json"),
                "STRIX_LOG_LEVEL": "WARNING",
            }
        )
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "strix.api.app:create_app",
                "--factory",
                "--host",
                "127.0.0.1",
                "--port",
                str(args.port),
                "--log-level",
                "warning",
            ],
            cwd=repo_root,
            env=env,
        )
        try:
            latencies, errors, wall_seconds = asyncio.run(
                _drive(f"http://127.0.0.1:{args.port}", args.requests, args.concurrency)
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()

    rps = len(latencies) / wall_seconds if wall_seconds else 0.0
    print(f"requests: {len(latencies)}")
    print(f"concurrency: {args.concurrency}")
    print(f"errors: {errors}")
    print(f"throughput: {rps:.1f} req/s")
    print(f"latency p50: {statistics.median(latencies):.2f} ms")
    print(f"latency p95: {_percentile(latencies, 0.95):.2f} ms")
    print(f"latency p99: {_percentile(latencies, 0.99):.2f} ms")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

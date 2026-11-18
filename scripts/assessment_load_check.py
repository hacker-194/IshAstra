#!/usr/bin/env python3
"""End-to-end assessment throughput benchmark.

Starts a real uvicorn API with a bounded in-process worker pool and a temporary
SQLite database, then submits assessments against the loopback detection lab.
Unlike ``load_check.py`` this exercises scope checks, adapter execution, job
persistence and finding writes — the work an assessment actually does.

The result is a single-machine smoke measurement, not a capacity commitment.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

from strix.lab.target import LabTarget

API_KEY = "assessment-load-admin-key-123456"
AUDIT_KEY = "assessment-load-audit-key-123456"
TERMINAL = {"completed", "partial", "failed", "cancelled"}


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


async def _wait_for_health(client: httpx.AsyncClient, base_url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if (await client.get(f"{base_url}/api/health")).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0.2)
    raise RuntimeError("API did not become healthy within the timeout")


async def _run(
    base_url: str, target_url: str, *, jobs: int, submit_concurrency: int, timeout: float
) -> tuple[list[dict], list[float], float]:
    headers = {"Authorization": f"Bearer {API_KEY}"}
    semaphore = asyncio.Semaphore(submit_concurrency)
    async with httpx.AsyncClient(timeout=30.0) as client:
        await _wait_for_health(client, base_url)
        started = time.perf_counter()

        async def submit_one() -> str:
            async with semaphore:
                response = await client.post(
                    f"{base_url}/api/assess",
                    headers=headers,
                    json={"target": target_url, "profile": "web", "wait": False},
                )
                response.raise_for_status()
                return response.json()["id"]

        job_ids = await asyncio.gather(*(submit_one() for _ in range(jobs)))

        latencies: list[float] = []
        rows: list[dict] = []
        pending = set(job_ids)
        submitted_at = dict.fromkeys(job_ids, started)
        deadline = time.monotonic() + timeout
        while pending and time.monotonic() < deadline:
            for job_id in list(pending):
                response = await client.get(f"{base_url}/api/assess/{job_id}", headers=headers)
                if response.status_code != 200:
                    continue
                row = response.json()
                if row["state"] in TERMINAL:
                    pending.discard(job_id)
                    rows.append(row)
                    latencies.append((time.perf_counter() - submitted_at[job_id]) * 1000)
            if pending:
                await asyncio.sleep(0.1)
        wall_seconds = time.perf_counter() - started

        for job_id in pending:
            rows.append({"id": job_id, "state": "timed_out"})
    return rows, latencies, wall_seconds


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=50)
    parser.add_argument("--submit-concurrency", type=int, default=10)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--port", type=int, default=8098)
    parser.add_argument(
        "--database-url",
        default="",
        help="PostgreSQL DSN (default: temporary SQLite database)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="strix-assessment-load-") as tmp, LabTarget() as lab:
        scope_path = Path(tmp) / "scope.json"
        scope_path.write_text(
            json.dumps(
                {
                    "program": "Strix assessment load check",
                    "authorized_by": "Benchmark",
                    "authorization_ref": "BENCH-ASSESS",
                    "include": ["127.0.0.1"],
                    "authorized_networks": ["127.0.0.1/32"],
                    "allowed_ports": [lab.port],
                }
            )
        )
        env = os.environ.copy()
        env.update(
            {
                "STRIX_DATABASE_URL": args.database_url,
                "STRIX_API_KEY": API_KEY,
                "STRIX_AUDIT_HMAC_KEY": AUDIT_KEY,
                "STRIX_DB": str(Path(tmp) / "assess.db") if not args.database_url else "",
                "STRIX_SCOPE_FILE": str(scope_path),
                "STRIX_SCOPE_MODE": "global",
                "STRIX_WORKERS": str(args.workers),
                "STRIX_QUEUE_MAX": "128",
                # Isolate scanner throughput from the API rate limiter; the
                # limiter has its own Redis test.
                "STRIX_RATE_LIMIT_DISABLED": "1",
                "STRIX_SKIP_REDIS_INIT": "1",
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
            rows, latencies, wall_seconds = asyncio.run(
                _run(
                    f"http://127.0.0.1:{args.port}",
                    f"{lab.base_url}/",
                    jobs=args.jobs,
                    submit_concurrency=args.submit_concurrency,
                    timeout=args.timeout,
                )
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()

    states: dict[str, int] = {}
    for row in rows:
        states[row["state"]] = states.get(row["state"], 0) + 1
    completed = states.get("completed", 0) + states.get("partial", 0)
    failed = len(rows) - completed

    print(f"jobs: {len(rows)}")
    print(f"worker concurrency: {args.workers}")
    print(f"states: {states}")
    print(f"throughput: {len(rows) / wall_seconds:.2f} jobs/s")
    if latencies:
        print(f"job latency p50: {statistics.median(latencies):.1f} ms")
        print(f"job latency p95: {_percentile(latencies, 0.95):.1f} ms")
        print(f"job latency p99: {_percentile(latencies, 0.99):.1f} ms")
    print(f"wall time: {wall_seconds:.2f} s")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

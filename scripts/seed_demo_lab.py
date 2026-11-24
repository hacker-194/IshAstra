#!/usr/bin/env python3
"""Seed a demo database with jobs in every dashboard state.

Writes to the same schema ``store`` creates (no API key, no network), so a
demo instance shows failed/partial/cancelled/queued/completed rows side by
side instead of an empty dashboard.

    python scripts/seed_demo_lab.py --db ./ishastra-demo.db
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import time
from pathlib import Path

TENANT = "demo"


def _bootstrap_schema(path: Path) -> None:
    """Create the real schema through store's migrations.

    Hand-written DDL drifts: rows written against a copy of the base tables
    miss columns that later migrations add, and store.get_job() then fails.
    """
    from ishastra.core import store

    async def _create() -> None:
        store.configure(path)
        await store.get_database()
        await store.close_database()

    asyncio.run(_create())


def _finding(job_id: str, fingerprint: str, **fields: str) -> tuple:
    return (
        job_id,
        TENANT,
        fingerprint,
        fields.get("asset", ""),
        fields.get("category", "demo-finding"),
        fields["title"],
        fields["severity"],
        "high",
        "observed",
        "new",
        "demo",
        "1.0",
        fields.get("asset", ""),
        fields.get("evidence", ""),
        f"{fields['title']} observed during the demo assessment.",
        fields.get("remediation", ""),
        fields.get("cwe", ""),
        "0.0",
    )


def seed(db_path: str | Path) -> dict[str, int]:
    path = Path(db_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    policy = json.dumps(
        {
            "scope": {
                "program": "Ishastra demo lab",
                "authorized_by": "Demo operator",
                "authorization_ref": "DEMO-001",
                "include": ["localhost", "127.0.0.1"],
                "allowed_ports": [80, 443, 8000],
            }
        }
    )
    coverage = json.dumps({"adapters": {}})
    jobs = [
        ("demo-completed", "http://127.0.0.1:8000", "web", "completed", "findings", "", now - 60, now - 30),
        ("demo-partial", "http://127.0.0.1:8001", "api", "partial", "inconclusive", "", now - 120, now - 90),
        (
            "demo-failed",
            "http://127.0.0.1:8002",
            "network",
            "failed",
            "error",
            "adapter crashed",
            now - 180,
            now - 150,
        ),
        ("demo-queued", "http://127.0.0.1:8003", "web-deep", "queued", "pending", "", None, None),
        (
            "demo-cancelled",
            "http://127.0.0.1:8004",
            "web",
            "cancelled",
            "cancelled",
            "cancelled by operator",
            now - 240,
            now - 230,
        ),
    ]
    findings = [
        _finding(
            "demo-completed",
            "demo-fp-1",
            title="Reflected cross-site scripting",
            severity="high",
            asset="http://127.0.0.1:8000/search?q=",
            evidence="payload reflected unencoded",
            cwe="CWE-79",
            remediation="Encode output",
        ),
        _finding(
            "demo-completed",
            "demo-fp-2",
            title="Server version disclosed",
            severity="info",
            asset="http://127.0.0.1:8000/",
            evidence="Server: demo/1.0",
        ),
        _finding(
            "demo-partial",
            "demo-fp-3",
            title="Open administrative interface",
            severity="medium",
            asset="http://127.0.0.1:8001/admin",
            evidence="HTTP 200 with login form",
        ),
    ]

    _bootstrap_schema(path)
    conn = sqlite3.connect(path)
    try:
        for job_id, target, profile, state, verdict, error, started, finished in jobs:
            conn.execute(
                "INSERT OR REPLACE INTO jobs (id, tenant, project, target, profile, actor, policy, "
                "state, verdict, error, started_at, finished_at, coverage, created_at) "
                "VALUES (?, ?, 'default', ?, ?, 'demo', ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    job_id,
                    TENANT,
                    target,
                    profile,
                    policy,
                    state,
                    verdict,
                    error,
                    started,
                    finished,
                    coverage,
                    now,
                ),
            )
        conn.executemany(
            "INSERT OR REPLACE INTO findings (job_id, tenant, fingerprint, asset, category, title, "
            "severity, confidence, verification, status, detector, detector_version, location, "
            "evidence, description, remediation, cwe, cvss_score, sources) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]')",
            findings,
        )
        conn.commit()
        counts = {
            state: conn.execute("SELECT COUNT(*) FROM jobs WHERE state = ?", (state,)).fetchone()[0]
            for state in ("completed", "partial", "failed", "queued", "cancelled")
        }
        counts["findings"] = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    finally:
        conn.close()
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed a demo database with sample jobs")
    parser.add_argument("--db", default="ishastra-demo.db", help="SQLite database path")
    args = parser.parse_args(argv)
    counts = seed(args.db)
    print(f"Seeded {args.db}: " + ", ".join(f"{key}={value}" for key, value in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

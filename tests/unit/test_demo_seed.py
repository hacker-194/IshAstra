"""The demo seeder must produce one row per dashboard state."""

from __future__ import annotations

import sqlite3

from scripts.seed_demo_lab import seed


def test_seed_writes_every_state(tmp_path):
    db_path = tmp_path / "demo.db"
    counts = seed(db_path)

    assert counts["completed"] == 1
    assert counts["partial"] == 1
    assert counts["failed"] == 1
    assert counts["queued"] == 1
    assert counts["cancelled"] == 1
    assert counts["findings"] == 3

    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT job_id FROM findings WHERE job_id = 'demo-failed'").fetchall()
        assert rows == []
    finally:
        conn.close()

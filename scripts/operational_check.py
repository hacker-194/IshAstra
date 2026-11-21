"""Non-destructive backup/restore drill for a Ishastra SQLite database.

Uses SQLite's online backup API, then reopens the copy read-only, checks
integrity and compares table row counts. Exits non-zero on any mismatch.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sqlite3
import sys
import tempfile
from pathlib import Path


def _table_counts(conn: sqlite3.Connection) -> dict[str, int]:
    tables = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    return {table: conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0] for table in tables}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="ishastra.db", help="source SQLite database (read-only)")
    parser.add_argument("--out", default=None, help="backup path (default: temporary file)")
    parser.add_argument(
        "--hmac-key",
        default=os.environ.get("ISHASTRA_AUDIT_HMAC_KEY", ""),
        help="audit-chain HMAC key (default: ISHASTRA_AUDIT_HMAC_KEY); omit to skip chain verification",
    )
    args = parser.parse_args()

    source_path = Path(args.db)
    if not source_path.is_file():
        print(f"error: database not found: {source_path}", file=sys.stderr)
        return 2

    if args.out:
        backup_path = Path(args.out)
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
    else:
        handle, name = tempfile.mkstemp(suffix=".db", prefix="ishastra-backup-")
        Path(name).unlink(missing_ok=True)
        backup_path = Path(name)
        temporary = handle

    source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
    try:
        backup = sqlite3.connect(backup_path)
        try:
            source.backup(backup)
        finally:
            backup.close()

        source_counts = _table_counts(source)

        restored = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
        try:
            integrity = restored.execute("PRAGMA integrity_check").fetchone()[0]
            backup_counts = _table_counts(restored)
        finally:
            restored.close()
    finally:
        source.close()
        if temporary is not None:
            os.close(temporary)

    rows = sum(source_counts.values())
    print(f"source: {source_path} ({len(source_counts)} tables, {rows} rows)")
    print(f"backup: {backup_path}")
    print(f"integrity: {integrity}")
    print(f"tables match: {source_counts == backup_counts}")
    if source_counts != backup_counts:
        print(f"source counts: {source_counts}", file=sys.stderr)
        print(f"backup counts: {backup_counts}", file=sys.stderr)
        return 1
    if integrity != "ok":
        return 1

    if not args.hmac_key:
        print("audit chain: skipped (no --hmac-key or ISHASTRA_AUDIT_HMAC_KEY)")
        return 0

    from ishastra.audit import AuditChain
    from ishastra.core import store

    async def verify_chain() -> tuple[bool, str | None, int]:
        store.configure(backup_path)
        chain = AuditChain(persistent=True, hmac_key=args.hmac_key)
        valid, reason = await chain.verify_async()
        length = await chain.len_async()
        await store.close_database()
        return valid, reason, length

    try:
        valid, reason, entries = asyncio.run(verify_chain())
    except Exception as exc:
        print(f"audit chain: failed ({type(exc).__name__}: {exc})", file=sys.stderr)
        return 1
    print(f"audit chain: {'ok' if valid else 'FAILED'} ({entries} entries)")
    if not valid:
        print(f"audit chain error: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

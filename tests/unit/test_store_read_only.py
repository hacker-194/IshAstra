"""Read-only transactions reject writes on SQLite."""

from __future__ import annotations

import pytest

from ishastra.core import store


async def test_read_transaction_allows_reads_and_rejects_writes() -> None:
    db = await store.get_database()
    async with db.read_transaction() as conn:
        cursor = await conn.execute("SELECT 1")
        row = await cursor.fetchone()
        assert row[0] == 1
        with pytest.raises(Exception) as excinfo:
            await conn.execute("CREATE TABLE readonly_probe (id INTEGER)")
        assert "readonly" in str(excinfo.value).lower()

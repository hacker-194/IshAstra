"""Local object store must not escape the tenant directory."""

from __future__ import annotations

import asyncio

import pytest

from ishastra.core.object_storage import LocalObjectStore


def test_round_trip(tmp_path):
    store = LocalObjectStore(str(tmp_path))
    asyncio.run(store.put_object("tenant-a/reports/a.txt", b"hello"))
    assert asyncio.run(store.get_object("tenant-a/reports/a.txt")) == b"hello"


@pytest.mark.parametrize(
    "key",
    [
        "../outside.txt",
        "tenant-a/../../outside.txt",
        "tenant-a/../../../etc/passwd",
        "tenant-a//etc/passwd",
        "../tenant-b/secret.txt",
    ],
)
def test_rejects_paths_outside_the_tenant(tmp_path, key):
    store = LocalObjectStore(str(tmp_path))
    with pytest.raises(ValueError, match="escapes"):
        asyncio.run(store.put_object(key, b"nope"))
    assert not (tmp_path.parent / "outside.txt").exists()

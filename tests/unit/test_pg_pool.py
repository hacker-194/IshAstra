"""PostgreSQL pool sizing: configurable, bounded, never absurd.

Each process opens its own asyncpg pool, so the pool size multiplied by the
replica count has to fit the server's max_connections. A bad value here is a
fleet that cannot connect at all.
"""

from __future__ import annotations

from ishastra.core import store


def _clear(monkeypatch):
    monkeypatch.delenv("ISHASTRA_PG_POOL_MIN", raising=False)
    monkeypatch.delenv("ISHASTRA_PG_POOL_MAX", raising=False)


def test_defaults_are_small_enough_for_a_fleet(monkeypatch):
    _clear(monkeypatch)
    assert store._pg_pool_sizes() == (1, 5)


def test_env_overrides_are_used(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("ISHASTRA_PG_POOL_MIN", "2")
    monkeypatch.setenv("ISHASTRA_PG_POOL_MAX", "4")
    assert store._pg_pool_sizes() == (2, 4)


def test_max_below_min_is_raised_to_min(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("ISHASTRA_PG_POOL_MIN", "8")
    monkeypatch.setenv("ISHASTRA_PG_POOL_MAX", "3")
    assert store._pg_pool_sizes() == (8, 8)


def test_garbage_falls_back_to_defaults(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("ISHASTRA_PG_POOL_MIN", "lots")
    monkeypatch.setenv("ISHASTRA_PG_POOL_MAX", "-4")
    assert store._pg_pool_sizes() == (1, 5)


def test_absurd_max_is_clamped(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("ISHASTRA_PG_POOL_MAX", "100000")
    assert store._pg_pool_sizes()[1] == store.PG_POOL_MAX_LIMIT

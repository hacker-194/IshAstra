"""Regression: every API tier must resolve a rate limit instead of raising.

A fresh production install uses the bootstrap key, whose tier is ``free``.
The rate-limit tables only knew ``standard/elevated/unlimited``, so every
authenticated request raised ``KeyError: 'free'`` and returned 500.
"""

from __future__ import annotations

from strix.api.security import TIER_ORDER, _RateLimiter
from strix.core.rate_limit import ASSESS_RATE_LIMITS, TIER_RATE_LIMITS


def test_every_api_tier_has_both_limits() -> None:
    for tier in TIER_ORDER:
        assert tier in TIER_RATE_LIMITS, f"missing general limit for tier {tier!r}"
        assert tier in ASSESS_RATE_LIMITS, f"missing assessment limit for tier {tier!r}"


def test_organization_tiers_still_covered() -> None:
    for tier in ("standard", "elevated", "unlimited"):
        assert tier in TIER_RATE_LIMITS
        assert tier in ASSESS_RATE_LIMITS


def test_unknown_tier_falls_back_without_raising() -> None:
    for route_class in ("default", "assessment"):
        rate, per = _RateLimiter._limit_for(route_class, "not-a-real-tier")
        assert rate > 0
        assert per > 0

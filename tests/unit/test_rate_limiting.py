"""Tests for per-job token bucket rate limiting enforcement."""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

from ishastra.core.rate_limiter import JobRateLimiter, RateLimitResult, TokenBucket


class TestTokenBucket:
    """Tests for the TokenBucket class."""

    def test_unlimited_bucket_allows_all_requests(self) -> None:
        """Rate limit of 0 means unlimited."""
        bucket = TokenBucket(0)
        for _ in range(100):
            result = bucket.try_consume()
            assert result.allowed is True
            assert result.limit == 0

    def test_bucket_allows_burst_up_to_capacity(self) -> None:
        """Bucket should allow burst up to capacity."""
        bucket = TokenBucket(10)  # 10 RPS = capacity of 10
        for i in range(10):
            result = bucket.try_consume()
            assert result.allowed is True
            assert result.remaining == 9 - i

    def test_bucket_rejects_when_empty(self) -> None:
        """Bucket should reject when tokens exhausted."""
        bucket = TokenBucket(2)
        bucket.try_consume()
        bucket.try_consume()
        result = bucket.try_consume()
        assert result.allowed is False
        assert result.retry_after > 0

    def test_bucket_refills_over_time(self) -> None:
        """Bucket should refill tokens over time."""
        bucket = TokenBucket(10)
        bucket.try_consume(10)  # Exhaust
        time.sleep(0.2)  # Wait for ~2 tokens to refill (10 RPS * 0.2s = 2)
        result = bucket.try_consume()
        assert result.allowed is True

    def test_consume_blocks_until_available(self) -> None:
        """consume() should block until tokens available."""
        bucket = TokenBucket(5)
        bucket.try_consume(5)  # Exhaust
        start = time.monotonic()
        waited = bucket.consume(1)
        elapsed = time.monotonic() - start
        assert waited > 0
        assert elapsed >= waited * 0.9  # Allow some slack

    def test_reset_restores_full_capacity(self) -> None:
        """reset() should restore bucket to full."""
        bucket = TokenBucket(5)
        bucket.try_consume(5)
        bucket.reset()
        result = bucket.try_consume()
        assert result.allowed is True
        assert result.remaining == 4

    def test_thread_safety(self) -> None:
        """TokenBucket should be thread-safe."""
        bucket = TokenBucket(100)
        allowed_count = 0
        rejected_count = 0
        lock = threading.Lock()

        def worker():
            nonlocal allowed_count, rejected_count
            try:
                for _ in range(25):
                    result = bucket.try_consume()
                    with lock:
                        if result.allowed:
                            allowed_count += 1
                        else:
                            rejected_count += 1
            except Exception:
                with lock:
                    rejected_count += 1

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 4 threads * 25 = 100 requests, bucket capacity = 100
        assert allowed_count == 100
        assert rejected_count == 0

    def test_rate_limit_result_fields(self) -> None:
        """RateLimitResult should have correct fields."""
        bucket = TokenBucket(10)
        result = bucket.try_consume()
        assert isinstance(result, RateLimitResult)
        assert hasattr(result, "allowed")
        assert hasattr(result, "limit")
        assert hasattr(result, "remaining")
        assert hasattr(result, "retry_after")


class TestJobRateLimiter:
    """Tests for the JobRateLimiter class."""

    def test_disabled_when_rate_limit_is_zero(self) -> None:
        """JobRateLimiter should be disabled when rate_limit_rps is 0."""
        limiter = JobRateLimiter(0)
        assert limiter.enabled is False
        assert limiter.rate_limit_rps == 0
        # pace() should not block
        start = time.monotonic()
        limiter.pace()
        assert time.monotonic() - start < 0.01

    def test_enabled_when_rate_limit_positive(self) -> None:
        """JobRateLimiter should be enabled when rate_limit_rps > 0."""
        limiter = JobRateLimiter(10)
        assert limiter.enabled is True
        assert limiter.rate_limit_rps == 10

    def test_pace_enforces_rate_limit(self) -> None:
        """pace() should enforce the rate limit."""
        limiter = JobRateLimiter(10)  # 10 RPS = 0.1s between requests, capacity=10
        # Exhaust initial burst first
        for _ in range(10):
            limiter.pace()
        # Now next requests should be paced
        start = time.monotonic()
        for _ in range(5):
            limiter.pace()
        elapsed = time.monotonic() - start
        # 5 requests at 10 RPS = ~0.5s minimum
        assert elapsed >= 0.4  # Allow some slack

    def test_try_pace_returns_result(self) -> None:
        """try_pace() should return RateLimitResult without blocking."""
        limiter = JobRateLimiter(10)
        result = limiter.try_pace()
        assert isinstance(result, RateLimitResult)
        assert result.allowed is True
        assert result.limit == 10

    def test_try_pace_rejects_when_exhausted(self) -> None:
        """try_pace() should reject when bucket empty."""
        limiter = JobRateLimiter(2)
        limiter.try_pace()
        limiter.try_pace()
        result = limiter.try_pace()
        assert result.allowed is False
        assert result.retry_after > 0


class TestRateLimiterIntegration:
    """Integration tests for rate limiter with jobs."""

    def test_job_creates_rate_limiter_from_roe(self) -> None:
        """Job should create rate limiter from engagement rules_of_engagement."""
        from ishastra.core.jobs import prepare
        from ishastra.core.scope import Scope

        scope = Scope(
            program="test",
            authorized_by="tester",
            authorization_ref="ref",
            include=("example.com",),
            rules_of_engagement={"rate_limit_rps": 50},
        )

        job = prepare("https://example.com", scope_snapshot=scope)
        assert job.policy.get("rate_limit_rps") == 50

    @patch("ishastra.core.jobs.adapter_module.select")
    def test_job_passes_rate_limiter_to_adapters(self, mock_select) -> None:
        """Job should pass rate limiter in context to adapters."""
        from ishastra.core.adapters import AdapterResult
        from ishastra.core.jobs import execute, prepare
        from ishastra.core.scope import Scope

        class MockAdapter:
            id = "mock"
            requires = ()

            def available(self):
                return True, "ok"

            def assess(self, target, timeout, cancel, context):
                # Verify rate_limiter is in context
                assert "rate_limiter" in context
                assert context["rate_limiter"] is not None
                assert context["rate_limiter"].enabled is True
                return AdapterResult()

        mock_select.return_value = [MockAdapter()]

        scope = Scope(
            program="test",
            authorized_by="tester",
            authorization_ref="ref",
            include=("example.com",),
            rules_of_engagement={"rate_limit_rps": 10},
        )

        job = prepare("https://example.com", scope_snapshot=scope)
        execute(job)

        assert job.state.value == "completed"


class TestProbeWithRateLimiter:
    """Tests for EndpointProbe using JobRateLimiter."""

    def test_probe_uses_rate_limiter_when_provided(self) -> None:
        """Probe should use JobRateLimiter when provided."""
        from ishastra.core.probe import EndpointProbe
        from ishastra.core.rate_limiter import JobRateLimiter

        limiter = JobRateLimiter(100)  # High rate for test
        probe = EndpointProbe(timeout=1.0, rate_limiter=limiter)

        # Mock _fetch to avoid actual network calls
        call_count = 0

        def mock_fetch(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return {"url": "test", "status": 200, "headers": {}, "body": ""}

        probe._fetch = mock_fetch

        probe.probe("https://example.com")
        probe.probe("https://example.com")

        # Should have been paced by rate limiter
        assert call_count == 2

    def test_probe_fallback_to_min_interval_when_no_limiter(self) -> None:
        """Probe should fall back to min_interval when no rate_limiter."""
        from ishastra.core.probe import EndpointProbe

        probe = EndpointProbe(timeout=1.0, rate_limit_rps=10)

        call_count = 0

        def mock_fetch(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return {"url": "test", "status": 200, "headers": {}, "body": ""}

        probe._fetch = mock_fetch

        start = time.monotonic()
        probe.probe("https://example.com")
        probe.probe("https://example.com")
        elapsed = time.monotonic() - start

        # Should have been paced by min_interval (0.1s)
        assert elapsed >= 0.08  # Allow some slack
        assert call_count == 2


class TestRateLimitEdgeCases:
    """Edge case tests for rate limiting."""

    def test_very_high_rate_limit(self) -> None:
        """Very high rate limit should effectively be unlimited."""
        limiter = JobRateLimiter(10000)
        start = time.monotonic()
        for _ in range(100):
            limiter.pace()
        elapsed = time.monotonic() - start
        # Should complete very quickly
        assert elapsed < 0.1

    def test_fractional_rate_limit(self) -> None:
        """Fractional rate limits should work (e.g., 0.5 RPS = 1 request per 2s)."""
        limiter = JobRateLimiter(0.5)
        assert limiter.enabled is True
        assert limiter.rate_limit_rps == 0.5

    def test_rate_limit_result_retry_after_calculation(self) -> None:
        """retry_after should be correctly calculated."""
        bucket = TokenBucket(2)
        bucket.try_consume(2)  # Exhaust
        result = bucket.try_consume()
        assert result.allowed is False
        # Need 1 token at 2 RPS = 0.5s
        assert 0.4 < result.retry_after < 0.6

    def test_multiple_tokens_consumed_at_once(self) -> None:
        """Consuming multiple tokens at once should work."""
        bucket = TokenBucket(10)
        result = bucket.try_consume(5)
        assert result.allowed is True
        assert result.remaining == 5

        result = bucket.try_consume(6)  # Only 5 left
        assert result.allowed is False

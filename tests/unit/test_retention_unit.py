"""Tests for strix.retention module."""

from __future__ import annotations

import time
from unittest.mock import patch

from strix.retention import RetentionWorker, prune


class TestPruneFunction:
    """Test the prune function."""

    def test_prune_zero_days(self):
        """Test prune with zero or negative days returns empty counts."""
        result = prune(0)
        assert result == {"jobs": 0, "audit_entries": 0}

        result = prune(-1)
        assert result == {"jobs": 0, "audit_entries": 0}

    def test_prune_with_now_parameter(self):
        """Test prune with explicit now parameter."""
        # Use a fixed time to avoid flakiness
        fixed_now = 1700000000.0
        result = prune(1, now=fixed_now)
        # We can't easily assert counts without a DB, but verify it runs
        assert "jobs" in result
        assert "audit_entries" in result


class TestRetentionWorker:
    """Test RetentionWorker class."""

    def test_retention_worker_creation(self):
        """Test creating a RetentionWorker."""
        worker = RetentionWorker(days=30)
        assert worker.days == 30
        assert worker._thread is None

    def test_retention_worker_disabled(self):
        """Test worker with zero days doesn't start thread."""
        worker = RetentionWorker(days=0)
        worker.start()
        assert worker._thread is None

    def test_retention_worker_start_stop(self):
        """Test worker starts and stops a thread."""
        worker = RetentionWorker(days=1)
        worker.start()
        assert worker._thread is not None
        assert worker._thread.is_alive()
        worker.shutdown(timeout=1.0)
        assert worker._thread is None

    def test_retention_worker_double_start(self):
        """Test starting worker twice doesn't create two threads."""
        worker = RetentionWorker(days=1)
        worker.start()
        first_thread = worker._thread
        worker.start()
        assert worker._thread is first_thread
        worker.shutdown(timeout=1.0)

    @patch("strix.retention.store")
    @patch("strix.retention._prune_async")
    def test_retention_worker_loop(self, mock_prune_async, mock_store):
        """Test worker loop calls prune."""
        mock_prune_async.return_value = (5, 3)
        mock_store.vacuum = lambda: None
        mock_store._run_async = lambda x: x

        worker = RetentionWorker(days=1)
        worker.start()

        # Wait for one sweep cycle
        time.sleep(0.2)

        worker.shutdown(timeout=1.0)

        # Verify prune was called
        assert mock_prune_async.called

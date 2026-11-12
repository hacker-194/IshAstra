"""Regression test for missing HTTP timeout in adapters.

The bug: HTTP calls in adapters lack explicit timeout= on the client level.
A hung upstream server (accepts connection but never sends response) can stall
a worker thread indefinitely.

This test demonstrates the bug by spinning up a slow HTTP server that accepts
connections but never sends a response, then verifying the adapter call times out
properly. Currently this test FAILS (hangs), proving the bug exists.
"""
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from strix.core.adapters import HTTPAdapter


class SlowNeverRespondsHandler(BaseHTTPRequestHandler):
    """HTTP handler that accepts connection but never sends a response.

    This simulates a hung upstream server (slowloris-style attack or just
    a misbehaving server that accepts the TCP connection but never writes
    the HTTP response headers/body).
    """

    def do_GET(self):
        # Accept the connection but never send a response.
        # The client will wait forever for headers that never arrive.
        # We don't call send_response(), send_header(), end_headers(), or wfile.write()
        # This mimics a server that accepts the TCP connection then hangs.
        time.sleep(3600)  # Sleep for a very long time (test will timeout first)

    def log_message(self, *args):
        pass


def test_http_adapter_times_out_on_hung_server():
    """Test that HTTPAdapter times out when server accepts but never responds.

    This test demonstrates the missing timeout bug. Currently it FAILS because
    the probe hangs indefinitely waiting for a response that never comes.
    """
    # Start a slow server that never responds
    server = HTTPServer(("127.0.0.1", 0), SlowNeverRespondsHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        target_url = f"http://127.0.0.1:{server.server_port}/test"
        adapter = HTTPAdapter()
        cancel_event = threading.Event()

        # This should timeout within a few seconds, but currently hangs
        # because the probe doesn't have a proper read timeout on the response
        start = time.monotonic()
        try:
            result = adapter.assess(target_url, timeout=3.0, cancel=cancel_event)
            elapsed = time.monotonic() - start

            # If we get here, the call completed (either success or error)
            # It should have timed out within ~3 seconds
            assert elapsed < 5.0, f"Call took {elapsed:.1f}s, should have timed out within 3s"

            # Should have an error/timeout finding, not a clean result
            # The probe should return an error status, not hang
            assert any("timeout" in note.lower() or "error" in note.lower()
                       for note in result.notes), f"Expected timeout/error in notes: {result.notes}"

        except Exception as exc:
            elapsed = time.monotonic() - start
            # If an exception is raised, it should be a timeout error
            assert elapsed < 5.0, f"Exception took {elapsed:.1f}s, should have timed out within 3s"
            assert "timeout" in str(exc).lower() or "timed out" in str(exc).lower(), \
                f"Expected timeout error, got: {exc}"

    finally:
        # Close the server socket to unblock serve_forever
        # The request handler thread is a daemon and will be terminated on exit
        # Don't call server.shutdown() as it waits for the handler to finish
        server.socket.close()
        server.server_close()


def test_endpoint_probe_times_out_on_hung_server():
    """Test that EndpointProbe directly times out on a hung server.

    This is a more granular test targeting the probe directly.
    """
    from strix.core.probe import EndpointProbe

    # Start a slow server that never responds
    server = HTTPServer(("127.0.0.1", 0), SlowNeverRespondsHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        target_url = f"http://127.0.0.1:{server.server_port}/test"
        probe = EndpointProbe(timeout=2.0)
        deadline = time.monotonic() + 3.0  # 3 second overall deadline

        # This should timeout within the probe's timeout
        start = time.monotonic()
        result = probe.probe(target_url, deadline=deadline)
        elapsed = time.monotonic() - start

        # Should complete quickly with an error, not hang
        assert elapsed < 4.0, f"Probe took {elapsed:.1f}s, should have timed out within 2-3s"

        # Result should indicate error/timeout, not a successful response
        assert result.get("status") in ("error", "timeout", "blocked"), \
            f"Expected error/timeout status, got: {result.get('status')}"
        assert "error" in result or "timeout" in str(result.get("error", "")).lower(), \
            f"Expected error in result: {result}"

    finally:
        # Close the server socket to unblock serve_forever
        # The request handler thread is a daemon and will be terminated on exit
        server.socket.close()
        server.server_close()


def test_http_adapter_respects_deadline_on_slow_response():
    """Test that HTTPAdapter respects the overall deadline even with slow response.

    This tests the scenario where the server sends headers very slowly
    (e.g., one byte per second) - the deadline should still be enforced.
    """

    class SlowDripHandler(BaseHTTPRequestHandler):
        """Sends response headers extremely slowly (one byte at a time)."""

        def do_GET(self):
            self.send_response(200)
            # Send headers one byte at a time with delays
            header = "Content-Type: text/html\r\n"
            for byte in header.encode():
                self.wfile.write(bytes([byte]))
                self.wfile.flush()
                time.sleep(0.5)  # Very slow drip
            self.end_headers()
            # Send body slowly too
            body = b"Hello"
            for byte in body:
                self.wfile.write(bytes([byte]))
                self.wfile.flush()
                time.sleep(0.5)
            # Never close - keep connection open

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), SlowDripHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        target_url = f"http://127.0.0.1:{server.server_port}/test"
        adapter = HTTPAdapter()
        cancel_event = threading.Event()

        # Use a short timeout - should be enforced even with slow drip
        start = time.monotonic()
        try:
            adapter.assess(target_url, timeout=2.0, cancel=cancel_event)
            elapsed = time.monotonic() - start

            # Should timeout within ~2 seconds
            assert elapsed < 4.0, f"Call took {elapsed:.1f}s, should respect 2s deadline"

        except Exception:
            elapsed = time.monotonic() - start
            assert elapsed < 4.0, f"Exception took {elapsed:.1f}s, should respect 2s deadline"

    finally:
        # Close the server socket to unblock serve_forever
        # The request handler thread is a daemon and will be terminated on exit
        server.socket.close()
        server.server_close()


if __name__ == "__main__":
    # Allow running directly for debugging
    pytest.main([__file__, "-v", "-x"])

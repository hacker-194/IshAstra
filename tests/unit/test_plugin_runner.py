"""Tests for ishastra.core.plugin_runner - out-of-process plugin runner."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from ishastra.core.adapter_base import AdapterCancelled, AdapterError, AdapterNotApplicable, AdapterTimeout
from ishastra.core.plugin_runner import (
    AdapterPlugin,
    PluginProcess,
    PluginProtocolError,
    PluginRunner,
    PluginTimeout,
    run_plugin_assessment,
)


class TestPluginProtocol:
    """Tests for the JSON plugin protocol."""

    def test_plugin_request_serialization(self):
        """Test PluginRequest serializes correctly."""
        from ishastra.core.plugin_runner import PluginRequest

        req = PluginRequest(method="info", params={}, request_id=1)
        json_str = req.to_json()
        data = json.loads(json_str)
        assert data["protocol"] == 1
        assert data["method"] == "info"
        assert data["params"] == {}
        assert data["id"] == 1

    def test_plugin_response_deserialization(self):
        """Test PluginResponse deserializes correctly."""
        from ishastra.core.plugin_runner import PluginResponse

        line = '{"result": {"available": true}, "id": 1}'
        resp = PluginResponse.from_json(line)
        assert resp.result == {"available": True}
        assert resp.request_id == 1
        assert not resp.is_error()

    def test_plugin_response_error(self):
        """Test PluginResponse error handling."""
        from ishastra.core.plugin_runner import PluginResponse

        line = '{"error": {"code": "NOT_FOUND", "message": "Adapter not found"}, "id": 1}'
        resp = PluginResponse.from_json(line)
        assert resp.is_error()
        code, msg = resp.get_error()
        assert code == "NOT_FOUND"
        assert msg == "Adapter not found"


class TestPluginProcess:
    """Tests for PluginProcess management."""

    def test_plugin_process_start_stop(self):
        """Test starting and stopping a plugin process."""
        # Use a simple echo script as a mock plugin
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys, json
# Handshake
print(json.dumps({"result": {"protocol": 1, "adapter": "test"}}), flush=True)
# Loop
for line in sys.stdin:
    req = json.loads(line)
    if req.get("method") == "shutdown":
        print(json.dumps({"id": req.get("id"), "result": {"status": "ok"}}), flush=True)
        break
    print(json.dumps({"id": req.get("id"), "result": {"ok": True}}), flush=True)
""")
            script_path = f.name

        os.chmod(script_path, 0o755)

        try:
            process = PluginProcess(command=[sys.executable, script_path])
            process.start()

            # Call info
            result = process.call("info", {}, timeout=5.0)
            assert result == {"ok": True}

            # Shutdown
            process.close()
        finally:
            os.unlink(script_path)

    def test_plugin_process_timeout(self):
        """Test plugin process call timeout."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys, json, time
# Handshake
print(json.dumps({"result": {"protocol": 1, "adapter": "test"}}), flush=True)
# Loop - never responds to assess
for line in sys.stdin:
    req = json.loads(line)
    if req.get("method") == "shutdown":
        print(json.dumps({"id": req.get("id"), "result": {"status": "ok"}}), flush=True)
        break
    # Don't respond to assess - causes timeout
    time.sleep(10)
""")
            script_path = f.name

        os.chmod(script_path, 0o755)

        try:
            process = PluginProcess(command=[sys.executable, script_path])
            process.start()

            # Call assess with short timeout - should timeout
            with pytest.raises(PluginTimeout):
                process.call("assess", {}, timeout=0.5)

            process.close()
        finally:
            os.unlink(script_path)

    def test_plugin_process_handshake_failure(self):
        """Test plugin process handles handshake failure."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys
# Send invalid handshake
print("not json", flush=True)
""")
            script_path = f.name

        os.chmod(script_path, 0o755)

        try:
            process = PluginProcess(command=[sys.executable, script_path])
            with pytest.raises(PluginProtocolError, match="Invalid handshake JSON"):
                process.start()
        finally:
            os.unlink(script_path)

    def test_plugin_process_protocol_version_mismatch(self):
        """Test plugin process detects protocol version mismatch."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys, json
# Handshake with wrong protocol version
print(json.dumps({"result": {"protocol": 999, "adapter": "test"}}), flush=True)
""")
            script_path = f.name

        os.chmod(script_path, 0o755)

        try:
            process = PluginProcess(command=[sys.executable, script_path])
            with pytest.raises(PluginProtocolError, match="Protocol version mismatch"):
                process.start()
        finally:
            os.unlink(script_path)


class TestPluginRunner:
    """Tests for PluginRunner high-level interface."""

    def test_runner_start_and_info(self):
        """Test PluginRunner starts plugin and gets info."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys, json, threading

cancel = threading.Event()

# Handshake
print(json.dumps({"result": {"protocol": 1, "adapter": "test-adapter"}}), flush=True)

for line in sys.stdin:
    req = json.loads(line)
    method = req.get("method")
    rid = req.get("id")
    if method == "info":
        print(json.dumps({"id": rid, "result": {
            "id": "test-adapter",
            "version": "1.0",
            "asset_types": ["web"],
            "requires": [],
            "available": True,
            "detail": "test adapter",
            "contract": {
                "id": "test-adapter",
                "version": "1.0",
                "asset_types": ["web"],
                "protocols": ["tcp"],
                "scan_modes": ["connect"],
                "enforcement": "none",
                "timeout": 30,
                "requires": []
            }
        }}), flush=True)
    elif method == "assess":
        print(json.dumps({"id": rid, "result": {
            "findings": [],
            "notes": ["test assessment completed"],
            "partial": False
        }}), flush=True)
    elif method == "shutdown":
        print(json.dumps({"id": rid, "result": {"status": "ok"}}), flush=True)
        break
""")
            script_path = f.name

        os.chmod(script_path, 0o755)

        try:
            runner = PluginRunner(script_path, timeout=10.0)
            info = runner.start()

            assert info["id"] == "test-adapter"
            assert info["version"] == "1.0"
            assert info["available"] is True

            # Test assess
            result = runner.assess("http://example.com/", context={})
            assert result.notes == ["test assessment completed"]
            assert result.partial is False

            runner.close()
        finally:
            os.unlink(script_path)

    def test_runner_assess_timeout(self):
        """Test PluginRunner assess timeout."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys, json, time, threading

cancel = threading.Event()

# Handshake
print(json.dumps({"result": {"protocol": 1, "adapter": "slow-adapter"}}), flush=True)

for line in sys.stdin:
    req = json.loads(line)
    method = req.get("method")
    rid = req.get("id")
    if method == "info":
        print(json.dumps({"id": rid, "result": {
            "id": "slow-adapter",
            "version": "1.0",
            "asset_types": ["web"],
            "requires": [],
            "available": True,
            "detail": "slow adapter",
            "contract": {
                "id": "slow-adapter",
                "version": "1.0",
                "asset_types": ["web"],
                "protocols": ["tcp"],
                "scan_modes": ["connect"],
                "enforcement": "none",
                "timeout": 30,
                "requires": []
            }
        }}), flush=True)
    elif method == "assess":
        # Sleep longer than timeout (runner timeout is 0.5 + 5 = 5.5, so sleep 10)
        time.sleep(10)
        print(json.dumps({"id": rid, "result": {"findings": [], "notes": [], "partial": False}}), flush=True)
    elif method == "shutdown":
        print(json.dumps({"id": rid, "result": {"status": "ok"}}), flush=True)
        break
""")
            script_path = f.name

        os.chmod(script_path, 0o755)

        try:
            runner = PluginRunner(script_path, timeout=0.5)
            runner.start()

            with pytest.raises(AdapterTimeout):
                runner.assess("http://example.com/", context={})

            runner.close()
        finally:
            os.unlink(script_path)

    def test_runner_cancel(self):
        """Test PluginRunner respects cancellation."""
        cancel_event = threading.Event()
        cancel_event.set()  # Pre-cancelled

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys, json
print(json.dumps({"result": {"protocol": 1, "adapter": "test"}}), flush=True)
for line in sys.stdin:
    req = json.loads(line)
    print(json.dumps({"id": req.get("id"), "result": {"ok": True}}), flush=True)
""")
            script_path = f.name

        os.chmod(script_path, 0o755)

        try:
            runner = PluginRunner(script_path, timeout=10.0, cancel=cancel_event)
            with pytest.raises(AdapterCancelled):
                runner.start()
        finally:
            os.unlink(script_path)


class TestAdapterPlugin:
    """Tests for AdapterPlugin wrapper."""

    def test_adapter_plugin_wraps_external_plugin(self):
        """Test AdapterPlugin wraps external plugin as Adapter."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys, json, threading

# Handshake
print(json.dumps({"result": {"protocol": 1, "adapter": "wrapped-adapter"}}), flush=True)

for line in sys.stdin:
    req = json.loads(line)
    method = req.get("method")
    rid = req.get("id")
    if method == "info":
        print(json.dumps({"id": rid, "result": {
            "id": "wrapped-adapter",
            "version": "2.0",
            "asset_types": ["network"],
            "requires": ["netcat"],
            "available": True,
            "detail": "wrapped external adapter",
            "contract": {
                "id": "wrapped-adapter",
                "version": "2.0",
                "asset_types": ["network"],
                "protocols": ["tcp"],
                "scan_modes": ["connect"],
                "enforcement": "none",
                "timeout": 60,
                "requires": ["netcat"]
            }
        }}), flush=True)
    elif method == "assess":
        print(json.dumps({"id": rid, "result": {
            "findings": [],
            "notes": ["wrapped assessment done"],
            "partial": False
        }}), flush=True)
    elif method == "shutdown":
        print(json.dumps({"id": rid, "result": {"status": "ok"}}), flush=True)
        break
""")
            script_path = f.name

        os.chmod(script_path, 0o755)

        try:
            adapter = AdapterPlugin(script_path, timeout=10.0)

            # Check metadata populated from plugin - need to call available() first
            ok, detail = adapter.available()
            assert ok is True

            assert adapter.id == "wrapped-adapter"
            assert adapter.version == "2.0"
            assert adapter.asset_types == ("network",)
            assert adapter.requires == ("netcat",)

            # Check assess
            cancel = threading.Event()
            result = adapter.assess("http://example.com/", timeout=10.0, cancel=cancel, context={})
            assert result.notes == ["wrapped assessment done"]

            adapter.close()
        finally:
            os.unlink(script_path)

    def test_adapter_plugin_contract(self):
        """Test AdapterPlugin contract() returns plugin contract."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys, json
print(json.dumps({"result": {"protocol": 1, "adapter": "contract-test"}}), flush=True)
for line in sys.stdin:
    req = json.loads(line)
    if req.get("method") == "info":
        print(json.dumps({"id": req.get("id"), "result": {
            "id": "contract-test",
            "version": "1.0",
            "asset_types": ["web"],
            "requires": [],
            "available": True,
            "detail": "test",
            "contract": {
                "id": "contract-test",
                "version": "1.0",
                "asset_types": ["web"],
                "protocols": ["tcp"],
                "scan_modes": ["connect"],
                "enforcement": "proxy",
                "timeout": 120,
                "requires": []
            }
        }}), flush=True)
    elif req.get("method") == "shutdown":
        print(json.dumps({"id": req.get("id"), "result": {"status": "ok"}}), flush=True)
        break
""")
            script_path = f.name

        os.chmod(script_path, 0o755)

        try:
            adapter = AdapterPlugin(script_path, timeout=10.0)
            adapter.start()  # This calls _get_runner() which starts the plugin

            contract = adapter.contract()
            assert contract["enforcement"] == "proxy"
            assert contract["timeout"] == 120

            adapter.close()
        finally:
            os.unlink(script_path)


class TestRunPluginAssessment:
    """Tests for run_plugin_assessment convenience function."""

    def test_run_plugin_assessment_function(self):
        """Test run_plugin_assessment runs and returns result."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys, json
print(json.dumps({"result": {"protocol": 1, "adapter": "func-test"}}), flush=True)
for line in sys.stdin:
    req = json.loads(line)
    if req.get("method") == "info":
        print(json.dumps({"id": req.get("id"), "result": {
            "id": "func-test",
            "version": "1.0",
            "asset_types": ["web"],
            "requires": [],
            "available": True,
            "detail": "function test adapter",
            "contract": {
                "id": "func-test",
                "version": "1.0",
                "asset_types": ["web"],
                "protocols": ["tcp"],
                "scan_modes": ["connect"],
                "enforcement": "none",
                "timeout": 30,
                "requires": []
            }
        }}), flush=True)
    elif req.get("method") == "assess":
        print(json.dumps({"id": req.get("id"), "result": {
            "findings": [],
            "notes": ["function test completed"],
            "partial": False
        }}), flush=True)
    elif req.get("method") == "shutdown":
        print(json.dumps({"id": req.get("id"), "result": {"status": "ok"}}), flush=True)
        break
""")
            script_path = f.name

        os.chmod(script_path, 0o755)

        try:
            result, findings = run_plugin_assessment(
                script_path,
                "http://example.com/",
                timeout=10.0,
                context={},
            )
            assert result.notes == ["function test completed"]
            assert findings == []
        finally:
            os.unlink(script_path)


class TestTCPScannerPlugin:
    """Integration test with the built-in tcp_port_scanner plugin."""

    def test_tcp_scanner_plugin_exists(self):
        """Test the example plugin exists and is executable."""
        plugin_path = (
            Path(__file__).parent.parent.parent / "src" / "ishastra" / "plugins" / "tcp_port_scanner.py"
        )
        assert plugin_path.exists(), f"Plugin not found at {plugin_path}"
        assert os.access(plugin_path, os.X_OK), "Plugin not executable"

    def test_tcp_scanner_plugin_requires_gateway_fail_closed(self):
        """Test TCP scanner plugin fails closed when no gateway URL provided."""
        plugin_path = (
            Path(__file__).parent.parent.parent / "src" / "ishastra" / "plugins" / "tcp_port_scanner.py"
        )

        proc = subprocess.Popen(
            [sys.executable, str(plugin_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            # Read handshake
            handshake_line = proc.stdout.readline()
            assert handshake_line, "No handshake received"
            handshake = json.loads(handshake_line)
            assert handshake["result"]["adapter"] == "tcp-port-scanner"

            # Send assess request WITHOUT gateway_url in context - should fail
            assess_req = (
                json.dumps(
                    {
                        "protocol": 1,
                        "method": "assess",
                        "params": {
                            "target": "http://127.0.0.1/",
                            "timeout": 5.0,
                            "context": {"ports": [22, 80, 443]},  # No gateway_url
                        },
                        "id": 1,
                    }
                )
                + "\n"
            )
            proc.stdin.write(assess_req)
            proc.stdin.flush()

            # Read response - should be an error (fail-closed)
            response_line = proc.stdout.readline()
            assert response_line, "No assess response"
            response = json.loads(response_line)
            assert response["id"] == 1
            assert "error" in response, "Expected error for missing gateway_url"
            error = response["error"]
            assert error["code"] == "INTERNAL_ERROR"
            assert "egress gateway required" in error["message"].lower()

            # Shutdown
            shutdown_req = json.dumps({"protocol": 1, "method": "shutdown", "params": {}, "id": 2}) + "\n"
            proc.stdin.write(shutdown_req)
            proc.stdin.flush()

            proc.wait(timeout=5)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=2)

    def test_tcp_scanner_plugin_handshake(self):
        """Test TCP scanner plugin handshake works."""
        plugin_path = (
            Path(__file__).parent.parent.parent / "src" / "ishastra" / "plugins" / "tcp_port_scanner.py"
        )

        # Run plugin and send handshake + info request
        proc = subprocess.Popen(
            [sys.executable, str(plugin_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            # Read handshake
            handshake_line = proc.stdout.readline()
            assert handshake_line, "No handshake received"
            handshake = json.loads(handshake_line)
            assert handshake["result"]["protocol"] == 1
            assert handshake["result"]["adapter"] == "tcp-port-scanner"

            # Send info request
            info_req = json.dumps({"protocol": 1, "method": "info", "params": {}, "id": 1}) + "\n"
            proc.stdin.write(info_req)
            proc.stdin.flush()

            # Read response
            response_line = proc.stdout.readline()
            assert response_line, "No info response"
            response = json.loads(response_line)
            assert response["id"] == 1
            assert response["result"]["id"] == "tcp-port-scanner"
            assert response["result"]["version"] == "1.0.0"

            # Shutdown
            shutdown_req = json.dumps({"protocol": 1, "method": "shutdown", "params": {}, "id": 2}) + "\n"
            proc.stdin.write(shutdown_req)
            proc.stdin.flush()

            proc.wait(timeout=5)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=2)

    def test_tcp_scanner_plugin_assess(self):
        """Test TCP scanner plugin assess method."""
        plugin_path = (
            Path(__file__).parent.parent.parent / "src" / "ishastra" / "plugins" / "tcp_port_scanner.py"
        )

        proc = subprocess.Popen(
            [sys.executable, str(plugin_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            # Read handshake
            handshake_line = proc.stdout.readline()
            handshake = json.loads(handshake_line)
            assert handshake["result"]["adapter"] == "tcp-port-scanner"

            # Send assess request - scan localhost on a few ports (with gateway for fail-closed)
            assess_req = (
                json.dumps(
                    {
                        "protocol": 1,
                        "method": "assess",
                        "params": {
                            "target": "http://127.0.0.1/",
                            "timeout": 5.0,
                            "context": {"ports": [22, 80, 443], "gateway_url": "http://gateway:8080"},
                        },
                        "id": 1,
                    }
                )
                + "\n"
            )
            proc.stdin.write(assess_req)
            proc.stdin.flush()

            # Read response (with timeout)
            response_line = proc.stdout.readline()
            assert response_line, "No assess response"
            response = json.loads(response_line)
            assert response["id"] == 1
            assert "result" in response
            result = response["result"]
            assert "findings" in result
            assert "notes" in result
            assert "partial" in result

            # Shutdown
            shutdown_req = json.dumps({"protocol": 1, "method": "shutdown", "params": {}, "id": 2}) + "\n"
            proc.stdin.write(shutdown_req)
            proc.stdin.flush()

            proc.wait(timeout=5)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=2)


class TestPluginRunnerCleanup:
    """Tests for plugin runner cleanup."""

    def test_runner_close_idempotent(self):
        """Test PluginRunner.close() is idempotent."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys, json
print(json.dumps({"result": {"protocol": 1, "adapter": "test"}}), flush=True)
for line in sys.stdin:
    req = json.loads(line)
    if req.get("method") == "info":
        print(json.dumps({"id": req.get("id"), "result": {
            "id": "test", "version": "1.0", "asset_types": ["web"],
            "requires": [], "available": True, "detail": "test",
            "contract": {"id": "test", "version": "1.0", "asset_types": ["web"],
            "protocols": ["tcp"], "scan_modes": ["connect"], "enforcement": "none",
            "timeout": 30, "requires": []}
        }}), flush=True)
    elif req.get("method") == "shutdown":
        print(json.dumps({"id": req.get("id"), "result": {"status": "ok"}}), flush=True)
        break
""")
            script_path = f.name

        os.chmod(script_path, 0o755)

        try:
            runner = PluginRunner(script_path, timeout=10.0)
            runner.start()
            runner.close()
            runner.close()  # Second close should not error
        finally:
            os.unlink(script_path)

    def test_adapter_plugin_close_idempotent(self):
        """Test AdapterPlugin.close() is idempotent."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys, json
print(json.dumps({"result": {"protocol": 1, "adapter": "test"}}), flush=True)
for line in sys.stdin:
    req = json.loads(line)
    if req.get("method") == "info":
        print(json.dumps({"id": req.get("id"), "result": {
            "id": "test", "version": "1.0", "asset_types": ["web"],
            "requires": [], "available": True, "detail": "test",
            "contract": {"id": "test", "version": "1.0", "asset_types": ["web"],
            "protocols": ["tcp"], "scan_modes": ["connect"], "enforcement": "none",
            "timeout": 30, "requires": []}
        }}), flush=True)
    elif req.get("method") == "shutdown":
        print(json.dumps({"id": req.get("id"), "result": {"status": "ok"}}), flush=True)
        break
""")
            script_path = f.name

        os.chmod(script_path, 0o755)

        try:
            adapter = AdapterPlugin(script_path, timeout=10.0)
            adapter.start()
            adapter.close()
            adapter.close()  # Second close should not error
        finally:
            os.unlink(script_path)


class TestPluginErrorHandling:
    """Tests for plugin error handling."""

    def test_plugin_not_applicable_error(self):
        """Test PluginNotApplicable error propagation."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys, json
print(json.dumps({"result": {"protocol": 1, "adapter": "test"}}), flush=True)
for line in sys.stdin:
    req = json.loads(line)
    if req.get("method") == "info":
        print(json.dumps({"id": req.get("id"), "result": {
            "id": "test", "version": "1.0", "asset_types": ["web"],
            "requires": [], "available": True, "detail": "test",
            "contract": {"id": "test", "version": "1.0", "asset_types": ["web"],
            "protocols": ["tcp"], "scan_modes": ["connect"], "enforcement": "none",
            "timeout": 30, "requires": []}
        }}), flush=True)
    elif req.get("method") == "assess":
        print(json.dumps({"id": req.get("id"), "error": {
            "code": "NOT_APPLICABLE", "message": "No ports to scan"
        }}), flush=True)
    elif req.get("method") == "shutdown":
        print(json.dumps({"id": req.get("id"), "result": {"status": "ok"}}), flush=True)
        break
""")
            script_path = f.name

        os.chmod(script_path, 0o755)

        try:
            runner = PluginRunner(script_path, timeout=10.0)
            runner.start()

            with pytest.raises(AdapterNotApplicable, match="No ports to scan"):
                runner.assess("http://example.com/", context={})

            runner.close()
        finally:
            os.unlink(script_path)

    def test_plugin_generic_error(self):
        """Test generic plugin error propagation."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""#!/usr/bin/env python3
import sys, json
print(json.dumps({"result": {"protocol": 1, "adapter": "test"}}), flush=True)
for line in sys.stdin:
    req = json.loads(line)
    if req.get("method") == "info":
        print(json.dumps({"id": req.get("id"), "result": {
            "id": "test", "version": "1.0", "asset_types": ["web"],
            "requires": [], "available": True, "detail": "test",
            "contract": {"id": "test", "version": "1.0", "asset_types": ["web"],
            "protocols": ["tcp"], "scan_modes": ["connect"], "enforcement": "none",
            "timeout": 30, "requires": []}
        }}), flush=True)
    elif req.get("method") == "assess":
        print(json.dumps({"id": req.get("id"), "error": {
            "code": "INTERNAL_ERROR", "message": "Something went wrong"
        }}), flush=True)
    elif req.get("method") == "shutdown":
        print(json.dumps({"id": req.get("id"), "result": {"status": "ok"}}), flush=True)
        break
""")
            script_path = f.name

        os.chmod(script_path, 0o755)

        try:
            runner = PluginRunner(script_path, timeout=10.0)
            runner.start()

            with pytest.raises(AdapterError, match="Something went wrong"):
                runner.assess("http://example.com/", context={})

            runner.close()
        finally:
            os.unlink(script_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

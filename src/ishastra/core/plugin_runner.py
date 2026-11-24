"""Out-of-process plugin runner for adapter execution.

Adapters run as subprocesses communicating via stdin/stdout JSON protocol.
Provides timeout, resource limits, and cleanup guarantees.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ishastra.core.adapter_base import (
    Adapter,
    AdapterCancelled,
    AdapterError,
    AdapterNotApplicable,
    AdapterResult,
    AdapterTimeout,
)

log = logging.getLogger(__name__)


PLUGIN_PROTOCOL_VERSION = 1
DEFAULT_PLUGIN_TIMEOUT = 300.0
MAX_OUTPUT_BYTES = 16 * 1024 * 1024


class PluginError(AdapterError):
    """Plugin execution error."""


class PluginTimeout(AdapterTimeout):
    """Plugin timed out."""


class PluginCancelled(AdapterCancelled):
    """Plugin was cancelled."""


class PluginNotApplicable(AdapterNotApplicable):
    """Plugin not applicable to target."""


class PluginProtocolError(PluginError):
    """Plugin protocol violation."""


@dataclass
class PluginRequest:
    """Request sent to plugin process."""

    method: str
    params: dict[str, Any]
    request_id: int = 0

    def to_json(self) -> str:
        return json.dumps(
            {
                "protocol": PLUGIN_PROTOCOL_VERSION,
                "method": self.method,
                "params": self.params,
                "id": self.request_id,
            },
            separators=(",", ":"),
        )


@dataclass
class PluginResponse:
    """Response received from plugin process."""

    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    request_id: int = 0

    @classmethod
    def from_json(cls, line: str) -> PluginResponse:
        data = json.loads(line)
        return cls(
            result=data.get("result"),
            error=data.get("error"),
            request_id=data.get("id", 0),
        )

    def is_error(self) -> bool:
        return self.error is not None

    def get_error(self) -> tuple[str, str]:
        """Return (code, message) from error."""
        if self.error:
            return self.error.get("code", "UNKNOWN"), self.error.get("message", "Unknown error")
        return "UNKNOWN", "No error"


class PluginProcess:
    """Manages a single plugin subprocess."""

    def __init__(
        self,
        command: list[str],
        env: dict[str, str] | None = None,
        cwd: str | Path | None = None,
    ):
        self.command = command
        self.env = env or os.environ.copy()
        self.cwd = cwd
        self.process: subprocess.Popen | None = None
        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._stdout_buffer: list[str] = []
        self._stderr_buffer: list[str] = []
        self._stdout_lock = threading.Lock()
        self._stderr_lock = threading.Lock()
        self._closed = False
        self._request_id = 0

    def start(self) -> None:
        """Start the plugin process."""
        if self.process is not None:
            return

        # Sanitize environment
        clean_env = {
            "PATH": self.env.get("PATH", os.environ.get("PATH", "")),
            "HOME": self.env.get("HOME", os.environ.get("HOME", "")),
            "TMPDIR": self.env.get("TMPDIR", "/tmp"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        # Pass through ISHASTRA_* vars
        for k, v in self.env.items():
            if k.startswith("ISHASTRA_"):
                clean_env[k] = v

        self.process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=clean_env,
            cwd=self.cwd,
            text=True,
            bufsize=1,  # Line buffered
        )

        # Start stdout/stderr drain threads
        self._stdout_thread = threading.Thread(target=self._drain_stdout, daemon=True)
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()

        # Handshake
        self._handshake()

    def _handshake(self) -> None:
        """Perform protocol handshake with plugin."""
        if not self.process or not self.process.stdout:
            raise PluginError("Process not started")

        # Read handshake line
        line = self._read_line(self.process.stdout, timeout=5.0)
        if not line:
            raise PluginError("Plugin handshake failed: no response")

        try:
            response = PluginResponse.from_json(line)
        except json.JSONDecodeError as e:
            raise PluginProtocolError(f"Invalid handshake JSON: {e}") from e

        if response.is_error():
            code, msg = response.get_error()
            raise PluginError(f"Plugin handshake error [{code}]: {msg}")

        if response.result is None:
            raise PluginError("Plugin handshake missing result")

        protocol_version = response.result.get("protocol")
        if protocol_version != PLUGIN_PROTOCOL_VERSION:
            raise PluginProtocolError(
                f"Protocol version mismatch: expected {PLUGIN_PROTOCOL_VERSION}, got {protocol_version}"
            )

    def _drain_stdout(self) -> None:
        """Drain stdout to buffer."""
        if not self.process or not self.process.stdout:
            return
        for line in self.process.stdout:
            with self._stdout_lock:
                if len(self._stdout_buffer) < 1000:  # Prevent memory exhaustion
                    self._stdout_buffer.append(line.rstrip("\n"))

    def _drain_stderr(self) -> None:
        """Drain stderr to buffer."""
        if not self.process or not self.process.stderr:
            return
        for line in self.process.stderr:
            with self._stderr_lock:
                if len(self._stderr_buffer) < 1000:
                    self._stderr_buffer.append(line.rstrip("\n"))

    def _read_line(self, stream, timeout: float) -> str | None:
        """Read a line from stream with timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._stdout_lock:
                if self._stdout_buffer:
                    return self._stdout_buffer.pop(0)
            time.sleep(0.01)
        return None

    def call(self, method: str, params: dict[str, Any], timeout: float) -> dict[str, Any]:
        """Call a method on the plugin and return result."""
        if self._closed:
            raise PluginError("Plugin process already closed")
        if not self.process or not self.process.stdin:
            raise PluginError("Plugin process not running")

        self._request_id += 1
        request = PluginRequest(method=method, params=params, request_id=self._request_id)
        request_json = request.to_json() + "\n"

        try:
            self.process.stdin.write(request_json)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise PluginError(f"Failed to write to plugin: {e}") from e

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._stdout_lock:
                if self._stdout_buffer:
                    line = self._stdout_buffer.pop(0)
                    try:
                        response = PluginResponse.from_json(line)
                    except json.JSONDecodeError:
                        continue  # Skip non-JSON lines

                    if response.request_id == self._request_id:
                        if response.is_error():
                            code, msg = response.get_error()
                            if code == "NOT_APPLICABLE":
                                raise PluginNotApplicable(msg)
                            raise PluginError(f"Plugin error [{code}]: {msg}")
                        return response.result or {}
            time.sleep(0.01)

        # Timeout
        self.close()
        raise PluginTimeout(f"Plugin call '{method}' timed out after {timeout}s")

    def close(self) -> None:
        """Close the plugin process."""
        if self._closed:
            return
        self._closed = True

        if self.process:
            # Try graceful shutdown first
            if self.process.stdin:
                try:
                    self.process.stdin.write('{"method":"shutdown","params":{},"id":0}\n')
                    self.process.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass

            # Wait briefly for graceful exit
            try:
                self.process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                # Force kill
                try:
                    self.process.terminate()
                    self.process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    try:
                        self.process.kill()
                        self.process.wait(timeout=1.0)
                    except Exception:
                        pass
                except Exception:
                    pass
            except Exception:
                pass

            self.process = None


class PluginRunner:
    """Runs adapters as out-of-process plugins."""

    def __init__(
        self,
        plugin_path: str | Path,
        timeout: float = DEFAULT_PLUGIN_TIMEOUT,
        cancel: threading.Event | None = None,
    ):
        self.plugin_path = Path(plugin_path)
        self.timeout = timeout
        self.cancel = cancel or threading.Event()
        self._process: PluginProcess | None = None
        self._adapter_info: dict[str, Any] | None = None

    def _check_cancel(self) -> None:
        if self.cancel.is_set():
            raise PluginCancelled("Plugin runner cancelled")

    def start(self) -> dict[str, Any]:
        """Start the plugin and return adapter info."""
        self._check_cancel()

        if not self.plugin_path.exists():
            raise PluginError(f"Plugin not found: {self.plugin_path}")

        # Make executable if needed
        if not os.access(self.plugin_path, os.X_OK):
            os.chmod(self.plugin_path, 0o755)

        self._process = PluginProcess(command=[str(self.plugin_path)])
        self._process.start()

        # Get adapter info
        self._adapter_info = self._process.call("info", {}, timeout=10.0)
        return self._adapter_info

    def available(self) -> tuple[bool, str]:
        """Check if plugin is available."""
        if self._adapter_info is None:
            try:
                self.start()
            except Exception as e:
                return False, str(e)
        if self._adapter_info is None:
            return False, "plugin did not report adapter info"
        return self._adapter_info.get("available", False), self._adapter_info.get("detail", "")

    def assess(
        self,
        target: str,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        """Run assessment via plugin."""
        self._check_cancel()

        if self._process is None:
            self.start()
        assert self._process is not None

        params = {
            "target": target,
            "context": context or {},
            "timeout": self.timeout,
        }

        # Use the provided timeout for the assess call, with a small buffer for protocol overhead
        assess_timeout = self.timeout + 5.0

        try:
            result = self._process.call("assess", params, timeout=assess_timeout)
        except PluginNotApplicable as e:
            raise AdapterNotApplicable(str(e)) from e
        except PluginTimeout as e:
            raise AdapterTimeout(str(e)) from e
        except PluginCancelled as e:
            raise AdapterCancelled(str(e)) from e
        except PluginError as e:
            raise AdapterError(str(e)) from e

        # Findings stay serialized in result["findings"]; the caller handles
        # them via assess_with_findings() rather than AdapterResult.findings.
        return AdapterResult(
            findings=[],  # Findings are serialized separately in result["findings"]
            notes=result.get("notes", []),
            partial=result.get("partial", False),
        )

    def assess_with_findings(
        self,
        target: str,
        context: dict[str, Any] | None = None,
    ) -> tuple[AdapterResult, list[dict[str, Any]]]:
        """Run assessment and return both result and raw findings."""
        self._check_cancel()

        if self._process is None:
            self.start()
        assert self._process is not None

        params = {
            "target": target,
            "context": context or {},
            "timeout": self.timeout,
        }

        assess_timeout = self.timeout + 5.0

        try:
            result = self._process.call("assess", params, timeout=assess_timeout)
        except PluginNotApplicable as e:
            raise AdapterNotApplicable(str(e)) from e
        except PluginTimeout as e:
            raise AdapterTimeout(str(e)) from e
        except PluginCancelled as e:
            raise AdapterCancelled(str(e)) from e
        except PluginError as e:
            raise AdapterError(str(e)) from e

        adapter_result = AdapterResult(
            findings=[],
            notes=result.get("notes", []),
            partial=result.get("partial", False),
        )
        findings = result.get("findings", [])
        return adapter_result, findings

    def get_findings(self) -> list[dict[str, Any]]:
        """Get findings from last assess call (if any)."""
        # Findings are returned in the assess result
        return []

    def close(self) -> None:
        """Close the plugin process."""
        if self._process:
            self._process.close()
            self._process = None


def run_plugin_assessment(
    plugin_path: str | Path,
    target: str,
    *,
    timeout: float = DEFAULT_PLUGIN_TIMEOUT,
    cancel: threading.Event | None = None,
    context: dict[str, Any] | None = None,
) -> tuple[AdapterResult, list[dict[str, Any]]]:
    """Convenience function to run a single plugin assessment.

    Returns (AdapterResult, findings_list).
    """
    runner = PluginRunner(plugin_path, timeout=timeout, cancel=cancel)
    try:
        runner.start()
        return runner.assess_with_findings(target, context=context)
    finally:
        runner.close()


class AdapterPlugin(Adapter):
    """Wrapper that runs an external plugin as an Adapter.

    This allows existing in-process adapters to be gradually replaced
    by out-of-process plugins without changing the orchestrator.
    """

    id = ""
    version = "0"
    asset_types: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()

    def __init__(
        self,
        plugin_path: str | Path,
        timeout: float = DEFAULT_PLUGIN_TIMEOUT,
    ):
        self._plugin_path = Path(plugin_path)
        self._timeout = timeout
        self._runner: PluginRunner | None = None
        self._info: dict[str, Any] | None = None

    def _get_runner(self) -> PluginRunner:
        if self._runner is None:
            self._runner = PluginRunner(self._plugin_path, timeout=self._timeout)
            self._info = self._runner.start()
            # Update our metadata from plugin
            contract = self._info.get("contract", {})
            self.id = contract.get("id", self.id)
            self.version = contract.get("version", self.version)
            self.asset_types = tuple(contract.get("asset_types", self.asset_types))
            self.requires = tuple(contract.get("requires", self.requires))
        return self._runner

    def start(self) -> dict[str, Any]:
        """Start the plugin and return adapter info."""
        return self._get_runner()._adapter_info or {}

    def available(self) -> tuple[bool, str]:
        runner = self._get_runner()
        return runner.available()

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        runner = self._get_runner()
        # Override timeout if provided
        original_timeout = runner.timeout
        runner.timeout = timeout
        try:
            return runner.assess(target, context=context)
        finally:
            runner.timeout = original_timeout

    def contract(self) -> dict[str, Any]:
        if self._info:
            return self._info.get("contract", {})
        return super().contract()

    def info(self) -> dict[str, Any]:
        if self._info:
            return self._info
        return super().info()

    def close(self) -> None:
        if self._runner:
            self._runner.close()
            self._runner = None

    def __del__(self):
        self.close()

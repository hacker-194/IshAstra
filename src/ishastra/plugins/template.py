#!/usr/bin/env python3
"""Plugin template for out-of-process adapters.

Copy this file and implement the AdapterBase methods.
The plugin communicates via stdin/stdout JSON protocol.

Protocol:
- Each message is a single JSON line
- Request: {"protocol": 1, "method": "info|assess|shutdown", "params": {...}, "id": N}
- Response: {"result": {...}, "error": {"code": "...", "message": "..."}, "id": N}

Methods:
- info: Returns adapter metadata and contract
- assess: Runs assessment on target, returns findings and notes
- shutdown: Graceful shutdown signal
"""

from __future__ import annotations

import json
import sys
import threading
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """Finding data structure."""

    asset: str
    category: str
    title: str
    severity: str
    confidence: str
    detector: str
    detector_version: str
    evidence: str
    location: str
    description: str = ""
    remediation: str = ""
    cwe: str = ""
    verification: str = "observed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "detector": self.detector,
            "detector_version": self.detector_version,
            "evidence": self.evidence,
            "location": self.location,
            "description": self.description,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "verification": self.verification,
        }


@dataclass
class AdapterResult:
    """Assessment result."""

    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    partial: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
            "partial": self.partial,
        }


class AdapterBase:
    """Base class for plugin adapters. Override the methods below."""

    # Adapter metadata - MUST be overridden
    id: str = ""
    version: str = "0"
    asset_types: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()

    # Contract
    protocols: tuple[str, ...] = ("tcp",)
    scan_modes: tuple[str, ...] = ("connect",)
    enforcement: str = "proxy"
    timeout: float = 300.0

    def info(self) -> dict[str, Any]:
        """Return adapter metadata."""
        return {
            "id": self.id,
            "version": self.version,
            "asset_types": list(self.asset_types),
            "requires": list(self.requires),
            "available": True,
            "detail": "built in",
            "contract": self.contract(),
        }

    def contract(self) -> dict[str, Any]:
        """Return adapter contract."""
        return {
            "id": self.id,
            "version": self.version,
            "asset_types": list(self.asset_types),
            "protocols": list(self.protocols),
            "scan_modes": list(self.scan_modes),
            "enforcement": self.enforcement,
            "timeout": self.timeout,
            "requires": list(self.requires),
        }

    def available(self) -> tuple[bool, str]:
        """Check if adapter is available to run."""
        return True, "built in"

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        """Run assessment on target. Override this method."""
        raise NotImplementedError

    def on_shutdown(self) -> None:
        """Called before plugin exits. Override for cleanup."""


class PluginServer:
    """JSON-RPC-like server for plugin communication."""

    def __init__(self, adapter: AdapterBase):
        self.adapter = adapter
        self._request_id = 0
        self._cancel = threading.Event()

    def run(self) -> None:
        """Main loop: read requests from stdin, write responses to stdout."""
        # Send handshake
        self._write_response(
            request_id=0,
            result={"protocol": 1, "adapter": self.adapter.id},
        )

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                request = json.loads(line)
            except json.JSONDecodeError as e:
                self._write_response(
                    request_id=0,
                    error={"code": "PARSE_ERROR", "message": f"Invalid JSON: {e}"},
                )
                continue

            method = request.get("method")
            params = request.get("params", {})
            request_id = request.get("id", 0)

            try:
                if method == "info":
                    info = self.adapter.info()
                    self._write_response(request_id=request_id, result=info)

                elif method == "assess":
                    target = params.get("target", "")
                    timeout = params.get("timeout", 300.0)
                    context = params.get("context", {})
                    assessment = self.adapter.assess(
                        target,
                        timeout=timeout,
                        cancel=self._cancel,
                        context=context,
                    )
                    self._write_response(request_id=request_id, result=assessment.to_dict())

                elif method == "shutdown":
                    self.adapter.on_shutdown()
                    self._write_response(request_id=request_id, result={"status": "ok"})
                    break

                else:
                    self._write_response(
                        request_id=request_id,
                        error={"code": "METHOD_NOT_FOUND", "message": f"Unknown method: {method}"},
                    )

            except Exception as e:
                error_code = "INTERNAL_ERROR"
                if isinstance(e, NotImplementedError):
                    error_code = "NOT_APPLICABLE"
                self._write_response(
                    request_id=request_id,
                    error={"code": error_code, "message": str(e)},
                )

    def _write_response(
        self,
        request_id: int,
        result: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
    ) -> None:
        """Write a response to stdout."""
        response: dict[str, Any] = {"id": request_id}
        if result is not None:
            response["result"] = result
        if error is not None:
            response["error"] = error
        print(json.dumps(response, separators=(",", ":")), flush=True)


def main(adapter: AdapterBase) -> None:
    """Entry point for plugin. Call this from your plugin's main()."""
    server = PluginServer(adapter)
    server.run()


__example__ = """
Example usage (see docs/adapters/custom.md for full guide):

class MyAdapter(AdapterBase):
    id = "my-custom-adapter"
    version = "1.0"
    asset_types = ("web",)
    requires = ("mytool",)
    enforcement = "proxy"

    def available(self) -> tuple[bool, str]:
        return True, "available"

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        gateway_url = (context or {}).get("gateway_url")
        if not gateway_url:
            raise RuntimeError(f"{self.id}: egress gateway required; set ISHASTRA_GATEWAY_URL")
        result = AdapterResult()
        result.findings.append(Finding(...))
        return result

if __name__ == "__main__":
    main(MyAdapter())
"""

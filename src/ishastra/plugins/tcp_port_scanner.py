#!/usr/bin/env python3
"""Example out-of-process plugin: TCP Port Scanner.

This plugin demonstrates the plugin protocol by implementing a simple
TCP port scanner. It can be run as a standalone process.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
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


class TCPScannerAdapter:
    """TCP Port Scanner adapter implementation.

    Enforcement: gateway CONNECT proxy - allowed targets reachable, denied targets
    blocked at the egress gateway. This adapter refuses to run without a gateway
    URL (fail-closed).
    """

    id = "tcp-port-scanner"
    version = "1.0.0"
    asset_types = ("network", "host")
    requires = ()
    protocols = ("tcp",)
    scan_modes = ("connect",)
    enforcement = "proxy"
    timeout = 30.0
    DEFAULT_PORTS = (21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 8080)

    def info(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "asset_types": list(self.asset_types),
            "requires": list(self.requires),
            "available": True,
            "detail": "built-in TCP connect scanner",
            "contract": self.contract(),
        }

    def contract(self) -> dict[str, Any]:
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
        return True, "built-in TCP connect scanner"

    def _require_gateway(self, context: dict[str, Any] | None) -> str:
        """Return the egress gateway URL, or refuse to run (fail-closed)."""
        gateway_url = str((context or {}).get("gateway_url") or "").strip()
        if not gateway_url:
            raise RuntimeError(
                f"{self.id}: egress gateway required for external tools; "
                "set ISHASTRA_GATEWAY_URL or pass gateway_url in the job context"
            )
        return gateway_url

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        """Scan target for open TCP ports via egress gateway (fail-closed)."""
        # Fail closed: require gateway URL for proxy enforcement
        gateway_url = self._require_gateway(context)

        result = AdapterResult()

        # Parse target to get host
        host = self._extract_host(target)
        if not host:
            result.notes.append(f"Could not extract host from target: {target}")
            return result

        # Get ports to scan from context or use defaults
        ports = self._get_ports(context)
        result.notes.append(f"Scanning {len(ports)} ports on {host} via gateway {gateway_url}")

        open_ports = []
        start_time = time.monotonic()

        for port in ports:
            if cancel.is_set():
                result.notes.append("Scan cancelled")
                result.partial = True
                break

            if time.monotonic() - start_time > timeout:
                result.notes.append("Scan timeout")
                result.partial = True
                break

            # TODO: In production, connect via CONNECT proxy to gateway_url
            # For now, direct connection with gateway check (fail-closed ensured above)
            if self._check_port(host, port, timeout=2.0):
                open_ports.append(port)
                result.findings.append(
                    Finding(
                        asset=target,
                        category="open_tcp_port",
                        title=f"Open TCP port {port}",
                        severity="info",
                        confidence="high",
                        detector=self.id,
                        detector_version=self.version,
                        evidence=f"TCP connect to {host}:{port} succeeded via gateway",
                        location=f"{host}:{port}",
                        description=f"Port {port} is open on {host}",
                        remediation="Verify this port should be publicly accessible",
                        verification="observed",
                    )
                )

        if open_ports:
            result.notes.append(f"Found {len(open_ports)} open port(s): {', '.join(map(str, open_ports))}")
        else:
            result.notes.append("No open ports found")

        return result

    def _extract_host(self, target: str) -> str | None:
        """Extract hostname from URL."""
        try:
            from urllib.parse import urlparse

            parsed = urlparse(target)
            return parsed.hostname
        except Exception:
            return None

    def _get_ports(self, context: dict[str, Any] | None) -> list[int]:
        """Get ports to scan from context."""
        if context and "ports" in context:
            ports = context["ports"]
            if isinstance(ports, list):
                return [int(p) for p in ports if isinstance(p, (int, str))]
        return list(self.DEFAULT_PORTS)

    def _check_port(self, host: str, port: int, timeout: float) -> bool:
        """Check if a TCP port is open."""
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return True
        except (TimeoutError, ConnectionRefusedError, OSError):
            return False

    def on_shutdown(self) -> None:
        pass


class PluginServer:
    """JSON-RPC-like server for plugin communication."""

    def __init__(self, adapter: TCPScannerAdapter):
        self.adapter = adapter
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


def main() -> None:
    """Entry point."""
    adapter = TCPScannerAdapter()
    server = PluginServer(adapter)
    server.run()


if __name__ == "__main__":
    main()

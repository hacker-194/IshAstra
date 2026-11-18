"""Native TCP connect discovery -- the port check without an external binary.

Same rules as the nmap adapter: only ports the engagement authorizes
(``allowed_ports``, else just the target URL's port), connecting to the address
the scope gate pinned and never to a fresh lookup. Discovery only -- an
accepted connection is an observed fact, no protocol bytes are sent -- and
when nmap is installed both run, with findings de-duplicating on
(asset, category, location).
"""

from __future__ import annotations

import socket
import threading
from typing import Any

from strix import __version__
from strix.core.adapter_base import (
    Adapter,
    AdapterCancelled,
    AdapterResult,
    checked_destination,
)
from strix.core.findings import Finding
from strix.core.scope import current as current_scope
from strix.core.urls import parse_url

# Static table of conventionally risky ports, not a vulnerability feed. Drive
# severity from an exposure policy per asset if that ever matters.
RISKY_PORTS: dict[int, tuple[str, str]] = {
    21: ("high", "FTP often allows anonymous access"),
    22: ("medium", "SSH brute-force target"),
    23: ("high", "Telnet sends credentials in cleartext"),
    25: ("medium", "SMTP open relay risk"),
    53: ("medium", "DNS zone transfer / amplification"),
    110: ("medium", "POP3 cleartext auth"),
    135: ("medium", "MS RPC endpoint mapper"),
    139: ("high", "NetBIOS / SMBv1"),
    143: ("medium", "IMAP cleartext auth"),
    445: ("high", "SMB / EternalBlue family"),
    993: ("low", "IMAPS - usually fine"),
    995: ("low", "POP3S - usually fine"),
    1433: ("high", "MSSQL - common target"),
    1521: ("high", "Oracle TNS - common target"),
    3306: ("high", "MySQL - common target"),
    3389: ("high", "RDP - BlueKeep, brute-force"),
    5432: ("high", "PostgreSQL - common target"),
    5900: ("high", "VNC - often no auth"),
    6379: ("high", "Redis - often no auth"),
    8080: ("medium", "HTTP alt - often admin panels"),
    8443: ("medium", "HTTPS alt - often admin panels"),
    27017: ("high", "MongoDB - often no auth"),
}

# Cap the number of ports any single job will scan natively.
MAX_PORTS = 100


class TCPPortAdapter(Adapter):
    """Check which authorized TCP ports are open."""

    id = "strix-tcp"
    version = __version__
    asset_types = ("web", "api", "network")
    requires = ()

    def available(self) -> tuple[bool, str]:
        return True, "built in"

    @staticmethod
    def _connect(ip: str, port: int, timeout: float) -> str:
        """Return "open", "closed", or "filtered"."""
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return "open"
        except ConnectionRefusedError:
            return "closed"
        except (TimeoutError, OSError):
            return "filtered"

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        destination = checked_destination(target)
        result = AdapterResult()

        # Use target URL for asset reference (destination has no url attribute)
        asset_url = target

        # Determine which ports to scan from the current scope.
        scope = current_scope()
        allowed = list(scope.allowed_ports) if scope else []
        if not allowed:
            parsed = parse_url(target)
            if parsed and parsed.port:
                allowed = [parsed.port]
            else:
                allowed = [80, 443] if (parsed and parsed.scheme == "https") else [80]

        # Cap the scan.
        if len(allowed) > MAX_PORTS:
            allowed = allowed[:MAX_PORTS]
            result.partial = True
            result.notes.append(f"port list capped at {MAX_PORTS}")

        for port in allowed:
            if cancel.is_set():
                raise AdapterCancelled()
            state = self._connect(destination.ip, port, timeout)
            if state == "open":
                # Severity from RISKY_PORTS table, default to info.
                severity, remediation = RISKY_PORTS.get(port, ("info", ""))
                result.findings.append(
                    Finding(
                        asset=asset_url,
                        category="open_tcp_port",
                        title=f"Open TCP Port {port}",
                        severity=severity,
                        confidence="high",
                        detector=self.id,
                        detector_version=self.version,
                        evidence=f"TCP connection to {destination.ip}:{port} succeeded",
                        location=f"{destination.host}:{port}/tcp",
                        description=f"Port {port} is open on {destination.host}.",
                        remediation=remediation,
                        verification="observed",
                    )
                )
            elif state == "filtered":
                result.partial = True
                result.notes.append(f"port {port}: filtered (no answer)")

        return result

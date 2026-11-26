"""Minimal Ishastra adapter example — demonstrates the adapter contract."""

from __future__ import annotations

from typing import Any

from ishastra.core.adapter_base import Adapter, AdapterResult, checked_destination
from ishastra.core.findings import Finding


class HelloAdapter(Adapter):
    """Example adapter that emits a single INFO finding per authorized target."""

    id = "ishastra-hello"
    version = "0.1.0"
    asset_types = ("web",)
    protocols = ("http", "https")
    scan_modes = ("connect",)
    enforcement = "none"
    timeout = 30.0

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: Any,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        # Validate the target through the Scope Gate (Layer 1/2/3)
        dest = checked_destination(target)

        # Emit a single informational finding proving the adapter ran
        finding = Finding(
            id=f"{self.id.upper()}-REACHABLE",
            title="Target reachable via Scope Gate",
            description=f"Successfully connected to {dest.host}:{dest.port} (pinned IP: {dest.ip}) through all three authorization layers.",
            severity="info",
            category="network",
            location=target,
            evidence={
                "pinned_ip": dest.ip,
                "port": dest.port,
                "scheme": dest.scheme,
                "resolved_at": dest.resolved_at,
            },
            references=[
                "https://ishastra.dev/docs/adapters/sdk",
            ],
            metadata={
                "adapter_version": self.version,
                "gate_layer": 3,
            },
        )

        return AdapterResult(findings=[finding], partial=False)


# Entry point for direct execution (useful for debugging)
if __name__ == "__main__":
    import asyncio

    from ishastra.core.scope import ScopeDocument, ScopeMetadata
    from ishastra.security.authorization.scope import ScopeGate

    async def main():
        scope = ScopeDocument(
            version=2,
            metadata=ScopeMetadata(name="Test", owner="test@example.com"),
            authorized_networks=["0.0.0.0/0"],
            include_hosts=["httpbin.org"],
            allowed_ports=[80, 443],
        )
        gate = ScopeGate(scope)

        # Test the scope gate directly
        dest = await gate.validate_outbound("https://httpbin.org/get")
        print(f"Scope gate OK: {dest.ip}:{dest.port}")

    asyncio.run(main())

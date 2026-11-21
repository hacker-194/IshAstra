"""
Real-world ScopeGate Integration Examples

This module demonstrates production-ready integration patterns for Ishastra ScopeGate
authorization system across different frameworks and use cases.
"""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncIterator, Optional

import httpx
from ishastra.core.scope import Scope, ScopeGate, load, configure, Destination






def basic_sync_example():
    """Basic synchronous validation for CLI tools or simple scripts."""
    

    scope = load("scope.json")
    

    result = ScopeGate.validate_outbound("https://api.example.com/users", scope)
    
    if result.allowed:
        print(f"Allowed: {result.host}:{result.port}")
        print(f"  Resolved IPs: {result.resolved_ips}")

    else:
        print(f"Denied: {result.denial_code} - {result.reason}")







async def async_validation_example():
    """Async validation for high-throughput async applications."""
    
    scope = load("scope.json")
    

    targets = [
        "https://api.example.com/users",
        "https://api.example.com/posts",
        "https://admin.example.com/",
    ]
    
    results = await asyncio.gather(*[
        ScopeGate.validate_outbound_async(target, scope)
        for target in targets
    ])
    
    for target, result in zip(targets, results):
        status = "OK" if result.allowed else "DENIED"
        print(f"{status} {target}: {result.denial_code or 'allowed'}")





















































class ScopeValidatingTransport(httpx.BaseTransport):
    """
    httpx transport that validates every request through ScopeGate.
    Use this to automatically enforce scope on all HTTP clients.
    """
    
    def __init__(self, scope: Scope, wrapped: Optional[httpx.BaseTransport] = None):
        self.scope = scope
        self.wrapped = wrapped or httpx.AsyncHTTPTransport()
    
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:

        result = await ScopeGate.validate_outbound_async(str(request.url), self.scope)
        
        if not result.allowed:
            return httpx.Response(
                status_code=403,
                content=f"Scope violation: {result.reason}",
                request=request,
            )
        

        if result.resolved_ips:
            pinned_url = request.url.copy_with(
                host=result.resolved_ips[0],
            )

            request.headers["Host"] = request.url.host
            request.url = pinned_url
        
        return await self.wrapped.handle_async_request(request)
    
    def handle_request(self, request: httpx.Request) -> httpx.Response:

        result = ScopeGate.validate_outbound(str(request.url), self.scope)
        
        if not result.allowed:
            return httpx.Response(
                status_code=403,
                content=f"Scope violation: {result.reason}",
                request=request,
            )
        
        if result.resolved_ips:
            request.headers["Host"] = request.url.host
            request.url = request.url.copy_with(host=result.resolved_ips[0])
        
        return self.wrapped.handle_request(request)


def create_scoped_client(scope: Scope) -> httpx.AsyncClient:
    """Create an httpx client that automatically enforces scope."""
    transport = ScopeValidatingTransport(scope)
    return httpx.AsyncClient(transport=transport)


async def httpx_integration_example():
    """Using the scoped httpx client."""
    
    scope = load("scope.json")
    client = create_scoped_client(scope)
    
    try:

        response = await client.get("https://api.example.com/health")
        print(f"Status: {response.status_code}")
        

        response = await client.get("https://evil.com/")
        print(f"Status: {response.status_code}")
    finally:
        await client.aclose()


















































class TenantScopeManager:
    """Manages scopes for multiple tenants with caching and hot-reload."""
    
    def __init__(self, scope_dir: Path, jwks_env: str = "ISHASTRA_SCOPE_JWKS"):
        self.scope_dir = scope_dir
        self.jwks_env = jwks_env
        self._cache: dict[str, tuple[Scope, float]] = {}
        self._default_scope: Optional[Scope] = None
    
    def get_scope(self, tenant_id: str) -> Scope:
        """Get scope for tenant, loading from file with hot-reload."""
        scope_path = self.scope_dir / f"{tenant_id}.json"
        
        if not scope_path.exists():
            if self._default_scope is None:
                self._default_scope = load(self.scope_dir / "default.json")
            return self._default_scope
        
        mtime = scope_path.stat().st_mtime
        cached = self._cache.get(tenant_id)
        
        if cached and cached[1] == mtime:
            return cached[0]
        
        scope = load(str(scope_path))
        self._cache[tenant_id] = (scope, mtime)
        return scope
    
    def invalidate(self, tenant_id: str):
        """Force reload on next access."""
        self._cache.pop(tenant_id, None)
    
    @asynccontextmanager
    async def bound_scope(self, tenant_id: str) -> AsyncIterator[Scope]:
        """Context manager for per-request scope binding."""
        scope = self.get_scope(tenant_id)
        token = scope.bound()
        try:
            yield scope
        finally:
            token.reset()


async def multi_tenant_example():
    """Multi-tenant request handling."""
    
    manager = TenantScopeManager(Path("/etc/ishastra/scopes"))
    
    async def handle_request(tenant_id: str, target_url: str):
        async with manager.bound_scope(tenant_id) as scope:
            result = await ScopeGate.validate_outbound_async(target_url, scope)
            if not result.allowed:
                raise PermissionError(f"Scope violation: {result.reason}")
            return result
    

    await asyncio.gather(
        handle_request("acme-corp", "https://api.acmecorp.com/"),
        handle_request("globex-inc", "https://api.globex.com/"),
        handle_request("unknown-tenant", "https://example.com/"),
    )






def generate_ephemeral_scope(
    program: str,
    authorized_by: str,
    authorization_ref: str,
    include: list[str],
    authorized_networks: list[str],
    allowed_ports: list[int],
    expires_in_hours: int = 2,
    output_path: Optional[Path] = None,
) -> dict:
    """Generate a short-lived scope document for CI/CD pipelines."""
    
    expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
    
    scope_doc = {
        "version": 2,
        "program": program,
        "authorized_by": authorized_by,
        "authorization_ref": authorization_ref,
        "include": include,
        "exclude": [],
        "authorized_networks": authorized_networks,
        "allowed_ports": allowed_ports,
        "allow_broad_networks": any(
            net in ["0.0.0.0/0", "::/0"] for net in authorized_networks
        ),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "metadata": {
            "generated_by": "ci-pipeline",
            "pipeline_run_id": os.environ.get("CI_RUN_ID", "local"),
            "ephemeral": True,
        },
    }
    
    if output_path:
        output_path.write_text(json.dumps(scope_doc, indent=2))
        print(f"Scope written to {output_path}")
    
    return scope_doc


def ci_cd_example():
    """Generate scope for a CI pipeline run."""
    
    scope_doc = generate_ephemeral_scope(
        program="PR Validation - acme/api-service",
        authorized_by="CI System",
        authorization_ref=f"PR-{os.environ.get('PR_NUMBER', '123')}",
        include=["api-staging.acmecorp.com"],
        authorized_networks=["10.0.0.0/8"],
        allowed_ports=[443, 8443],
        expires_in_hours=2,
        output_path=Path("scope.ephemeral.json"),
    )
    


    
    return scope_doc






def create_break_glass_scope(
    incident_ticket: str,
    approver_1: str,
    approver_2: str,
    target_hosts: list[str],
    authorized_networks: list[str],
    expires_in_hours: int = 4,
) -> dict:
    """
    Create a break-glass scope document.
    Requires dual approval - both approvers must sign off.
    """
    
    expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
    
    scope_doc = {
        "version": 2,
        "program": f"Emergency Access - {incident_ticket}",
        "authorized_by": f"{approver_1}, {approver_2}",
        "authorization_ref": incident_ticket,
        "include": target_hosts,
        "exclude": [],
        "authorized_networks": authorized_networks,
        "allowed_ports": [443],
        "allow_broad_networks": False,
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "metadata": {
            "break_glass": True,
            "incident_ticket": incident_ticket,
            "approver_1": approver_1,
            "approver_2": approver_2,
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    }
    
    return scope_doc






class ScopeMetricsCollector:
    """Collects and exports scope gate metrics."""
    
    def __init__(self, scope: Scope):
        self.scope = scope
        self.decisions: dict[str, int] = {
            "allowed": 0,
            "blocked": 0,
            "by_reason": {},
            "by_tenant": {},
        }
    
    async def validate_and_record(
        self,
        target_url: str,
        tenant_id: str = "unknown",
    ) -> tuple[bool, str]:
        result = await ScopeGate.validate_outbound_async(target_url, self.scope)
        
        if result.allowed:
            self.decisions["allowed"] += 1
        else:
            self.decisions["blocked"] += 1
            self.decisions["by_reason"][result.denial_code] = (
                self.decisions["by_reason"].get(result.denial_code, 0) + 1
            )
        
        self.decisions["by_tenant"][tenant_id] = (
            self.decisions["by_tenant"].get(tenant_id, 0) + 1
        )
        
        return result.allowed, result.denial_code or "allowed"
    
    def get_prometheus_metrics(self) -> str:
        """Export in Prometheus format."""
        lines = [
            f'ishastra_scope_gate_decisions_allowed {self.decisions["allowed"]}',
            f'ishastra_scope_gate_decisions_blocked {self.decisions["blocked"]}',
        ]
        
        for reason, count in self.decisions["by_reason"].items():
            lines.append(
                f'ishastra_scope_gate_decisions_blocked_by_reason{{reason="{reason}"}} {count}'
            )
        
        for tenant, count in self.decisions["by_tenant"].items():
            lines.append(
                f'ishastra_scope_gate_decisions_by_tenant{{tenant="{tenant}"}} {count}'
            )
        
        return "\n".join(lines)


async def metrics_example():
    """Monitor scope gate decisions."""
    
    scope = load("scope.json")
    collector = ScopeMetricsCollector(scope)
    

    targets = [
        ("https://api.example.com/", "tenant-1"),
        ("https://admin.example.com/", "tenant-1"),
        ("https://evil.com/", "tenant-2"),
        ("https://api.example.com:8080/", "tenant-1"),
    ]
    
    for url, tenant in targets:
        await collector.validate_and_record(url, tenant)
    
    print(collector.get_prometheus_metrics())






PRODUCTION_SCOPE_EXAMPLE = {
    "version": 2,
    "program": "Production Security Assessment",
    "authorized_by": "CISO Jane Smith",
    "authorization_ref": "CONTRACT-2025-SEC-001",
    "include": [
        "api.production.example.com",
        "*.production.example.com",
        "api.staging.example.com",
        "10.10.0.0/16",
    ],
    "exclude": [
        "admin.production.example.com",
        "vault.production.example.com",
        "*.internal.example.com",
    ],
    "authorized_networks": [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "::/0",
    ],
    "allowed_ports": [80, 443, 8080, 8443, 8000, 9000],
    "allow_broad_networks": True,
    "expires_at": "2025-12-31T23:59:59Z",
    "auth": {
        "users": [
            {
                "id": "scanner-1",
                "cookies": [{"name": "session", "value": "prod-session-abc"}],
                "headers": {"Authorization": "Bearer prod-token-123"},
                "bearer": "eyJhbGciOiJIUzI1NiJ9...",
            }
        ]
    },
    "collab": {
        "host": "10.10.10.50",
        "port": 8080,
    },
    "metadata": {
        "environment": "production",
        "compliance": ["SOC2", "ISO27001"],
        "reviewed_by": "security-team",
        "review_date": "2025-01-15",
    },
}


def production_config_example():
    """Show production-ready scope configuration."""
    print(json.dumps(PRODUCTION_SCOPE_EXAMPLE, indent=2))






if __name__ == "__main__":
    print("=== Ishastra ScopeGate Integration Examples ===\n")
    


    







    
    print("See individual functions for usage patterns.")
    print("Create scope.json from PRODUCTION_SCOPE_EXAMPLE to run examples.")

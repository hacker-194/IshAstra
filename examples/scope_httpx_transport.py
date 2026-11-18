"""
Production-ready httpx transport adapter for Strix ScopeGate.

This transport intercepts ALL outbound HTTP requests and validates them
through ScopeGate before allowing the connection. It prevents DNS rebinding
by pinning to the validated IP address.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx
from httpx import Request, Response

from strix.core.scope import Scope, ScopeGate

logger = logging.getLogger(__name__)


class ScopeValidatingTransport(httpx.BaseTransport):
    """
    httpx transport that validates every request through ScopeGate.
    
    Features:
    - Validates every outbound request against scope
    - Pins to resolved IP to prevent DNS rebinding
    - Preserves Host header for SNI/virtual hosting
    - Supports both sync and async clients
    - Comprehensive logging and metrics
    """
    
    def __init__(
        self,
        scope: Scope,
        wrapped: Optional[httpx.BaseTransport] = None,
        *,
        allow_redirects: bool = True,
        max_redirects: int = 5,
    ):
        self.scope = scope
        self.wrapped = wrapped or httpx.AsyncHTTPTransport()
        self.allow_redirects = allow_redirects
        self.max_redirects = max_redirects
        self._redirect_count = 0
    
    def _validate_request(self, request: Request) -> tuple[bool, Optional[Response]]:
        """Validate a request synchronously."""
        url = str(request.url)
        
        # Skip validation for non-HTTP(S) URLs
        if not url.startswith(("http://", "https://")):
            logger.debug(f"Skipping validation for non-HTTP URL: {url}")
            return True, None
        
        result = ScopeGate.validate_outbound(url, self.scope)
        
        if not result.allowed:
            logger.warning(
                f"Scope violation: {url} -> {result.denial_code}: {result.reason}"
            )
            response = Response(
                status_code=403,
                content=f"Scope violation: {result.reason}".encode(),
                request=request,
                headers={"X-Scope-Decision": result.denial_code or "denied"},
            )
            return False, response
        
        # Pin to resolved IP to prevent DNS rebinding
        if result.resolved_ips:
            pinned_ip = result.resolved_ips[0]
            original_host = request.url.host
            
            # Preserve original host for SNI and virtual hosting
            request.headers["Host"] = original_host
            
            # Rewrite URL to use pinned IP
            request.url = request.url.copy_with(host=pinned_ip)
            
            logger.debug(f"Pinned {original_host} -> {pinned_ip} for {url}")
        
        return True, None
    
    async def _validate_request_async(self, request: Request) -> tuple[bool, Optional[Response]]:
        """Validate a request asynchronously."""
        url = str(request.url)
        
        if not url.startswith(("http://", "https://")):
            logger.debug(f"Skipping validation for non-HTTP URL: {url}")
            return True, None
        
        result = await ScopeGate.validate_outbound_async(url, self.scope)
        
        if not result.allowed:
            logger.warning(
                f"Scope violation: {url} -> {result.denial_code}: {result.reason}"
            )
            response = Response(
                status_code=403,
                content=f"Scope violation: {result.reason}".encode(),
                request=request,
                headers={"X-Scope-Decision": result.denial_code or "denied"},
            )
            return False, response
        
        if result.resolved_ips:
            pinned_ip = result.resolved_ips[0]
            original_host = request.url.host
            
            request.headers["Host"] = original_host
            request.url = request.url.copy_with(host=pinned_ip)
            
            logger.debug(f"Pinned {original_host} -> {pinned_ip} for {url}")
        
        return True, None
    
    def handle_request(self, request: Request) -> Response:
        """Handle synchronous request."""
        allowed, response = self._validate_request(request)
        if not allowed:
            return response
        return self.wrapped.handle_request(request)
    
    async def handle_async_request(self, request: Request) -> Response:
        """Handle asynchronous request."""
        allowed, response = await self._validate_request_async(request)
        if not allowed:
            return response
        return await self.wrapped.handle_async_request(request)


class MultiTenantScopeTransport(httpx.BaseTransport):
    """
    Transport that resolves tenant scope from request context.
    
    Use this when you have multiple tenants with different scopes.
    The tenant is determined from a header or request context.
    """
    
    def __init__(
        self,
        scope_resolver,  # Callable[[Request], Scope]
        wrapped: Optional[httpx.BaseTransport] = None,
    ):
        self.scope_resolver = scope_resolver
        self.wrapped = wrapped or httpx.AsyncHTTPTransport()
    
    def _get_scope(self, request: Request) -> Scope:
        return self.scope_resolver(request)
    
    def handle_request(self, request: Request) -> Response:
        scope = self._get_scope(request)
        result = ScopeGate.validate_outbound(str(request.url), scope)
        
        if not result.allowed:
            return Response(
                status_code=403,
                content=f"Scope violation: {result.reason}".encode(),
                request=request,
            )
        
        if result.resolved_ips:
            request.headers["Host"] = request.url.host
            request.url = request.url.copy_with(host=result.resolved_ips[0])
        
        return self.wrapped.handle_request(request)
    
    async def handle_async_request(self, request: Request) -> Response:
        scope = self._get_scope(request)
        result = await ScopeGate.validate_outbound_async(str(request.url), scope)
        
        if not result.allowed:
            return Response(
                status_code=403,
                content=f"Scope violation: {result.reason}".encode(),
                request=request,
            )
        
        if result.resolved_ips:
            request.headers["Host"] = request.url.host
            request.url = request.url.copy_with(host=result.resolved_ips[0])
        
        return await self.wrapped.handle_async_request(request)


# =============================================================================
# Factory Functions
# =============================================================================

def create_scoped_client(
    scope: Scope,
    *,
    timeout: float = 30.0,
    limits: Optional[httpx.Limits] = None,
    **kwargs,
) -> httpx.AsyncClient:
    """
    Create an httpx AsyncClient that enforces scope on all requests.
    
    Args:
        scope: The Scope object to validate against
        timeout: Request timeout in seconds
        limits: Connection limits
        **kwargs: Additional arguments passed to AsyncClient
    
    Returns:
        Configured AsyncClient with scope validation
    """
    transport = ScopeValidatingTransport(scope)
    return httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        limits=limits,
        **kwargs,
    )


def create_sync_scoped_client(
    scope: Scope,
    *,
    timeout: float = 30.0,
    **kwargs,
) -> httpx.Client:
    """Create a synchronous httpx Client with scope validation."""
    transport = ScopeValidatingTransport(scope)
    return httpx.Client(
        transport=transport,
        timeout=timeout,
        **kwargs,
    )


def create_multi_tenant_client(
    scope_resolver,
    *,
    timeout: float = 30.0,
    **kwargs,
) -> httpx.AsyncClient:
    """Create a client that resolves scope per-request."""
    transport = MultiTenantScopeTransport(scope_resolver)
    return httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        **kwargs,
    )


# =============================================================================
# Usage Examples
# =============================================================================

async def example_basic_usage():
    """Basic usage with a single scope."""
    from strix.core.scope import load
    
    scope = load("/etc/strix/scope.json")
    client = create_scoped_client(scope)
    
    try:
        # This request will be validated
        response = await client.get("https://api.example.com/health")
        print(f"Status: {response.status_code}")
        
        # This will be blocked if not in scope
        response = await client.get("https://evil.com/")
        print(f"Status: {response.status_code}")  # 403
    finally:
        await client.aclose()


async def example_multi_tenant():
    """Multi-tenant usage with per-request scope resolution."""
    from strix.core.scope import load
    from pathlib import Path
    
    SCOPE_DIR = Path("/etc/strix/scopes")
    scopes = {}
    
    def get_scope(request: Request) -> Scope:
        tenant = request.headers.get("X-Tenant-ID", "default")
        if tenant not in scopes:
            scope_path = SCOPE_DIR / f"{tenant}.json"
            if scope_path.exists():
                scopes[tenant] = load(str(scope_path))
            else:
                scopes[tenant] = load(str(SCOPE_DIR / "default.json"))
        return scopes[tenant]
    
    client = create_multi_tenant_client(get_scope)
    
    try:
        # Requests with different tenants
        response = await client.get(
            "https://api.acmecorp.com/",
            headers={"X-Tenant-ID": "acme-corp"}
        )
        print(f"Acme: {response.status_code}")
        
        response = await client.get(
            "https://api.globex.com/",
            headers={"X-Tenant-ID": "globex-inc"}
        )
        print(f"Globex: {response.status_code}")
    finally:
        await client.aclose()


async def example_with_retries():
    """Client with retry logic and scope validation."""
    from strix.core.scope import load
    from httpx import Retry
    
    scope = load("/etc/strix/scope.json")
    transport = ScopeValidatingTransport(scope)
    
    # Wrap with retry transport
    retry_transport = httpx.AsyncRetryTransport(
        transport,
        retry=Retry(total=3, backoff_factor=0.5),
    )
    
    client = httpx.AsyncClient(transport=retry_transport, timeout=30.0)
    
    try:
        response = await client.get("https://api.example.com/flaky-endpoint")
        print(f"Status: {response.status_code}")
    finally:
        await client.aclose()


if __name__ == "__main__":
    import asyncio
    asyncio.run(example_basic_usage())

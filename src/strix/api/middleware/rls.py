"""RLS (Row-Level Security) tenant context middleware.

This middleware sets the PostgreSQL session variable `app.current_tenant`
for each request based on the authenticated API key, enabling RLS policies
to filter data at the database level.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from strix.core import store


class RLSTenantMiddleware(BaseHTTPMiddleware):
    """Middleware to inject tenant context into database connections for RLS.

    This middleware runs after authentication and extracts the tenant_id
    from the validated API key, then makes it available for database
    operations via the PostgreSQLDatabase.set_tenant_context method.
    """

    async def dispatch(self, request: Request, call_next):
        # Get tenant_id from request.state (set by TenantStateMiddleware)
        tenant_id = getattr(request.state, "tenant_id", None)

        # Skip for anonymous requests
        if tenant_id and tenant_id != "anonymous":
            # Set tenant context on the PostgreSQL database instance
            db = await store.get_database()
            if db.is_postgresql():
                # Type check: PostgreSQLDatabase has set_tenant_context
                db.set_tenant_context(tenant_id)  # type: ignore[attr-defined]

        try:
            response = await call_next(request)
        finally:
            # Clear tenant context after request
            db = await store.get_database()
            if db.is_postgresql():
                db.set_tenant_context(None)  # type: ignore[attr-defined]

        return response


async def get_db_with_tenant(tenant_id: str | None = None):
    """Get a database connection with tenant context set.

    Usage in route handlers:
        async with get_db_with_tenant(tenant_id) as conn:
            # RLS policies will use this tenant_id
            results = await conn.fetch(...)

    For admin/cross-tenant access, pass tenant_id=None.
    """
    db = await store.get_database()
    return db.transaction_with_tenant(tenant_id)


# Dependency for FastAPI routes
async def get_tenant_db(
    request: Request,
    tenant_id: str | None = None,
):
    """FastAPI dependency that provides a database connection with tenant context.

    Usage:
        @router.get("/findings")
        async def list_findings(conn = Depends(get_tenant_db)):
            # conn has tenant context set from request.state.tenant_id
            ...

    Override tenant_id for cross-tenant queries (admin only):
        @router.get("/admin/findings")
        async def list_all_findings(conn = Depends(lambda: get_tenant_db(request, None))):
            ...
    """
    if tenant_id is None:
        tenant_id = getattr(request.state, "tenant_id", None)
        if tenant_id == "anonymous":
            tenant_id = None

    db = await store.get_database()
    async with db.transaction_with_tenant(tenant_id) as conn:
        yield conn

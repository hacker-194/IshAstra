"""The RLS tenant middleware must be installed and must scope each request."""

from __future__ import annotations

import contextvars

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from ishastra.api.app import create_app
from ishastra.api.middleware import RLSTenantMiddleware
from ishastra.core import store


class _FakePostgres:
    def __init__(self) -> None:
        self._tenant: contextvars.ContextVar[str | None] = contextvars.ContextVar(
            "test_rls_tenant", default=None
        )
        self.values: list[str | None] = []

    def is_postgresql(self) -> bool:
        return True

    def set_tenant_context(self, tenant_id: str | None) -> None:
        self.values.append(tenant_id)
        self._tenant.set(tenant_id)

    def get_tenant_context(self) -> str | None:
        return self._tenant.get()


class _SetIdentity(BaseHTTPMiddleware):
    """Stand-in for TenantStateMiddleware, which resolves the API key first."""

    async def dispatch(self, request, call_next):
        request.state.tenant_id = request.headers.get("x-test-tenant", "anonymous")
        return await call_next(request)


def test_rls_tenant_middleware_is_registered() -> None:
    app = create_app()
    assert any(m.cls is RLSTenantMiddleware for m in app.user_middleware)


def test_rls_middleware_scopes_request_and_clears_context(monkeypatch) -> None:
    db = _FakePostgres()

    async def fake_get_database():
        return db

    async def endpoint(request):
        return JSONResponse({"tenant": db.get_tenant_context()})

    monkeypatch.setattr(store, "get_database", fake_get_database)
    app = Starlette(routes=[Route("/", endpoint)])
    app.add_middleware(RLSTenantMiddleware)
    app.add_middleware(_SetIdentity)

    with TestClient(app) as client:
        response = client.get("/", headers={"x-test-tenant": "tenant-a"})
        assert response.json() == {"tenant": "tenant-a"}

        response = client.get("/")
        assert response.json() == {"tenant": None}

    # Middleware sets the validated tenant and clears it in finally.
    assert db.values == ["tenant-a", None, None]

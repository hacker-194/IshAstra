"""Rate limiting must be enforced by the registered application middleware.

Identity for a limit is the validated API key's tenant; callers without a valid
key are counted against their peer address. Changing request headers must never
reset or move the bucket, and liveness probes must keep working.
"""
import pytest
from fastapi.testclient import TestClient

from strix.api.app import app
from strix.api.security import RedisRateLimitMiddleware, api_keys, rate_limiter

client = TestClient(app)

# Anonymous floor: high enough for dashboards, low enough to bound a flood.
ANON_LIMIT = 120
FREE_DEFAULT = 5        # free tier, generic routes
PRO_ASSESS = 20         # pro tier, assessment-creating routes


@pytest.fixture(autouse=True)
def _frozen_clock():
    """Freeze the limiter clock: token refill during a request loop made the
    exhaustion assertions flaky (120 req/min refills ~2 tokens per second)."""
    rate_limiter.reset()
    rate_limiter._clock = lambda: 1_000.0
    yield
    rate_limiter._clock = __import__("time").monotonic
    rate_limiter.reset()


def _auth(name: str, tier: str = "free", *, admin: bool = False):
    key = api_keys.register(name, tier, admin=admin)
    return {"Authorization": f"Bearer {key}"}


def test_rate_limit_middleware_is_registered_on_the_app():
    assert any(m.cls is RedisRateLimitMiddleware for m in app.user_middleware), (
        "RedisRateLimitMiddleware exists but is not wired into the application"
    )


def test_requests_below_the_threshold_succeed():
    headers = _auth("rl-below")
    for _ in range(FREE_DEFAULT):
        assert client.get("/api/overview", headers=headers).status_code == 200


def test_requests_above_the_threshold_get_429():
    headers = _auth("rl-above")
    for _ in range(FREE_DEFAULT):
        assert client.get("/api/overview", headers=headers).status_code == 200

    res = client.get("/api/overview", headers=headers)
    assert res.status_code == 429
    assert res.headers.get("Retry-After")
    assert res.headers.get("X-RateLimit-Limit") == str(FREE_DEFAULT)
    assert res.json()["detail"] == "Rate limit exceeded"


def test_limits_are_separate_per_tenant():
    first, second = _auth("rl-sep-a"), _auth("rl-sep-b")
    for _ in range(FREE_DEFAULT + 1):
        client.get("/api/overview", headers=first)

    assert client.get("/api/overview", headers=first).status_code == 429
    assert client.get("/api/overview", headers=second).status_code == 200


def test_repeated_unauthenticated_requests_are_eventually_limited():
    for _ in range(ANON_LIMIT):
        assert client.get("/api/overview").status_code == 401   # no key: still counted
    assert client.get("/api/overview").status_code == 429


def test_forwarded_identity_headers_cannot_reset_the_anonymous_bucket():
    # A rotating X-Forwarded-For / X-Real-IP must not mint a fresh bucket:
    # the peer address is what counts when no trusted proxy is configured.
    res = None
    for i in range(ANON_LIMIT + 1):
        res = client.get("/api/overview", headers={
            "X-Forwarded-For": f"203.0.113.{i % 250}",
            "X-Real-IP": f"198.51.100.{i % 250}",
            "X-Tenant-ID": "default-soc",
        })
    assert res.status_code == 429


def test_health_and_static_checks_are_never_limited():
    for _ in range(ANON_LIMIT):
        client.get("/api/overview")
    assert client.get("/api/overview").status_code == 429          # bucket exhausted

    assert client.get("/api/health").status_code == 200
    assert client.get("/api/ready").status_code == 200


def test_assessment_creation_has_its_own_stricter_bucket():
    headers = _auth("rl-assess", "pro")   # default pro = 60/min, assessment pro = 20/min
    out_of_scope = {"target": "http://victim.example.net/"}

    for _ in range(PRO_ASSESS):
        res = client.post("/api/assess", json=out_of_scope, headers=headers)
        assert res.status_code == 403      # scope refusal, but the attempt is counted

    res = client.post("/api/assess", json=out_of_scope, headers=headers)
    assert res.status_code == 429

    # The default bucket for the same tenant was not consumed by those attempts.
    assert client.get("/api/overview", headers=headers).status_code == 200


def test_credential_minting_has_its_own_bucket():
    headers = _auth("rl-mint-admin", "enterprise", admin=True)
    mint = {"tenant": "rl-mint-target", "tier": "free"}

    for _ in range(10):
        assert client.post("/api/keys/create", json=mint,
                           headers=headers).status_code == 200
    res = client.post("/api/keys/create", json=mint, headers=headers)
    assert res.status_code == 429

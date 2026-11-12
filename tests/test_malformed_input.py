"""Hostile or malformed URLs must be refused cleanly — never a 500.

Found by fuzzing every route: ``urllib.parse`` raises ValueError for bad ports
and broken IPv6 literals, and nothing used to catch it.
"""
import pytest
from fastapi.testclient import TestClient

from strix.api.app import app
from strix.api.security import api_keys
from strix.core import scope
from strix.core.probe import EndpointProbe
from strix.core.signatures import match_url_signatures
from strix.core.urls import parse_url

client = TestClient(app, raise_server_exceptions=False)

BAD_URLS = [
    "http://example.com:abc/",
    "http://example.com:-1/",
    "http://example.com:99999/",
    "http://[::1",
    "http://[::1]:abc/",
    "http://" + "a" * 300 + ".example.com/",       # over-long DNS label
    "http://exa mple.com/",
    "http://example.com\\@evil.com/",
    "http://evil.com\\@example.com/",          # parser differential: host depends on the parser
    "http://user:pw@example.com/",
    "http://example.com%2f@evil.com/",
    "http://example.com/\npath",
]


@pytest.fixture
def key():
    return {"Authorization": f"Bearer {api_keys.register('fuzz-tenant', 'enterprise', admin=True)}"}


@pytest.mark.parametrize("url", BAD_URLS)
def test_parse_url_never_raises(url):
    parse_url(url)  # a result or None, but no exception


@pytest.mark.parametrize("url", ["http://example.com:abc/", "http://example.com:99999/", "http://[::1"])
def test_unparseable_urls_are_none(url):
    assert parse_url(url) is None


@pytest.mark.parametrize("url", BAD_URLS)
def test_scope_gate_refuses_malformed_targets(url):
    denial, _ = scope.check(url)
    assert denial == "invalid_target"


@pytest.mark.parametrize("url", BAD_URLS)
@pytest.mark.parametrize("path, body", [
    ("/api/assess", lambda u: {"target": u, "wait": True}),
    ("/api/assess", lambda u: {"target": u}),
    ("/api/report", lambda u: {"target": u}),
    ("/api/probe", lambda u: {"url": u}),
    ("/api/monitor/configure", lambda u: {"targets": [u]}),
])
def test_endpoints_return_4xx_for_malformed_targets(key, path, body, url):
    res = client.post(path, json=body(url), headers=key)
    if path == "/api/probe":   # a refused probe is a normal answer: blocked, not graded
        assert res.status_code == 200 and res.json()["blocked"] is True, (url, res.json())
    else:
        assert 400 <= res.status_code < 500, (path, url, res.status_code)


@pytest.mark.parametrize("url", ["http://[::1", "https://example.com:abc/hook", "https://x:99999/"])
def test_webhook_rejects_malformed_urls(key, url):
    res = client.post("/api/alerts/webhook", json={"name": "w", "url": url}, headers=key)
    assert res.status_code == 400


@pytest.mark.parametrize("url", BAD_URLS)
def test_url_signatures_ignore_malformed_urls(url):
    assert match_url_signatures(url) == []


def test_probe_survives_an_unparseable_redirect_from_the_server(local_target):
    result = EndpointProbe(timeout=3).probe(f"{local_target.url}/hostile-redirect")
    assert result["status"] == 302
    assert result["redirect_in_scope"] is False   # judged, never followed


def test_overlong_label_does_not_kill_the_resolver_thread(capfd):
    assert scope.resolve_sync("a" * 300 + ".example.com") == []
    assert "Traceback" not in capfd.readouterr().err

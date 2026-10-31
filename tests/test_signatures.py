"""URL-signature checks: they must flag attack shapes without crying wolf."""
import pytest

from strix.core.signatures import match_url_signatures


@pytest.mark.parametrize("url, expected", [
    ("http://evil.com/?id=1%27%20OR%20%271", {"sqli"}),
    ("http://evil.com/?redirect=http://127.0.0.1", {"open_redirect", "ssrf"}),
    ("http://example.com/?file=../../etc/passwd", {"path_traversal"}),
    ("http://example.com/?q=%3Cscript%3Ealert(1)", {"xss"}),
    ("http://example.com/?api_key=abc123", {"secret"}),
])
def test_detects_attack_shapes(url, expected):
    assert expected <= set(match_url_signatures(url))


@pytest.mark.parametrize("url", [
    "http://example.com/page's",                      # lone apostrophe is not SQLi
    "https://reporting.0.0.0.1.example.com",          # internal-looking host in a domain
    "https://example.com/products/orange",            # keyword inside a word
])
def test_ignores_benign_urls(url):
    assert match_url_signatures(url) == []


@pytest.mark.parametrize("url", ["not a url", "ftp://example.com/?id=1 OR 1", "../../etc/passwd"])
def test_non_http_targets_never_match(url):
    assert match_url_signatures(url) == []

"""DNS and target-scope hardening: rebinding, mixed answers, redirects, pinning."""
import pytest

from strix.core import scope
from strix.core.probe import EndpointProbe

PUBLIC = "93.184.216.34"
HOSTS = ["rebind.example.com", "dual.example.com", "int.example.com",
         "pinned.example.com", "slow.example.com", "internal.corp", "db.internal"]


def _scope(**overrides):
    base = dict(program="dns tests", authorized_by="pytest",
                authorization_ref="dns-test", include=list(HOSTS))
    base.update(overrides)
    return scope.configure(**base)


def _dns(*answers):
    """Monkeypatch scope.resolve_sync with a scripted sequence of answers."""
    calls = {"n": 0}

    def fake(host, port=None):
        answer = answers[min(calls["n"], len(answers) - 1)]
        calls["n"] += 1
        return list(answer)

    return fake


def test_hostname_is_revalidated_at_connect_time(monkeypatch):
    """A name that answers public at check time and internal at connect time
    must be refused at connect — the rebinding pattern."""
    _scope()
    monkeypatch.setattr(scope, "resolve_sync", _dns([PUBLIC], ["10.0.0.5"]))

    assert scope.check("http://rebind.example.com/") == ("", "")          # advisory pass

    denial, reason, dest = scope.destination("http://rebind.example.com/")
    assert denial == "out_of_scope"
    assert dest is None
    assert "10.0.0.5" in reason and "non-public" in reason


@pytest.mark.parametrize("answers", [
    (PUBLIC, "fd00::1"),          # IPv4 public + IPv6 ULA
    ("fd00::1", PUBLIC),          # internal answer first
    (PUBLIC, "10.1.2.3"),         # public + RFC1918
])
def test_mixed_ipv4_ipv6_answers_are_refused_wholesale(monkeypatch, answers):
    _scope()
    monkeypatch.setattr(scope, "resolve_sync", _dns(answers))
    denial, reason, dest = scope.destination("http://dual.example.com/")
    assert denial == "out_of_scope"
    assert dest is None
    assert "non-public" in reason


@pytest.mark.parametrize("target,include", [
    ("http://127.0.0.1/", "127.0.0.1"),              # loopback
    ("http://169.254.169.254/latest/", "169.254.169.254"),  # cloud metadata / link-local
    ("http://224.0.0.1/", "224.0.0.1"),              # multicast
    ("http://0.0.0.0/", "0.0.0.0"),                  # unspecified
    ("http://[fe80::1]/", "fe80::1"),                # IPv6 link-local
    ("http://[ff02::1]/", "ff02::1"),                # IPv6 multicast
    ("http://192.0.2.1/", "192.0.2.1"),              # reserved (TEST-NET-1)
])
def test_special_use_addresses_are_refused_even_when_listed(target, include):
    # Being named in `include` grants host authorization, never address
    # authorization: special-use space needs `authorized_networks`.
    _scope(include=[include])
    denial, reason, dest = scope.destination(target)
    assert denial == "out_of_scope"
    assert dest is None
    assert "non-public" in reason


def test_internal_network_requires_explicit_authorization():
    _scope(include=["int.example.com"])
    monkeypatch_target = "http://int.example.com/"
    original = scope.resolve_sync
    scope.resolve_sync = lambda host, port=None: ["10.0.0.5"]
    try:
        denial, _reason, dest = scope.destination(monkeypatch_target)
        assert denial == "out_of_scope" and dest is None   # not authorized by default

        _scope(include=["int.example.com"], authorized_networks=["10.0.0.0/8"])
        denial, reason, dest = scope.destination(monkeypatch_target)
        assert (denial, reason) == ("", "")
        assert dest is not None and dest.ip == "10.0.0.5"
    finally:
        scope.resolve_sync = original


def test_authorized_internal_hostname_overcomes_internal_suffix(monkeypatch):
    # .internal is an internal suffix (denied by default) but an explicitly
    # authorized network makes an engagement against it possible.
    _scope(include=["db.internal"], authorized_networks=["192.168.0.0/16"])
    monkeypatch.setattr(scope, "resolve_sync", _dns(["192.168.1.9"]))
    assert scope.check("http://db.internal/") == ("", "")

    _scope(include=["db.internal"])
    monkeypatch.setattr(scope, "resolve_sync", _dns(["192.168.1.9"]))
    denial, reason, _dest = scope.destination("http://db.internal/")
    assert denial == "out_of_scope" and "non-public" in reason


def test_unresolvable_name_fails_closed_at_connect(monkeypatch):
    _scope()
    monkeypatch.setattr(scope, "resolve_sync", lambda host, port=None: [])
    # Advisory path: nothing to judge, no connection possible anyway.
    assert scope.check("http://slow.example.com/") == ("", "")
    # Connect path: we are about to open a socket with no validated address.
    denial, reason, dest = scope.destination("http://slow.example.com/")
    assert denial == "resolution_failed"
    assert dest is None and "cannot resolve" in reason


def test_probe_connects_to_the_validated_address_only(monkeypatch, local_target):
    """The connection must go to the validated IP even when the hostname would
    resolve elsewhere: proof that the probe pins, it does not re-resolve."""
    port = int(local_target.url.rsplit(":", 1)[1])
    _scope(include=["pinned.example.com"], authorized_networks=["127.0.0.0/8"])
    monkeypatch.setattr(scope, "resolve_sync", lambda host, p=None: ["127.0.0.1"])

    out = EndpointProbe(timeout=2.0).probe(f"http://pinned.example.com:{port}/?q=hello")
    assert out["status"] == 200                      # reflector answered on the pinned IP
    assert out["body_snippet"] == "hello"


def test_redirect_target_is_scope_checked_but_never_followed(local_target):
    out = EndpointProbe(timeout=2.0).probe(f"{local_target.url}/redirect")
    assert out["status"] == 302
    assert out["redirect_to"] == "/landing"
    assert out["redirect_in_scope"] is True          # same host, still authorized
    assert "/landing" not in local_target.hits       # and was never contacted

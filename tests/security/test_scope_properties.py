"""Property tests for the gate, seeded and dependency-free.

Hypothesis is not installed here and PEP 668 blocks installing it, so the
properties are checked over a deterministic random sample instead: same
invariants, reproducible corpus, no new dependency. Seed changes only if the
property itself changes.
"""

from __future__ import annotations

import random

import pytest

from strix.core import scope as scope_module

SEED = 20261117
URLS = 300


def _scope(**kwargs):
    fields = {
        "program": "Properties",
        "authorized_by": "Test",
        "authorization_ref": "PROP-1",
        "include": ("example.com", "*.example.com"),
        "exclude": ("admin.example.com",),
        "allowed_ports": (443,),
        "authorized_networks": ("93.184.216.0/24",),
    }
    fields.update(kwargs)
    return scope_module.Scope(**fields)


def _random_host(rng: random.Random) -> str:
    labels = ["example", "admin", "api", "test", "evil", "a.b", "exa_mple", "xn--bcher-kva"]
    suffix = rng.choice(["com", "test", "example.com", "internal", ""])
    host = rng.choice(labels)
    return f"{host}.{suffix}" if suffix else host


@pytest.mark.parametrize("seed", [SEED, SEED + 1])
def test_a_host_outside_the_allowlist_is_never_allowed(seed):
    rng = random.Random(seed)
    gate = _scope()
    for _ in range(URLS):
        host = _random_host(rng)
        if gate._listed(host, gate.include) and not gate._listed(host, gate.exclude):
            continue
        denial, _reason = gate.gate(f"https://{host}/")
        assert denial != "", f"{host} was allowed"


def test_an_excluded_host_is_never_allowed():
    gate = _scope()
    assert gate.gate("https://admin.example.com/")[0] == "out_of_scope"
    wildcard_excluded = _scope(exclude=("*.example.com",))
    rng = random.Random(SEED)
    for _ in range(50):
        host = f"{rng.choice(['a', 'b', 'c'])}.example.com"
        assert wildcard_excluded.gate(f"https://{host}/")[0] == "out_of_scope"


def test_a_port_outside_the_policy_is_never_allowed():
    rng = random.Random(SEED)
    gate = _scope()
    for _ in range(URLS):
        port = rng.randint(1, 65535)
        if port == 443:
            continue
        denial, reason = gate.gate(f"https://example.com:{port}/")
        assert denial == "out_of_scope", reason


def test_an_ambiguous_url_is_never_allowed():
    rng = random.Random(SEED)
    gate = _scope()
    fragments = ["\\", "@", "%2f", " ", "\t", "%00", "..", "\r"]
    for _ in range(URLS):
        filler = "".join(rng.choice("abc./") for _ in range(rng.randint(0, 6)))
        raw = f"http://example.com{filler}{rng.choice(fragments)}{filler}/"
        assert gate.gate(raw)[0] != "", raw


def test_a_non_http_scheme_is_never_allowed():
    rng = random.Random(SEED)
    gate = _scope()
    schemes = ["ftp", "file", "gopher", "javascript", "data", "ws", "ldap"]
    for _ in range(URLS):
        assert gate.gate(f"{rng.choice(schemes)}://example.com/")[0] != ""


def test_destination_never_pins_an_unlisted_address(monkeypatch):
    rng = random.Random(SEED)
    scope_module._host_buckets.clear()
    for _ in range(50):
        address = str(scope_module.ipaddress.ip_address(rng.choice([0x0A000001, 0x7F000001, 0xC0A80001])))
        monkeypatch.setattr(scope_module, "resolve_sync", lambda host, port=None, a=address: [a])
        denial, _reason, destination = _scope().destination("https://example.com/")
        assert denial == "out_of_scope"
        assert destination is None

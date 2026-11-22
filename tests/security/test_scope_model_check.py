"""Bounded model check: scope inheritance can only narrow.

The 90-day plan asks for machine-checked formal verification (TLA+/Alloy) of the
inheritance rule. This executable model checks the same property exhaustively
over a finite universe of documents: for every pair of scopes, the merged scope
allows no host, port, network or expiry that either input does not allow.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from ishastra.security.authorization import scope as scope_module

INCLUDES = (
    ("a.example.com",),
    ("a.example.com", "b.example.com"),
    ("*.example.com",),
    ("a.example.com", "*.example.com"),
)
PORTS = ((), (443,), (80, 443))
NETWORKS = ((), ("10.0.0.0/8",), ("10.1.0.0/16",))
EXPIRIES = ("", "2030-01-01T00:00:00+00:00")


def _scope(include, ports, networks, expires_at, exclude=("admin.example.com",)):
    return scope_module.Scope(
        program="Model",
        authorized_by="Test",
        authorization_ref="MODEL-1",
        include=include,
        exclude=exclude,
        allowed_ports=ports,
        authorized_networks=networks,
        expires_at=expires_at,
    )


def _stamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def test_no_pair_of_scopes_can_widen_the_authorization():
    merged_count = 0
    for include_child in INCLUDES:
        for include_parent in INCLUDES:
            for ports_child in PORTS:
                for ports_parent in PORTS:
                    for nets_child in NETWORKS:
                        for nets_parent in NETWORKS:
                            for expiry_child in EXPIRIES:
                                for expiry_parent in EXPIRIES:
                                    child = _scope(include_child, ports_child, nets_child, expiry_child)
                                    parent = _scope(include_parent, ports_parent, nets_parent, expiry_parent)
                                    try:
                                        merged = child.inherited_from(parent)
                                    except ValueError:
                                        continue
                                    merged_count += 1
                                    _assert_narrower(merged, child, parent, ports_child, ports_parent)
                                    _assert_networks(merged, nets_child, nets_parent)
                                    _assert_expiry(merged, expiry_child, expiry_parent)
    assert merged_count > 100, "the model checked too few merges to mean anything"


def _assert_narrower(merged, child, parent, ports_child, ports_parent):
    assert set(merged.include) <= set(child.include)
    for pattern in merged.include:
        assert any(scope_module._pattern_covers(allowed, pattern) for allowed in parent.include), (
            f"{pattern} is not covered by the parent's {parent.include}"
        )
    assert merged.include, "a merged scope must never have an empty include list"
    if ports_child and ports_parent:
        assert set(merged.allowed_ports) <= set(ports_child) & set(ports_parent)
    else:
        assert merged.allowed_ports == (ports_child or ports_parent)
    assert merged.revoked == (child.revoked or parent.revoked)


def _assert_networks(merged, nets_child, nets_parent):
    if not nets_child or not nets_parent:
        assert merged.authorized_networks == ()
        return
    for entry in merged.authorized_networks:
        network = scope_module.ipaddress.ip_network(entry, strict=False)
        for side in (nets_child, nets_parent):
            assert any(
                network.subnet_of(scope_module.ipaddress.ip_network(other, strict=False)) for other in side
            ), f"{entry} is wider than something {side} allows"


def _assert_expiry(merged, expiry_child, expiry_parent):
    if expiry_child and expiry_parent:
        assert _stamp(merged.expires_at) == min(_stamp(expiry_child), _stamp(expiry_parent))
    else:
        assert merged.expires_at == (expiry_child or expiry_parent)


def test_a_disjoint_pair_is_refused_rather_than_emptied():
    with pytest.raises(ValueError):
        _scope(("a.example.com",), (443,), (), "").inherited_from(_scope(("b.example.com",), (8443,), (), ""))

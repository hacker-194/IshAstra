"""Reproducible property tests for scope allow/deny invariants."""

from __future__ import annotations

import ipaddress
import string
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from ishastra.security.authorization import scope as scope_module

PROPERTY_SETTINGS = settings(max_examples=100, derandomize=True, deadline=None)
LABELS = st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=16)
AUTHORIZED_NETWORK = ipaddress.ip_network("93.184.216.0/24")


def _scope(**kwargs):
    fields = {
        "program": "Properties",
        "authorized_by": "Test",
        "authorization_ref": "PROP-1",
        "include": ("example.com", "*.example.com"),
        "exclude": ("admin.example.com",),
        "allowed_ports": (443,),
        "authorized_networks": (str(AUTHORIZED_NETWORK),),
    }
    fields.update(kwargs)
    return scope_module.Scope(**fields)


@PROPERTY_SETTINGS
@given(host=LABELS.map(lambda label: f"{label}.outside.test"))
def test_hosts_outside_the_allowlist_are_denied(host):
    assert _scope().gate(f"https://{host}/")[0] == "out_of_scope"


@PROPERTY_SETTINGS
@given(label=LABELS)
def test_wildcards_match_subdomains_but_not_the_apex(label):
    gate = _scope(include=("*.example.com",), exclude=())
    assert gate.gate(f"https://{label}.example.com/")[0] == ""
    assert gate.gate("https://example.com/")[0] == "out_of_scope"


@PROPERTY_SETTINGS
@given(label=LABELS)
def test_explicit_exclusions_take_precedence_over_wildcard_includes(label):
    gate = _scope(include=("*.example.com",), exclude=(f"{label}.example.com",))
    assert gate.gate(f"https://{label}.example.com/")[0] == "out_of_scope"


@PROPERTY_SETTINGS
@given(port=st.integers(min_value=1, max_value=65535).filter(lambda value: value != 443))
def test_ports_outside_the_policy_are_denied(port):
    assert _scope().gate(f"https://example.com:{port}/")[0] == "out_of_scope"


@PROPERTY_SETTINGS
@given(scheme=st.sampled_from(("ftp", "file", "gopher", "javascript", "data", "ws", "ldap")))
def test_non_http_schemes_are_denied(scheme):
    assert _scope().gate(f"{scheme}://example.com/")[0] == "invalid_target"


@PROPERTY_SETTINGS
@given(marker=st.sampled_from(("\\", "@", "%2f", " ", "\t", "%00", "..", "\r")))
def test_ambiguous_urls_are_denied(marker):
    assert _scope().gate(f"http://example.com{marker}/")[0] != ""


@PROPERTY_SETTINGS
@given(address=st.ip_addresses(v=4).filter(lambda value: value not in AUTHORIZED_NETWORK))
def test_destinations_never_pin_an_address_outside_the_authorized_network(address):
    with (
        patch.object(scope_module, "_host_buckets", {}),
        patch.object(scope_module, "resolve_sync", return_value=[str(address)]),
    ):
        denial, _reason, destination = _scope().destination("https://example.com/")
    assert denial == "out_of_scope"
    assert destination is None


@PROPERTY_SETTINGS
@given(
    address=st.integers(
        min_value=int(AUTHORIZED_NETWORK.network_address),
        max_value=int(AUTHORIZED_NETWORK.broadcast_address),
    ).map(ipaddress.IPv4Address)
)
def test_authorized_network_addresses_can_be_pinned(address):
    with (
        patch.object(scope_module, "_host_buckets", {}),
        patch.object(scope_module, "resolve_sync", return_value=[str(address)]),
    ):
        denial, _reason, destination = _scope().destination("https://example.com/")
    assert denial == ""
    assert destination is not None
    assert destination.ip == str(address)

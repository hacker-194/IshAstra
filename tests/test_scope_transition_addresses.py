"""IPv6 transition addresses embed an IPv4 destination; scope must judge it.

NAT64 (64:ff9b::/96), 6to4 (2002::/16), Teredo (2001::/32) and IPv4-mapped
addresses can all reach an internal IPv4 host while looking like an ordinary
IPv6 address (Python 3.14 marks 64:ff9b::/96 as global). A DNS answer using one
of them must be refused exactly like the IPv4 address it carries.
"""
import ipaddress

import pytest

from strix.core import scope


@pytest.mark.parametrize("literal,expected", [
    ("64:ff9b::a00:1", "10.0.0.1"),
    ("64:ff9b::7f00:1", "127.0.0.1"),
    ("2002:7f00:1::1", "127.0.0.1"),
    ("2002:a9fe:a9fe::1", "169.254.169.254"),
    ("2001:0:4136:e378:8000:63bf:3fff:fdd2", "192.0.2.45"),
    ("::ffff:10.1.2.3", "10.1.2.3"),
])
def test_embedded_ipv4_is_extracted(literal, expected):
    assert str(scope.embedded_ipv4(ipaddress.ip_address(literal))) == expected


def test_plain_addresses_embed_nothing():
    assert scope.embedded_ipv4(ipaddress.ip_address("93.184.216.34")) is None
    assert scope.embedded_ipv4(ipaddress.ip_address("2606:2800:220:1::1")) is None


@pytest.mark.parametrize("literal", [
    "64:ff9b::a00:1",            # NAT64 -> 10.0.0.1
    "64:ff9b::7f00:1",           # NAT64 -> loopback
    "64:ff9b::a9fe:a9fe",        # NAT64 -> cloud metadata
    "2002:7f00:1::1",            # 6to4 -> loopback
    "2002:a9fe:a9fe::",          # 6to4 -> metadata
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",   # Teredo
    "::ffff:169.254.169.254",    # mapped metadata
])
def test_transition_addresses_to_internal_hosts_are_special_use(literal):
    assert scope.is_special_use(ipaddress.ip_address(literal))


def test_transition_address_to_a_public_host_is_not_internal():
    # 64:ff9b::5db8:d822 -> 93.184.216.34: an honest NAT64 answer must not be
    # judged internal merely because it is a transition address. (Whether the
    # prefix itself is refused is a separate, standard-library policy question:
    # CPython 3.14 marks 64:ff9b::/96 both global and reserved.)
    nat64_public = ipaddress.ip_address("64:ff9b::5db8:d822")
    assert not scope.embedded_is_special_use(nat64_public)
    assert not scope.is_special_use(ipaddress.ip_address("::ffff:93.184.216.34"))


def test_gate_refuses_hostname_resolving_to_nat64_private(monkeypatch):
    """End-to-end: a rebinding-shaped answer through NAT64 is out of scope."""
    scope.configure(program="p", authorized_by="a", authorization_ref="r",
                    include=["rebind.example"])
    monkeypatch.setattr(scope, "resolve_sync",
                        lambda host, port=None: ["64:ff9b::a00:1"])
    denial, reason = scope.check("http://rebind.example/")
    assert denial == "out_of_scope"
    assert "non-public" in reason
    assert scope.destination("http://rebind.example/")[2] is None

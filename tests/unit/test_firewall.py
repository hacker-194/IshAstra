"""Host firewall plan tests.

These prove the generated rules are deny-by-default for the worker subnet.
They do NOT prove the kernel enforces them: applying needs root + nftables,
which this environment may not have. See EGRESS_ENFORCEMENT.md.
"""

from __future__ import annotations

import pytest

from ishastra.security.egress import firewall
from ishastra.security.egress.firewall import FirewallPlan


def _plan(**overrides) -> FirewallPlan:
    values = {
        "worker_subnet": "172.30.0.0/24",
        "gateway_ip": "172.30.0.2",
        "gateway_port": 8080,
    }
    values.update(overrides)
    return FirewallPlan(**values)


def test_worker_may_only_reach_the_gateway_port() -> None:
    script = firewall.render_nft_script(_plan())

    allow = "ip saddr 172.30.0.0/24 ip daddr 172.30.0.2 tcp dport 8080 accept"
    drop = "ip saddr 172.30.0.0/24 drop"
    assert allow in script
    assert drop in script
    assert script.index(allow) < script.index(drop)


def test_metadata_addresses_are_dropped() -> None:
    script = firewall.render_nft_script(_plan())
    assert "ip daddr 169.254.169.254 drop" in script
    assert "ip daddr 169.254.170.2 drop" in script
    assert "ip daddr 100.100.100.200 drop" in script

    v6 = firewall.render_nft_script(_plan(worker_subnet="fd00:1::/64", gateway_ip="fd00:1::2"))
    assert "ip6 daddr fd00:ec2::254 drop" in v6


def test_no_blanket_allow_rule() -> None:
    script = firewall.render_nft_script(_plan())
    assert "0.0.0.0/0" not in script
    assert "::/0" not in script
    assert "tcp dport 8080 accept" in script
    worker_accepts = [line for line in script.splitlines() if "172.30.0.0/24" in line and "accept" in line]
    assert worker_accepts == ["    ip saddr 172.30.0.0/24 ip daddr 172.30.0.2 tcp dport 8080 accept"]


def test_ipv6_plan_uses_ip6_selectors() -> None:
    script = firewall.render_nft_script(_plan(worker_subnet="fd00:1::/64", gateway_ip="fd00:1::2"))
    assert "ip6 saddr fd00:1::/64 ip6 daddr fd00:1::2 tcp dport 8080 accept" in script
    assert "ip6 saddr fd00:1::/64 drop" in script


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"worker_subnet": "0.0.0.0/0"}, "must not be"),
        ({"worker_subnet": "::/0"}, "must not be"),
        ({"gateway_port": 0}, "between 1 and 65535"),
        ({"gateway_port": 70000}, "between 1 and 65535"),
        ({"worker_subnet": "fd00:1::/64"}, "address family"),
        ({"gateway_ip": "169.254.169.254"}, "metadata"),
    ],
)
def test_invalid_plans_are_rejected(overrides: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _plan(**overrides)


def test_dry_run_returns_the_script_without_applying() -> None:
    result = firewall.apply(_plan(), dry_run=True)
    assert result.applied is True
    assert "rules were not applied" in result.reason
    assert result.commands and "table inet ishastra_egress" in result.commands[0]


def test_apply_requires_root(monkeypatch) -> None:
    monkeypatch.setattr(firewall, "_is_root", lambda: False)
    result = firewall.apply(_plan())
    assert result.applied is False
    assert "root" in result.reason


def test_apply_fails_closed_without_posix_euid(monkeypatch) -> None:
    monkeypatch.setattr(firewall, "_is_root", lambda: None)
    result = firewall.apply(_plan())
    assert result.applied is False
    assert "POSIX" in result.reason


def test_apply_fails_closed_on_windows(monkeypatch) -> None:
    monkeypatch.setattr(firewall.os, "name", "nt")
    result = firewall.apply(_plan())
    assert result.applied is False
    assert "Linux-only" in result.reason


def test_dry_run_works_on_any_platform(monkeypatch) -> None:
    monkeypatch.setattr(firewall.os, "name", "nt")
    result = firewall.apply(_plan(), dry_run=True)
    assert result.applied is True
    assert result.commands


def test_apply_reports_missing_nft(monkeypatch) -> None:
    monkeypatch.setattr(firewall, "_is_root", lambda: True)
    monkeypatch.setattr(firewall.shutil, "which", lambda _name: None)
    result = firewall.apply(_plan())
    assert result.applied is False
    assert "not installed" in result.reason


def test_docker_user_accept_precedes_drop() -> None:
    commands = firewall.docker_user_commands(_plan())
    assert commands[0][:4] == ("iptables", "-A", "DOCKER-USER", "-s")
    joined = [" ".join(command) for command in commands]
    assert joined[0].endswith("-j ACCEPT")
    assert joined[1].endswith("-j DROP")
    assert len(commands) == 2


def test_teardown_deletes_the_table() -> None:
    assert firewall.render_teardown_script() == "delete table inet ishastra_egress\n"

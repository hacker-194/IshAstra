"""Every shipped adapter declares a valid contract (v4.0 section 8)."""

from __future__ import annotations

import pytest

from ishastra.core.adapter_base import Adapter, validate_contract
from ishastra.core.adapters import ADAPTERS, PROFILES


def test_every_builtin_and_plugin_adapter_declares_a_valid_contract() -> None:
    for adapter in ADAPTERS.values():
        validate_contract(adapter)
        contract = adapter.contract()
        assert contract["id"] == adapter.id
        assert contract["protocols"]
        assert contract["scan_modes"]
        assert contract["enforcement"] in {"proxy", "firewall", "none"}


def test_adapter_info_exposes_the_contract() -> None:
    adapter = ADAPTERS["nuclei"]
    assert adapter.info()["contract"] == adapter.contract()
    assert adapter.info()["contract"]["enforcement"] in {"proxy", "firewall", "none"}


def test_every_profile_only_references_declared_adapters() -> None:
    for profile, ids in PROFILES.items():
        assert ids, f"profile {profile!r} is empty"
        for adapter_id in ids:
            assert adapter_id in ADAPTERS, f"{profile!r} references unknown {adapter_id!r}"


def test_contract_validation_rejects_unknown_enforcement() -> None:
    class BadEnforcement(Adapter):
        id = "bad-enforcement"
        enforcement = "vibes"

    with pytest.raises(ValueError, match="unknown enforcement"):
        validate_contract(BadEnforcement())


def test_contract_validation_rejects_unsupported_protocol_and_mode() -> None:
    class BadProtocol(Adapter):
        id = "bad-protocol"
        protocols = ("sctp",)

    class BadMode(Adapter):
        id = "bad-mode"
        scan_modes = ("syn",)

    with pytest.raises(ValueError, match="unsupported protocol"):
        validate_contract(BadProtocol())
    with pytest.raises(ValueError, match="unsupported scan mode"):
        validate_contract(BadMode())


def test_contract_validation_rejects_missing_id_and_bad_timeout() -> None:
    class NoId(Adapter):
        id = " "

    class NoTimeout(Adapter):
        id = "no-timeout"
        timeout = 0

    with pytest.raises(ValueError, match="non-empty id"):
        validate_contract(NoId())
    with pytest.raises(ValueError, match="positive timeout"):
        validate_contract(NoTimeout())

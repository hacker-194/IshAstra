"""Deployment-supplied ASN/GeoIP tables from ``ISHASTRA_SCOPE_INTEL_FILE``."""

from __future__ import annotations

import json

import pytest

from ishastra.core import scope as scope_module


@pytest.fixture(autouse=True)
def clean_intel(monkeypatch):
    scope_module.register_intel()
    monkeypatch.delenv(scope_module.SCOPE_INTEL_FILE_ENV, raising=False)
    yield
    scope_module.register_intel()


def _intel_file(tmp_path, payload):
    path = tmp_path / "intel.json"
    path.write_text(json.dumps(payload))
    return path


def _gate(**kwargs):
    fields = {
        "program": "Intel env",
        "authorized_by": "Test",
        "authorization_ref": "INTEL-ENV-1",
        "include": ("example.com",),
    }
    fields.update(kwargs)
    return scope_module.Scope(**fields)


def test_a_table_is_installed_from_the_env_file(tmp_path, monkeypatch):
    path = _intel_file(
        tmp_path,
        {"asn": {"93.184.216.0/24": 15133}, "country": {"93.184.216.0/24": "us"}},
    )
    monkeypatch.setenv(scope_module.SCOPE_INTEL_FILE_ENV, str(path))

    assert scope_module.configure_intel_from_env() is True

    gate = _gate(allowed_asns=(15133,), allowed_countries=("US",))
    assert gate._judge_addresses("example.com", ["93.184.216.34"]) == ("", "")


def test_the_longest_prefix_wins(tmp_path, monkeypatch):
    path = _intel_file(tmp_path, {"asn": {"0.0.0.0/0": 64500, "93.184.216.0/24": 15133}})
    monkeypatch.setenv(scope_module.SCOPE_INTEL_FILE_ENV, str(path))
    scope_module.configure_intel_from_env()

    assert _gate(allowed_asns=(15133,))._judge_addresses("example.com", ["93.184.216.34"])[0] == ""
    denial, reason = _gate(allowed_asns=(15133,))._judge_addresses("example.com", ["8.8.8.8"])
    assert denial == "out_of_scope"
    assert "AS64500" in reason


def test_an_address_outside_every_prefix_is_refused(tmp_path, monkeypatch):
    path = _intel_file(tmp_path, {"country": {"93.184.216.0/24": "US"}})
    monkeypatch.setenv(scope_module.SCOPE_INTEL_FILE_ENV, str(path))
    scope_module.configure_intel_from_env()

    denial, _reason = _gate(allowed_countries=("US",))._judge_addresses("example.com", ["8.8.8.8"])
    assert denial == "policy_unavailable"


def test_a_malformed_file_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "intel.json"
    path.write_text('{"asn": {"not-a-prefix": 1}}')
    monkeypatch.setenv(scope_module.SCOPE_INTEL_FILE_ENV, str(path))
    with pytest.raises(ValueError, match="not a CIDR prefix"):
        scope_module.configure_intel_from_env()

    path.write_text('{"country": {"93.184.216.0/24": "Nepal"}}')
    with pytest.raises(ValueError, match="alpha-2"):
        scope_module.configure_intel_from_env()

    path.write_text("{not json")
    with pytest.raises(ValueError, match="unreadable"):
        scope_module.configure_intel_from_env()


def test_no_file_configured_is_a_no_op(monkeypatch):
    assert scope_module.configure_intel_from_env() is False

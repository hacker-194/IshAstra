"""ASN and country policy: an unusable data source denies, never allows."""

from __future__ import annotations

import json

import pytest

from strix.core import scope as scope_module


@pytest.fixture(autouse=True)
def clean_intel():
    scope_module.register_intel()
    yield
    scope_module.register_intel()


def _scope(**kwargs):
    fields = {
        "program": "Intel",
        "authorized_by": "Test",
        "authorization_ref": "INTEL-1",
        "include": ("example.com",),
        "authorized_networks": ("93.184.216.0/24",),
    }
    fields.update(kwargs)
    return scope_module.Scope(**fields)


ADDRESSES = ["93.184.216.34"]


class TestAsnPolicy:
    def test_an_authorized_asn_is_allowed(self):
        scope_module.register_intel(asn=lambda ip: 15133)
        assert _scope(allowed_asns=(15133,))._judge_addresses("example.com", ADDRESSES) == ("", "")

    def test_another_asn_is_refused(self):
        scope_module.register_intel(asn=lambda ip: 64500)
        denial, reason = _scope(allowed_asns=(15133,))._judge_addresses("example.com", ADDRESSES)
        assert denial == "out_of_scope"
        assert "AS64500" in reason

    def test_no_data_source_refuses_rather_than_allows(self):
        denial, reason = _scope(allowed_asns=(15133,))._judge_addresses("example.com", ADDRESSES)
        assert denial == "policy_unavailable"
        assert "no ASN lookup" in reason

    def test_an_address_without_data_is_refused(self):
        scope_module.register_intel(asn=lambda ip: None)
        denial, _reason = _scope(allowed_asns=(15133,))._judge_addresses("example.com", ADDRESSES)
        assert denial == "policy_unavailable"

    def test_a_failing_lookup_is_refused(self):
        def boom(_ip):
            raise RuntimeError("origin table missing")

        scope_module.register_intel(asn=boom)
        denial, _reason = _scope(allowed_asns=(15133,))._judge_addresses("example.com", ADDRESSES)
        assert denial == "policy_unavailable"


class TestCountryPolicy:
    def test_an_authorized_country_is_allowed(self):
        scope_module.register_intel(country=lambda ip: "np")
        assert _scope(allowed_countries=("NP",))._judge_addresses("example.com", ADDRESSES) == ("", "")

    def test_a_foreign_country_is_refused(self):
        scope_module.register_intel(country=lambda ip: "RU")
        denial, reason = _scope(allowed_countries=("NP",))._judge_addresses("example.com", ADDRESSES)
        assert denial == "out_of_scope"
        assert "geolocated to RU" in reason

    def test_a_missing_country_is_refused(self):
        scope_module.register_intel(country=lambda ip: None)
        denial, _reason = _scope(allowed_countries=("NP",))._judge_addresses("example.com", ADDRESSES)
        assert denial == "policy_unavailable"


class TestIntelDocumentsAndInheritance:
    def test_invalid_values_are_refused(self):
        with pytest.raises(ValueError, match="positive AS numbers"):
            _scope(allowed_asns=(0,))
        with pytest.raises(ValueError, match="alpha-2"):
            _scope(allowed_countries=("nepal",))

    def test_a_v2_document_carries_the_policy(self):
        document = {
            "version": 2,
            "program": "Doc",
            "authorized_by": "Test",
            "authorization_ref": "DOC-1",
            "include": ["example.com"],
            "allowed_asns": [15133],
            "allowed_countries": ["np"],
        }
        scope = scope_module.parse_scope_document(document)
        assert scope.allowed_asns == (15133,)
        assert scope.allowed_countries == ("NP",)

    def test_a_malformed_document_is_refused(self):
        document = {
            "version": 2,
            "program": "Doc",
            "authorized_by": "Test",
            "authorization_ref": "DOC-2",
            "include": ["example.com"],
            "allowed_asns": [0],
        }
        with pytest.raises(ValueError, match="validation failed"):
            scope_module.parse_scope_document(document)

    def test_inheritance_intersects_asn_and_country(self):
        child = _scope(allowed_asns=(15133, 64500), allowed_countries=("NP", "IN"))
        base = _scope(allowed_asns=(15133,), allowed_countries=("NP",))
        merged = child.inherited_from(base)
        assert merged.allowed_asns == (15133,)
        assert merged.allowed_countries == ("NP",)

    def test_disjoint_asn_lists_raise(self):
        with pytest.raises(ValueError, match="allows no ASN"):
            _scope(allowed_asns=(64500,)).inherited_from(_scope(allowed_asns=(15133,)))

    def test_an_empty_side_means_no_asn_policy(self):
        assert _scope().inherited_from(_scope(allowed_asns=(15133,))).allowed_asns == (15133,)

    def test_a_deployment_without_a_lookup_refuses_to_start(self, tmp_path):
        from strix.core import scope as module

        document = tmp_path / "scope.json"
        document.write_text(
            json.dumps(
                {
                    "version": 2,
                    "program": "Deploy",
                    "authorized_by": "Test",
                    "authorization_ref": "DEPLOY-1",
                    "include": ["example.com"],
                    "allowed_asns": [15133],
                }
            )
        )
        with pytest.raises(ValueError, match="not configured"):
            module.load(document)

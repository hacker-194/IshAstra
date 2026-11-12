"""Scope configuration validation: strict schema, fail-closed, atomic reload.

A syntactically valid JSON document with the wrong *shape* must never become
an authorization: a JSON array, a typo'd field name, a string where a list
belongs — each is a refusal with an actionable message, never an unhandled
exception and never a silently unrestricted policy.
"""
import json

import pytest

from strix.core import scope

VALID = {
    "program": "Example program",
    "authorized_by": "Jane Analyst",
    "authorization_ref": "eng-1",
    "include": ["example.com"],
}


def write(tmp_path, payload):
    path = tmp_path / "scope.json"
    if isinstance(payload, (dict, list, int, bool)) or payload is None:
        path.write_text(json.dumps(payload), encoding="utf-8")
    else:
        path.write_text(payload, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Structural refusals
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("document", [
    [VALID],                     # a JSON array: valid JSON, wrong shape
    42,
    None,
    True,
])
def test_non_object_documents_are_refused_not_crashed_on(tmp_path, document):
    with pytest.raises(ValueError) as excinfo:
        scope.load(write(tmp_path, document))
    assert "JSON object" in str(excinfo.value)


def test_unknown_fields_are_refused_with_their_names(tmp_path):
    document = {**VALID, "inlcude": ["example.com"]}     # classic typo
    with pytest.raises(ValueError) as excinfo:
        scope.load(write(tmp_path, document))
    assert "inlcude" in str(excinfo.value)


def test_missing_required_fields_are_refused(tmp_path):
    for key in ("program", "authorized_by", "authorization_ref", "include"):
        document = {k: v for k, v in VALID.items() if k != key}
        with pytest.raises(ValueError, match=key):
            scope.load(write(tmp_path, document))


@pytest.mark.parametrize("patch", [
    {"include": "example.com"},                 # string, not list
    {"include": []},                            # empty: nothing is authorized
    {"include": [7]},
    {"exclude": "billing.example.com"},
    {"authorized_networks": "10.0.0.0/8"},
    {"authorized_networks": [42]},
    {"allowed_ports": [80, "443"]},
    {"allowed_ports": [0]},
    {"allowed_ports": [70000]},
    {"allowed_ports": [True]},
    {"program": 3},
    {"allow_broad_networks": 1},                # int, not a JSON boolean
    {"auth": ["nope"]},
    {"collab": "127.0.0.1"},
])
def test_wrong_field_types_are_refused(tmp_path, patch):
    with pytest.raises(ValueError):
        scope.load(write(tmp_path, {**VALID, **patch}))


@pytest.mark.parametrize("host", ["-iL.example.com", "bad host.com", "", "*.spa ce.com"])
def test_invalid_host_patterns_are_refused(tmp_path, host):
    with pytest.raises(ValueError, match="host"):
        scope.load(write(tmp_path, {**VALID, "include": [host]}))


def test_invalid_cidr_entries_are_refused(tmp_path):
    with pytest.raises(ValueError, match="CIDR"):
        scope.load(write(tmp_path, {**VALID, "authorized_networks": ["10.0.0.0/999"]}))


def test_malformed_json_is_a_valueerror_with_location(tmp_path):
    with pytest.raises(ValueError) as excinfo:
        scope.load(write(tmp_path, '{"program": "x", '))
    assert "line 1" in str(excinfo.value)


def test_malformed_auth_block_fails_the_whole_document(tmp_path):
    document = {**VALID, "auth": {"users": [{"id": "u1"}]}}   # no credentials
    with pytest.raises(ValueError, match="auth"):
        scope.load(write(tmp_path, document))


def test_broad_cidr_refused_unless_explicitly_overridden(tmp_path):
    document = {**VALID, "authorized_networks": ["0.0.0.0/0"]}
    with pytest.raises(ValueError, match="broad"):
        scope.load(write(tmp_path, document))
    document["allow_broad_networks"] = True
    installed = scope.load(write(tmp_path, document))
    assert installed.allow_broad_networks is True
    scope._active = None


def test_ipv4_mapped_ipv6_networks_are_refused(tmp_path):
    with pytest.raises(ValueError, match="IPv4-mapped"):
        scope.load(write(tmp_path, {**VALID, "authorized_networks": ["::ffff:0:0/96"]}))


# ---------------------------------------------------------------------------
# Atomic reload semantics
# ---------------------------------------------------------------------------
def test_valid_document_installs_and_binds_fields(tmp_path):
    document = {**VALID, "allowed_ports": [80, 443], "exclude": ["billing.example.com"]}
    installed = scope.load(write(tmp_path, document))
    assert installed.program == "Example program"
    assert installed.allowed_ports == (80, 443)
    assert installed.exclude == ("billing.example.com",)
    assert scope.active() is installed
    assert scope.check("http://example.com:8080/") == (
        "out_of_scope", "port 8080 is not in the authorized port scope")
    scope._active = None


def test_failed_reload_keeps_the_previous_configuration(tmp_path):
    first = scope.load(write(tmp_path, VALID))
    assert scope.active() is first
    # A reload that fails validation must not disturb the active authorization
    # (and must not silently widen it either): the caller decides fail-closed.
    with pytest.raises(ValueError):
        scope.load(write(tmp_path, [VALID, VALID]))
    assert scope.active() is first
    assert scope.active().program == "Example program"
    scope._active = None


def test_missing_file_returns_none_and_leaves_the_active_scope(tmp_path):
    installed = scope.configure(**{**VALID, "include": ["example.com"]})
    assert scope.load(tmp_path / "absent.json") is None
    assert scope.active() is installed
    scope._active = None


def test_port_zero_target_is_refused(tmp_path):
    scope.load(write(tmp_path, VALID))
    denial, reason = scope.check("http://example.com:0/")
    assert denial == "invalid_target" and "port 0" in reason
    scope._active = None


def test_unparseable_target_still_refused_under_strict_loading(tmp_path):
    scope.load(write(tmp_path, VALID))
    for url in ("http://example.com\\@evil.com/", "http://u:p@example.com/",
                "ftp://example.com/"):
        denial, _reason = scope.check(url)
        assert denial in ("invalid_target", "out_of_scope"), url
    scope._active = None


def test_parse_scope_document_is_exported_for_admin_paths():
    """The API layer reuses the exact same validator — no second parser."""
    with pytest.raises(ValueError):
        scope.parse_scope_document([VALID])
    installed = scope.parse_scope_document(dict(VALID))
    assert installed.program == "Example program"
    scope._active = None

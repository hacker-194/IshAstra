"""Nepal sector templates must stay client-scoped and must not overwrite files."""

import argparse
import json

from strix.cli import _run_scope_template
from strix.core.evidence import get_scope_template


def test_sector_templates_are_client_scoped():
    for sector in ("bank", "telco", "gov", "global"):
        template = get_scope_template(sector)
        assert template is not None
        assert template["authorized_networks"] == []
        assert template["allow_broad_networks"] is False
        # Shared suffixes would authorize unrelated third-party hosts.
        assert not {"*.com.np", "*.org.np", "*.gov.np"} & set(template["include"])
        assert all("*" not in pattern for pattern in template["exclude"])
        assert "REPLACE" in template["authorized_by"]


def test_domain_substitution_preserves_subdomains_and_dedupes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "bank.json"
    args = argparse.Namespace(
        sector="bank", domain="testbank.com.np", output=str(output)
    )

    assert _run_scope_template(args) == 0

    data = json.loads(output.read_text())
    assert data["include"] == [
        "*.testbank.com.np",
        "api.testbank.com.np",
        "mobile.testbank.com.np",
    ]
    assert len(set(data["include"])) == len(data["include"])
    assert all(pattern.endswith("testbank.com.np") for pattern in data["exclude"])
    # Generating a template must not clobber ./scope.json as a side effect.
    assert not (tmp_path / "scope.json").exists()

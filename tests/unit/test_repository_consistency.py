"""Cross-file release consistency guards.

These tests do not exercise runtime behaviour; they fail when packaging,
deployment or documentation artefacts drift away from the application.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENV_TEMPLATES = (".env.example", ".env.production.example", ".env.staging.example")
_ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]*)\s*=", re.MULTILINE)
_ENV_REFERENCE = re.compile(r"ISHASTRA_[A-Z0-9_]+")
_SCOPE_MODE = re.compile(r"^ISHASTRA_SCOPE_MODE\s*=\s*(\S+)", re.MULTILINE)
_QUEUE_MODE = re.compile(r"^ISHASTRA_QUEUE_MODE\s*=\s*(\S+)", re.MULTILINE)

_SCOPE_MODES = {"auto", "global", "managed"}
_QUEUE_MODES = {"inprocess", "redis-streams", "sqlite", "postgres", "k8s-jobs"}


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _documented_ishastra_vars() -> set[str]:
    documented: set[str] = set()
    for template in ENV_TEMPLATES:
        documented.update(
            name for name in _ASSIGNMENT.findall(_read(template)) if name.startswith("ISHASTRA_")
        )
    return documented


def _referenced_in_source() -> set[str]:
    referenced: set[str] = set()
    for path in (ROOT / "src").rglob("*.py"):
        referenced.update(_ENV_REFERENCE.findall(path.read_text(encoding="utf-8")))
    return referenced


def test_documented_env_vars_are_read_by_the_application() -> None:
    undocumented = _documented_ishastra_vars() - _referenced_in_source()
    assert not undocumented, f"documented but never read: {sorted(undocumented)}"


def test_env_templates_drop_the_legacy_strix_namespace() -> None:
    for template in ENV_TEMPLATES:
        assert "strix" not in _read(template).lower(), template


@pytest.mark.parametrize("template", ENV_TEMPLATES)
def test_scope_and_queue_modes_in_templates_are_accepted(template: str) -> None:
    text = _read(template)
    for value in _SCOPE_MODE.findall(text):
        assert value in _SCOPE_MODES, f"{template}: ISHASTRA_SCOPE_MODE={value}"
    for value in _QUEUE_MODE.findall(text):
        assert value in _QUEUE_MODES, f"{template}: ISHASTRA_QUEUE_MODE={value}"


def test_production_template_carries_every_required_secret() -> None:
    text = _read(".env.production.example")
    for name in ("ISHASTRA_API_KEY", "ISHASTRA_AUDIT_HMAC_KEY", "ISHASTRA_ENCRYPTION_KEY"):
        assert re.search(rf"^{name}=", text, re.MULTILINE), name


def test_compose_has_no_default_credentials() -> None:
    text = _read("docker-compose.yml")
    for name in ("POSTGRES_PASSWORD", "GRAFANA_PASSWORD", "KEYCLOAK_ADMIN_PASSWORD"):
        assert f"${{{name}:?" in text, f"{name} must be required, not defaulted"
    for weak in ("ishastra_dev_password", "GRAFANA_PASSWORD:-admin", "local-only-change-me"):
        assert weak not in text, f"insecure default credential: {weak}"


def test_action_can_install_without_a_pypi_release() -> None:
    text = _read("action.yml")
    assert "github.action_path" in text
    assert "ishastra-version:\n    description:" in text
    assert 'default: "3.5.0"' not in text


def test_action_invokes_the_assess_run_subcommand() -> None:
    text = _read("action.yml")
    assert "ishastra assess run" in text
    assert "ishastra assess --target" not in text


def test_api_reference_uses_the_live_api_prefix() -> None:
    for path in (ROOT / "docs" / "api").glob("*.md"):
        text = path.read_text(encoding="utf-8")
        assert "/api/v1" not in text, f"{path.name} documents a removed API prefix"


def test_helm_role_cannot_write_services_or_endpoints() -> None:
    import yaml

    values = yaml.safe_load(_read("deploy/helm/ishastra/values.yaml"))
    rules = values["rbac"]["roleRules"]
    for rule in rules:
        resources = set(rule.get("resources", []))
        if resources & {"services", "endpoints", "endpointslices"}:
            assert set(rule.get("verbs", [])) <= {"get", "list", "watch"}, rule
    batch = [rule for rule in rules if "jobs" in rule.get("resources", [])]
    assert batch and "create" in batch[0]["verbs"], "k8s-jobs needs batch/jobs create"


def test_operator_runbooks_use_current_metric_labels() -> None:
    for path in (ROOT / "docs" / "runbooks").glob("*.md"):
        assert "strix" not in path.read_text(encoding="utf-8").lower(), path.name


def test_no_markdown_points_at_a_different_repository() -> None:
    bad = re.compile(r"github\.com/(?:ishastra|ishastra-project|useishastra)/")
    offenders = [
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*.md")
        if ".git" not in path.parts and bad.search(path.read_text(encoding="utf-8", errors="ignore"))
    ]
    assert not offenders, offenders


def test_package_and_chart_versions_match() -> None:
    from ishastra import __version__

    pyproject = re.search(r'^version = "([^"]+)"', _read("pyproject.toml"), re.MULTILINE)
    chart = re.search(r"^version: (\S+)", _read("deploy/helm/ishastra/Chart.yaml"), re.MULTILINE)
    assert pyproject and chart
    # Helm requires SemVer (4.0.0-rc1); the package reports PEP 440 (4.0.0rc1).
    assert pyproject.group(1) == chart.group(1).replace("-", "") == __version__


_DEAD_CLI_COMMANDS = (
    "ishastra compliance ",
    "ishastra adapter migrate",
    "ishastra adapter run",
    "ishastra adapter run-all",
    "ishastra adapter run-external",
    "ishastra auth rotate-key",
    "ishastra scope migrate",
    "ishastra scope validate",
    "ishastra policy ",
    "ishastra worker start",
    "ishastra keys rotate",
    "ishastra finding migrate-status",
    "ishastra scope-gate test",
    "ishastra migrate",
)


def test_docs_do_not_advertise_removed_cli_commands() -> None:
    skip = {"changelog.md", "consent-policy.md", "audit-report.md"}
    offenders = []
    for path in (ROOT / "docs").rglob("*.md"):
        if path.name in skip or "migration" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        offenders.extend(
            f"{path.relative_to(ROOT)}: {command}" for command in _DEAD_CLI_COMMANDS if command in text
        )
    assert not offenders, offenders

"""Local SAST/SCA over an explicitly selected source repository.

Never runs the target's code and never contacts a remote target: it snapshots
the tree (no symlinks, no vendor/build directories) and invokes installed
tools without a shell. Missing tools or an unavailable vulnerability database
produce PARTIAL results, never a claim that the repository is clean.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from strix import __version__
from strix.core.adapters import AdapterError, AdapterTimeout, _run_tool
from strix.core.findings import Finding, to_sarif

DETECTOR_VERSION = __version__
MAX_FILES = 10_000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 250 * 1024 * 1024
EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "vendor",
    "coverage",
    ".next",
    ".nuxt",
}
SOURCE_SUFFIXES = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".php",
    ".rb",
    ".rs",
    ".cs",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
    ".scala",
    ".kt",
    ".swift",
    ".sh",
    ".bash",
    ".sql",
    ".html",
    ".xml",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".conf",
    ".properties",
    ".tf",
    ".dockerfile",
    ".gradle",
    ".lock",
}
MANIFEST_NAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "packages.lock.json",
    "Directory.Packages.props",
    "Dockerfile",
    "Containerfile",
    "docker-compose.yml",
    "compose.yaml",
    ".env.example",
    ".env.sample",
}
SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "WARNING": "medium",
    "ERROR": "high",
}


@dataclass
class CodeScanReport:
    root: str
    findings: list[Finding] = field(default_factory=list)
    tools_run: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skipped_items: int = 0

    @property
    def state(self) -> str:
        if not self.tools_run:
            return "failed"
        incomplete_markers = (
            "unavailable",
            "failed or incomplete",
            " exited ",
            "invalid json",
            "could not be normalized",
            "skipped because",
            "omitted ",
            "snapshot is empty",
            "no requested scanner tools",
            "stopped at deadline",
        )
        if any(
            any(marker in note.lower() for marker in incomplete_markers)
            for note in self.notes
        ):
            return "partial"
        return "completed"

    @property
    def clean(self) -> bool:
        return self.state == "completed" and not self.findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": "strix-code-scan",
            "version": DETECTOR_VERSION,
            "root": self.root,
            "state": self.state,
            "verdict": (
                "no findings (all selected scanners completed)"
                if self.clean
                else (
                    f"{len(self.findings)} finding(s)"
                    if self.findings
                    else "inconclusive — scanner coverage incomplete"
                )
            ),
            "clean": self.clean,
            "tools_run": self.tools_run,
            "skipped_items": self.skipped_items,
            "notes": self.notes,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _source_snapshot(source: Path, destination: Path) -> tuple[int, int, list[str]]:
    """Copy only bounded regular source/manifests; never follow symlinks."""
    copied = 0
    total = 0
    skipped = 0
    notes: list[str] = []
    source = source.resolve()
    for current, dirs, files in os.walk(source, topdown=True, followlinks=False):
        current_path = Path(current)
        retained_dirs: list[str] = []
        for name in dirs:
            candidate = current_path / name
            if name in EXCLUDED_DIRS or candidate.is_symlink():
                skipped += 1
                continue
            retained_dirs.append(name)
        dirs[:] = retained_dirs
        rel_dir = current_path.relative_to(source)
        target_dir = destination / rel_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        for name in files:
            path = current_path / name
            if path.is_symlink() or not path.is_file():
                skipped += 1
                continue
            if (
                path.suffix.lower() not in SOURCE_SUFFIXES
                and name not in MANIFEST_NAMES
            ):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                skipped += 1
                continue
            if (
                size > MAX_FILE_BYTES
                or copied >= MAX_FILES
                or total + size > MAX_TOTAL_BYTES
            ):
                skipped += 1
                continue
            target = target_dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copyfile(path, target, follow_symlinks=False)
            except OSError:
                skipped += 1
                continue
            copied += 1
            total += size
    if skipped:
        notes.append(
            f"snapshot omitted {skipped} symlink, excluded, oversized, or over-limit item(s)"
        )
    notes.append(f"analysis snapshot contains {copied} file(s), {total} bytes")
    return copied, skipped, notes


def _relative_path(raw: Any, snapshot: Path, source: Path) -> str:
    try:
        path = Path(str(raw))
        resolved = path.resolve() if path.is_absolute() else (snapshot / path).resolve()
        relative = resolved.relative_to(snapshot.resolve())
        return relative.as_posix()
    except (OSError, ValueError, RuntimeError):
        return "<unknown>"


def _cwe_string(value: Any) -> str:
    if isinstance(value, str):
        return value.split()[0].rstrip(",")
    if isinstance(value, list):
        values = [_cwe_string(item) for item in value]
        return next((item for item in values if item), "")
    if isinstance(value, dict):
        ident = value.get("id") or value.get("cweId")
        if ident:
            return str(ident) if str(ident).startswith("CWE-") else f"CWE-{ident}"
    return ""


def _finding(
    *,
    root_name: str,
    category: str,
    title: str,
    severity: str,
    detector: str,
    evidence: str,
    location: str,
    cwe: str = "",
    remediation: str = "Review the source and the tool's rule guidance.",
    confidence: str = "medium",
    description: str = "",
) -> Finding:
    return Finding(
        asset=root_name,
        category=category[:180],
        title=title[:500] or category,
        severity=SEVERITY_MAP.get(severity.upper(), "info"),
        confidence=confidence if confidence in {"low", "medium", "high"} else "medium",
        detector=detector,
        detector_version=DETECTOR_VERSION,
        evidence=evidence[:4000] or "Scanner emitted a finding without a message.",
        location=location[:1000],
        description=description[:2000],
        remediation=remediation[:2000],
        cwe=cwe[:100],
        verification="inferred",
    )


def _parse_bandit(
    payload: dict[str, Any], snapshot: Path, source: Path, root_name: str
) -> list[Finding]:
    findings: list[Finding] = []
    for item in (
        payload.get("results", []) if isinstance(payload.get("results"), list) else []
    ):
        if not isinstance(item, dict):
            continue
        rel = _relative_path(item.get("filename", ""), snapshot, source)
        line = int(item.get("line_number") or 0)
        test_id = str(item.get("test_id") or "BANDIT")
        issue = str(item.get("issue_text") or item.get("test_name") or "Bandit finding")
        # Do not embed raw source lines in report evidence: the line may contain
        # a hard-coded credential. File/line and the tool's rule message suffice.
        cwe = _cwe_string(item.get("issue_cwe"))
        evidence = f"Bandit {test_id}: {issue} (line {line})"
        findings.append(
            _finding(
                root_name=root_name,
                category=f"sast_bandit_{test_id}",
                title=issue,
                severity=str(item.get("issue_severity") or "medium"),
                detector="bandit",
                evidence=evidence,
                location=f"{rel}:{line}" if line else rel,
                cwe=cwe,
                confidence=str(item.get("issue_confidence") or "medium").lower(),
            )
        )
    return findings


def _mapping(value: Any) -> dict[str, Any]:
    """A dict view of ``value``; non-dicts (including None) become empty."""
    return value if isinstance(value, dict) else {}


def _parse_semgrep(
    payload: dict[str, Any], snapshot: Path, source: Path, root_name: str
) -> list[Finding]:
    findings: list[Finding] = []
    for item in (
        payload.get("results", []) if isinstance(payload.get("results"), list) else []
    ):
        if not isinstance(item, dict):
            continue
        extra = _mapping(item.get("extra"))
        start = _mapping(item.get("start"))
        rel = _relative_path(item.get("path", ""), snapshot, source)
        line = int(start.get("line") or 0)
        rule = str(item.get("check_id") or "semgrep.unknown")
        message = str(extra.get("message") or rule)
        metadata = _mapping(extra.get("metadata"))
        severity = str(extra.get("severity") or "medium")
        cwe = _cwe_string(metadata.get("cwe"))
        confidence = str(metadata.get("confidence") or "medium").lower()
        findings.append(
            _finding(
                root_name=root_name,
                category=f"sast_semgrep_{rule}",
                title=message,
                severity=severity,
                detector="semgrep",
                evidence=f"Semgrep rule {rule}: {message}",
                location=f"{rel}:{line}" if line else rel,
                cwe=cwe,
                confidence=confidence,
                remediation=str(
                    metadata.get("fix") or "Review the matched code and rule guidance."
                ),
                description=str(
                    metadata.get("references")
                    or "Static-analysis result; validate reachability and runtime context."
                ),
            )
        )
    return findings


def _parse_trivy(
    payload: dict[str, Any], snapshot: Path, source: Path, root_name: str
) -> list[Finding]:
    findings: list[Finding] = []
    for result in (
        payload.get("Results", []) if isinstance(payload.get("Results"), list) else []
    ):
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "")
        for item in result.get("Vulnerabilities", []) or []:
            if not isinstance(item, dict):
                continue
            vuln_id = str(item.get("VulnerabilityID") or "CVE-UNKNOWN")
            pkg = str(item.get("PkgName") or "package")
            installed = str(item.get("InstalledVersion") or "unknown")
            fixed = str(item.get("FixedVersion") or "not specified")
            title = str(item.get("Title") or f"{vuln_id} affects {pkg}")
            url = str(item.get("PrimaryURL") or "")
            findings.append(
                _finding(
                    root_name=root_name,
                    category=f"sca_{vuln_id}_{pkg}",
                    title=title,
                    severity=str(item.get("Severity") or "unknown"),
                    detector="trivy-fs",
                    evidence=f"{vuln_id}: {pkg}@{installed}; fixed version: {fixed}; target: {target}; {url}",
                    location=_relative_path(target, snapshot, source),
                    cwe=_cwe_string(item.get("CweIDs")),
                    confidence="high",
                    remediation=(
                        f"Upgrade {pkg} to {fixed} when compatible."
                        if fixed != "not specified"
                        else "Review the advisory and upgrade to a supported, non-vulnerable version."
                    ),
                )
            )
        for item in result.get("Misconfigurations", []) or []:
            if not isinstance(item, dict):
                continue
            ident = str(item.get("ID") or "TRIVY-MISCONFIG")
            title = str(item.get("Title") or ident)
            cause = _mapping(item.get("CauseMetadata"))
            line = int(cause.get("StartLine") or 0)
            rel = _relative_path(target, snapshot, source)
            findings.append(
                _finding(
                    root_name=root_name,
                    category=f"misconfig_{ident}",
                    title=title,
                    severity=str(item.get("Severity") or "unknown"),
                    detector="trivy-fs",
                    evidence=str(
                        item.get("Message") or item.get("Description") or title
                    ),
                    location=f"{rel}:{line}" if line else rel,
                    remediation=str(
                        item.get("Resolution")
                        or "Apply the tool's recommended configuration fix."
                    ),
                    description=str(item.get("Description") or ""),
                    confidence="medium",
                )
            )
        for item in result.get("Secrets", []) or []:
            if not isinstance(item, dict):
                continue
            ident = str(item.get("RuleID") or "secret-detection")
            title = str(item.get("Title") or "Potential hard-coded secret")
            line = int(item.get("StartLine") or 0)
            rel = _relative_path(target, snapshot, source)
            findings.append(
                _finding(
                    root_name=root_name,
                    category=f"secret_{ident}",
                    title=title,
                    severity=str(item.get("Severity") or "high"),
                    detector="trivy-fs",
                    evidence=(
                        f"Trivy secret rule {ident} matched at {rel}:{line}; "
                        "raw matched value was deliberately omitted."
                    ),
                    location=f"{rel}:{line}" if line else rel,
                    confidence="medium",
                    cwe="CWE-798",
                    remediation=(
                        "Revoke and rotate any confirmed credential; "
                        "load secrets from a managed secret store."
                    ),
                )
            )
    return findings


def scan_codebase(
    root: str | Path,
    *,
    timeout: float = 180.0,
    enable_semgrep: bool = True,
    enable_bandit: bool = True,
    enable_trivy: bool = True,
) -> CodeScanReport:
    """Run optional local SAST/SCA tools against a bounded source snapshot."""
    raw_root = Path(root).expanduser()
    if raw_root.is_symlink():
        raise ValueError("repository root must not be a symlink")
    source = raw_root.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("repository path must be an existing directory")
    if timeout <= 0 or timeout > 3600:
        raise ValueError("timeout must be between 0 and 3600 seconds")

    report = CodeScanReport(root=source.name)
    with tempfile.TemporaryDirectory(prefix="strix-code-scan-") as temp:
        snapshot = Path(temp) / "source"
        snapshot.mkdir()
        copied_count, report.skipped_items, snapshot_notes = _source_snapshot(
            source, snapshot
        )
        report.notes.extend(snapshot_notes)
        if copied_count == 0:
            report.notes.append(
                "snapshot is empty; no supported source/manifests were copied"
            )
            return report

        tools: list[tuple[str, list[str], Any, set[int]]] = []
        rules = Path(__file__).parent / "rules" / "semgrep.yml"
        if enable_semgrep:
            binary = shutil.which("semgrep")
            if binary:
                tools.append(
                    (
                        "semgrep",
                        [
                            binary,
                            "scan",
                            "--json",
                            "--metrics=off",
                            "--disable-version-check",
                            "--config",
                            str(rules),
                            str(snapshot),
                        ],
                        _parse_semgrep,
                        {0, 1},
                    )
                )
            else:
                report.notes.append(
                    "Semgrep unavailable; SAST coverage is partial (install semgrep)"
                )
        if enable_bandit:
            binary = shutil.which("bandit")
            if binary:
                tools.append(
                    (
                        "bandit",
                        [binary, "-r", "-f", "json", "-q", str(snapshot)],
                        _parse_bandit,
                        {0, 1},
                    )
                )
            else:
                report.notes.append(
                    "Bandit unavailable; Python SAST coverage is partial (install bandit)"
                )
        if enable_trivy:
            binary = shutil.which("trivy")
            if binary:
                tools.append(
                    (
                        "trivy-fs",
                        [
                            binary,
                            "fs",
                            "--format",
                            "json",
                            "--scanners",
                            "vuln,secret,misconfig",
                            "--skip-db-update",
                            "--skip-check-update",
                            str(snapshot),
                        ],
                        _parse_trivy,
                        {0},
                    )
                )
            else:
                report.notes.append(
                    "Trivy unavailable; dependency/secret/config coverage is partial (install trivy)"
                )

        if not tools:
            if enable_semgrep or enable_bandit or enable_trivy:
                report.notes.append(
                    "no requested scanner tools are installed; no security verdict is possible"
                )
            else:
                report.notes.append(
                    "no scanners were selected; no security verdict is possible"
                )
            return report

        started = time.monotonic()
        cancel = threading.Event()
        for name, argv, parser, accepted_codes in tools:
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                report.notes.append(
                    f"{name} skipped because the overall code-scan deadline expired"
                )
                continue
            try:
                code, stdout, stderr = _run_tool(argv, timeout=remaining, cancel=cancel)
            except (AdapterError, AdapterTimeout) as exc:
                report.notes.append(f"{name} failed or was incomplete: {exc}")
                continue
            if code not in accepted_codes:
                report.notes.append(
                    f"{name} exited {code}: {stderr.strip()[:250] or 'no diagnostic'}"
                )
                continue
            try:
                payload = json.loads(stdout)
                if not isinstance(payload, dict):
                    raise ValueError("expected a JSON object")
            except (json.JSONDecodeError, ValueError) as exc:
                report.notes.append(f"{name} returned invalid JSON: {exc}")
                continue
            try:
                report.findings.extend(parser(payload, snapshot, source, source.name))
                report.tools_run.append(name)
            except (TypeError, ValueError, KeyError) as exc:
                report.notes.append(
                    f"{name} output could not be normalized: {type(exc).__name__}"
                )
        # Findings are redacted at serialization and SARIF boundaries. Dedupe is
        # intentionally by repository location + rule category, not message text.
        unique: dict[str, Finding] = {}
        for finding in report.findings:
            unique.setdefault(finding.fingerprint, finding)
        report.findings = sorted(
            unique.values(), key=lambda f: (f.location, f.category)
        )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="strix-code-scan",
        description="Run local static/dependency analysis on a repository; "
        "no target network requests are made.",
    )
    parser.add_argument("repository", help="local repository directory to scan")
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="overall deadline in seconds (max 3600)",
    )
    parser.add_argument(
        "--output", help="write JSON report to this path (default: stdout)"
    )
    parser.add_argument(
        "--sarif", action="store_true", help="emit SARIF 2.1.0 instead of Strix JSON"
    )
    parser.add_argument(
        "--no-semgrep", action="store_true", help="skip the Semgrep ruleset"
    )
    parser.add_argument(
        "--no-bandit", action="store_true", help="skip Bandit Python analysis"
    )
    parser.add_argument(
        "--no-trivy",
        action="store_true",
        help="skip Trivy dependency/secret/config analysis",
    )
    args = parser.parse_args(argv)
    try:
        report = scan_codebase(
            args.repository,
            timeout=args.timeout,
            enable_semgrep=not args.no_semgrep,
            enable_bandit=not args.no_bandit,
            enable_trivy=not args.no_trivy,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    payload: Any = to_sarif(report.findings) if args.sarif else report.to_dict()
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        output = Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0 if report.state == "completed" else 2


if __name__ == "__main__":  # pragma: no cover - exercised through entry point
    sys.exit(main())

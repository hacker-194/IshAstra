"""Fail if a credential-shaped string would be committed to the repository.

Scans exactly what a commit would include: files tracked by git plus untracked
files that are not gitignored. Ignored scratch/secrets directories (``.env``,
``prod-secrets/``, ``.hypothesis/``) are deliberately skipped, so a local run
agrees with CI instead of failing on files that can never be pushed.

This is a narrow, high-signal check for the credential formats this project can
accidentally emit (its own API keys, cloud keys, tokens, private keys). It is not
a replacement for a full secret scanner: it will not find a password someone
invented. It never prints the matched value, only a masked preview.

Usage: python scripts/check_secrets.py [ROOT]
Exit: 0 clean, 1 findings, 2 unusable invocation.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "graphify-out",
    "target",
    "tests",
}
SKIP_SUFFIXES = {
    ".pyc",
    ".zip",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".sqlite",
    ".db",
    ".whl",
    ".gz",
    ".woff",
    ".woff2",
    ".ico",
}
MAX_BYTES = 2 * 1024 * 1024

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ishastra api key",
        re.compile(r"\bstrix_(?=[A-Za-z0-9_-]{32,}\b)(?=[A-Za-z0-9_-]*[A-Z0-9])[A-Za-z0-9_-]+"),
    ),
    (
        "private key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    ("aws access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("github fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    ("google api key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)


ALLOW_MARKER = "pragma: allowlist secret"


def _mask(value: str) -> str:
    return f"{value[:4]}…{value[-2:]}" if len(value) > 8 else "…"


def _pushable_files(root: Path) -> list[Path] | None:
    """Tracked + untracked-not-ignored files, or None outside a git work tree."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "-co", "--exclude-standard"],
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    names = [name for name in result.stdout.decode("utf-8", "ignore").split("\0") if name]
    return [root / name for name in names]


def _iter_files(root: Path):
    candidates = _pushable_files(root)
    if candidates is None:
        candidates = sorted(root.rglob("*"))
    for path in candidates:
        if not path.is_file():
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        yield path, relative


def scan(root: Path) -> list[tuple[str, int, str, str]]:
    findings: list[tuple[str, int, str, str]] = []
    for path, relative in _iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        for kind, pattern in PATTERNS:
            for match in pattern.finditer(text):
                if kind == "private key" and len(text) - match.end() < 64:
                    continue
                line = text.count("\n", 0, match.start()) + 1
                if line <= len(lines) and ALLOW_MARKER in lines[line - 1]:
                    continue
                findings.append((str(relative), line, kind, _mask(match.group(0))))
    return findings


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else ".").resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    findings = scan(root)
    if not findings:
        print(f"secret scan clean ({root})")
        return 0
    for relative, line, kind, masked in findings:
        print(f"{relative}:{line}: possible {kind} ({masked})")
    print(f"FAILED: {len(findings)} possible credential(s) found", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

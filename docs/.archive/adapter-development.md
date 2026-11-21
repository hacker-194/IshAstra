# Adapter Development Guide

Ishastra's adapter framework follows the principle: **One Capability = One Adapter = One Tool**. This guide covers creating, registering, and testing custom adapters.

---

## Adapter Contract

Every adapter implements the `Adapter` base class from `ishastra.core.adapter_base`:

```python
from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from ishastra.core.adapter_base import Adapter, AdapterResult, checked_destination
from ishastra.core.findings import Finding


class MyCustomAdapter(Adapter):
    # Required class attributes
    id: ClassVar[str] = "ishastra-my-custom"
    version: ClassVar[str] = "1.0"
    asset_types: ClassVar[tuple[str, ...]] = ("web", "api")
    requires: ClassVar[tuple[str, ...]] = ("mytool",)  # External binary name

    def available(self) -> tuple[bool, str]:
        """Check if tool is installed and functional."""
        binary = shutil.which("mytool")
        if not binary:
            return False, "mytool not installed"
        # Optional: verify version/working
        return True, "mytool 1.2.3"

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict | None = None,
    ) -> AdapterResult:
        """Main assessment logic. MUST call checked_destination() FIRST."""
        # MANDATORY: Scope gate check before ANY network I/O
        destination = checked_destination(target)

        # Use destination.scheme, destination.host, destination.port, destination.ip
        # Respect timeout (wall clock) and cancel (threading.Event)
        # Context may contain: auth_principal, discovered_urls, etc.

        findings = []
        notes = []
        partial = False

        # ... run your tool ...

        return AdapterResult(findings=findings, notes=notes, partial=partial)

    def info(self) -> dict:
        """Metadata for /api/adapters endpoint."""
        return {
            "name": self.id,
            "description": "Custom adapter description",
            "categories": ["vuln", "info"],
            "requires": list(self.requires),
            "available": self.available()[0],
        }
```

---

## Mandatory Rules

### 1. Call `checked_destination()` FIRST

```python
def assess(self, target, *, timeout, cancel, context=None):
    destination = checked_destination(target)  # ← FIRST LINE
    # Now safe to connect to destination.ip:destination.port
```

This is the **single enforcement point** — no adapter can bypass the scope gate.

### 2. Respect Timeout & Cancellation

```python
import time

def assess(self, target, *, timeout, cancel, context=None):
    deadline = time.monotonic() + timeout
    destination = checked_destination(target)

    for item in work_items:
        if cancel.is_set():
            raise AdapterCancelled("Assessment cancelled")
        if time.monotonic() > deadline:
            raise AdapterTimeout("Deadline exceeded")
        # ... do work ...
```

### 3. Return `AdapterResult` with Proper `partial` Flag

```python
@dataclass(frozen=True)
class AdapterResult:
    findings: list[Finding]
    notes: list[str]          # Operational details, coverage gaps
    partial: bool             # True = incomplete coverage (deadline, budget)
```

| `partial` | Meaning | RunState |
|-----------|---------|----------|
| `False` | Completed full coverage | `OK` |
| `True` | Deadline cut sweep short, port budget hit | `PARTIAL` |

### 4. Handle `AdapterNotApplicable` for Non-Applicable Cases

```python
from ishastra.core.adapter_base import AdapterNotApplicable

def assess(self, target, *, timeout, cancel, context=None):
    if not context or not context.get("discovered_urls"):
        raise AdapterNotApplicable("No discovered URLs to validate")
    # ...
```

This is **not a failure** — orchestrator records as `REJECTED` coverage.

### 5. Use Normalized Finding Model

```python
from ishastra.core.findings import Finding, Severity, Confidence, Verification

finding = Finding(
    category="custom_finding_category",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    verification=Verification.OBSERVED,
    title="Descriptive Title",
    description="Detailed explanation",
    location="https://example.com/path",
    evidence={"key": "redacted_value"},
    cwe="CWE-XXX",                    # Required for vulnerabilities
    cvss_score=7.5,
    business_impact="Data exposure",
    asset_criticality="high",
    risk_rating="high",
    exploit_available=False,
    user_impact="All users affected",
    compliance_refs=["NRB-7.2", "NTA-5.1"],
    remediation_status="open",
)
```

### 6. Redact Credentials in Evidence

```python
from ishastra.core.redaction import redact

evidence = {
    "response": redact(raw_response),  # Strips passwords, tokens, JWTs, AWS keys, private keys
    "request_headers": redact(dict(request_headers)),
}
```

---

## Registering Your Adapter

### 1. Add to `src/ishastra/core/adapters.py`

```python
# Import your adapter
from .my_custom_adapter import MyCustomAdapter

# Register in ADAPTERS dict
ADAPTERS = {
    # ... existing adapters ...
    MyCustomAdapter().id: MyCustomAdapter(),
}
```

### 2. Add to Profiles

```python
PROFILES = {
    # ... existing profiles ...
    "web-deep": (
        "ishastra-crawl",
        "ishastra-http",
        "ishastra-dynamic-validation",
        "ishastra-git-exposure",
        "ishastra-nuclei",
        "ishastra-my-custom",  # ← Add here
    ),
    "custom-profile": (
        "ishastra-http",
        "ishastra-my-custom",
    ),
}
```

### 3. Export from Module

Ensure `adapters/__init__.py` re-exports if needed.

---

## External Tool Adapters

For adapters wrapping external binaries (nmap, nuclei, etc.):

### Safe Execution Pattern (`_run_tool`)

```python
from ishastra.core.adapter_base import _run_tool, AdapterTimeout, AdapterCancelled

def assess(self, target, *, timeout, cancel, context=None):
    destination = checked_destination(target)

    args = [
        "mytool",
        "-target", destination.ip,
        "-port", str(destination.port),
        "-timeout", str(int(timeout)),
    ]

    try:
        stdout, stderr, rc = _run_tool(
            args=args,
            timeout=timeout,
            cancel=cancel,
            max_output_bytes=16 * 1024 * 1024,  # 16MB bound
        )
    except AdapterTimeout:
        raise
    except AdapterCancelled:
        raise
    except Exception as e:
        raise AdapterError(f"Tool execution failed: {e}")

    # Parse output safely
    findings = self._parse_output(stdout)
    return AdapterResult(findings=findings, notes=[], partial=False)
```

### `_run_tool()` Safety Guarantees

| Protection | Implementation |
|------------|----------------|
| No shell injection | Argument array only |
| Minimal environment | `PATH`, `LC_ALL`, `HOME` only |
| Process group kill | `os.killpg()` + `proc.kill()` |
| Bounded output | 16MB/stream with continuous drain |
| Deadline enforcement | `time.monotonic()` + cancel event |
| stdin protection | `stdin=DEVNULL` (prevents nuclei hang) |
| XML parsing safety | `defusedxml` for XML output |

---

## Context Passing

Adapters receive a shared `context` dict for inter-adapter communication:

| Key | Set By | Consumed By |
|-----|--------|-------------|
| `discovered_urls` | `CrawlerAdapter` | `HTTPAdapter`, `DynamicValidationAdapter` |
| `auth_principal` | Job executor | All adapters needing auth |
| `openapi_spec` | `OpenAPIAdapter` | `AuthorizationDiffAdapter` |
| `crawl_pages` | `CrawlerAdapter` | Deep inspection adapters |

```python
def assess(self, target, *, timeout, cancel, context=None):
    context = context or {}
    discovered = context.get("discovered_urls", [])
    principal = context.get("auth_principal")
    # Use context data...
```

---

## Testing Your Adapter

### Unit Test Template

```python
# tests/test_my_custom_adapter.py
import pytest
from unittest.mock import patch, MagicMock
from ishastra.core.adapters import MyCustomAdapter
from ishastra.core.adapter_base import AdapterNotApplicable


def test_available_when_tool_missing():
    adapter = MyCustomAdapter()
    with patch("shutil.which", return_value=None):
        available, msg = adapter.available()
        assert available is False
        assert "not installed" in msg


def test_available_when_tool_present():
    adapter = MyCustomAdapter()
    with patch("shutil.which", return_value="/usr/bin/mytool"):
        available, msg = adapter.available()
        assert available is True
        assert "mytool" in msg


def test_assess_calls_checked_destination_first():
    adapter = MyCustomAdapter()
    with patch("ishastra.core.adapters.checked_destination") as mock_gate:
        mock_gate.return_value = MagicMock(ip="1.2.3.4", port=443, scheme="https", host="example.com")
        with patch("shutil.which", return_value="/usr/bin/mytool"):
            with patch.object(adapter, "_run_tool", return_value=("", "", 0)):
                result = adapter.assess("https://example.com", timeout=30, cancel=threading.Event())
                mock_gate.assert_called_once_with("https://example.com")


def test_assess_returns_findings():
    adapter = MyCustomAdapter()
    with patch("ishastra.core.adapters.checked_destination") as mock_gate:
        mock_gate.return_value = MagicMock(ip="1.2.3.4", port=443, scheme="https", host="example.com")
        with patch("shutil.which", return_value="/usr/bin/mytool"):
            with patch.object(adapter, "_run_tool", return_value=("finding output", "", 0)):
                result = adapter.assess("https://example.com", timeout=30, cancel=threading.Event())
                assert isinstance(result.findings, list)
                assert result.partial is False
```

### Integration Test

```python
# tests/integration/test_my_custom_adapter.py
@pytest.mark.integration
def test_my_custom_adapter_end_to_end():
    """Requires mytool installed and authorized target in scope."""
    from ishastra.core.jobs import run_assessment
    from ishastra.core.scope import load
    from ishastra.config import Settings

    # Load test scope
    scope.load("tests/fixtures/scope.json")

    job = run_assessment(
        target="https://authorized-target.example.com",
        profile="custom-profile",  # Includes your adapter
        wait=True,
    )

    assert job.state == "completed"
    # Verify your adapter ran
    adapter_runs = [r for r in job.runs if r.adapter == "ishastra-my-custom"]
    assert len(adapter_runs) == 1
    assert adapter_runs[0].state == "ok"
```

---

## Adapter Categories & Severity Mapping

Use consistent categories from `WEB_CHECKS` in `adapters.py`:

```python
WEB_CHECKS = {
    "missing_csp": ("medium", "Missing Content-Security-Policy", "CWE-693", "Add CSP header"),
    "missing_hsts": ("medium", "Missing HSTS Header", "CWE-523", "Enable HSTS"),
    "sqli_indicator": ("info", "SQL Injection Indicator", "CWE-89", "Validate input"),
    "xss_indicator": ("info", "XSS Indicator", "CWE-79", "Encode output"),
    # Add your category here
}
```

---

## Common Pitfalls

| Pitfall | Consequence | Fix |
|---------|-------------|-----|
| Forgetting `checked_destination()` | Bypasses authorization, security critical | Always call first line of `assess()` |
| Not respecting `cancel` | Jobs can't be cancelled, resource leaks | Check `cancel.is_set()` in loops |
| Not respecting `timeout` | Deadline exceeded, worker hangs | Use `time.monotonic()` deadline |
| Using `shell=True` | Command injection | Use argument arrays only |
| Unbounded tool output | OOM, DoS | Use `_run_tool()` with `max_output_bytes` |
| Not redacting evidence | Credential leakage | Call `redact()` on all output |
| Returning `partial=False` when incomplete | False "complete coverage" claim | Set `partial=True` if deadline/budget cut |
| Raising generic `Exception` on non-applicable | Recorded as `FAILED` not `REJECTED` | Raise `AdapterNotApplicable` |

---

## Debugging Adapters

```bash
# Run single adapter inline
ishastra assess --target https://example.com --profile web-deep --wait

# Enable debug logging
ISHASTRA_LOG_LEVEL=DEBUG ishastra serve

# Check adapter availability
curl -H "Authorization: Bearer $KEY" http://localhost:8000/api/adapters
```

---

## Publishing Custom Adapters

1. **Fork** the Ishastra repository
2. **Implement** adapter following this guide
3. **Test** thoroughly (unit + integration)
4. **Document** in PR description:
   - Capability provided
   - External tool requirements
   - Profile membership
   - Finding categories added
5. **Security review** required for:
   - No credential leakage
   - No SSRF/RCE in tool invocation
   - Authorization checks at trust boundaries
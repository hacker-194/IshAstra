# Contributing to Strix

Strix is an authorized security assessment platform. All contributions must preserve the **default-deny authorization model** — every outbound connection is validated against an authorization document before any network contact.

## License

Strix is fully open source under the **MIT License** (`LICENSE`). Every feature is
in the MIT project; there is no proprietary edition or feature gated behind a
commercial plan. By contributing, you agree that your contribution is licensed
under the same MIT terms. There is no contributor license agreement and no
copyright assignment.

## Development Setup

```bash
# Clone and install
git clone <repo>
cd strix
pip install -c constraints.txt -e ".[dev]"

# Configure authorization (required for any scan)
cp scope.example.json scope.json
# Edit scope.json with hosts you are AUTHORIZED to test

# Generate API key
export STRIX_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"

# Run server
strix serve --host 0.0.0.0 --port 8000

# Or run inline assessment (for testing)
strix assess --target https://example.com --profile web
```

## Code Quality Gates

Run before every commit:

```bash
ruff check src tests scripts
ruff format --check src tests scripts
mypy
python scripts/check_secrets.py .
pytest
```

CI runs the same checks. PRs failing any gate are blocked.

## Architecture Principles

### 1. Default-Deny Authorization
- **Never** make an outbound connection without `scope.check()` or `scope.destination()`
- The scope gate (`src/strix/core/scope.py`) is the single authorization point
- Adapters MUST call `checked_destination(target)` before connecting

### 2. One Capability = One Adapter
- Each adapter encapsulates one tool/technique
- `available()` reports actual tool presence, not assumed capability
- Adapters re-check scope internally — never trust caller validation

### 3. Coverage Honesty
- A job is "clean" ONLY when every selected adapter ran to completion (`RunState.OK`)
- Partial/failed/unavailable adapters → inconclusive result
- Adapters set `partial=True` when deadline cuts sweep short

### 4. Redaction at Every Boundary
- Credentials redacted from: evidence, job targets, errors, audit, SARIF, HTML, webhooks
- Use `strix.core.redaction.redact()` and `sanitize_target()`

### 5. Multi-Tenant Isolation
- Per-task scope binding via `strix.core.scope.bound()` ContextVar
- Job carries `policy_id` + `policy_version`; worker re-validates at execution
- Revoked policy = job fails, never scans under another tenant's auth

## Adding a New Adapter

### 1. Create the Adapter Class

```python
# src/strix/core/adapters.py (or new detector module)
from strix.core.adapter_base import Adapter, AdapterResult, checked_destination
from strix.core.findings import Finding

class MyNewAdapter(Adapter):
    id = "strix-my-new"
    version = "1.0"
    asset_types = ("web",)
    requires = ("mytool",)  # external binary name

    def available(self) -> tuple[bool, str]:
        # Check tool exists and works
        binary = shutil.which("mytool")
        if not binary:
            return False, "mytool not installed"
        return True, "mytool 1.2.3"

    def assess(self, target, *, timeout, cancel, context=None) -> AdapterResult:
        destination = checked_destination(target)  # MANDATORY
        # ... run tool with deadline/cancel ...
        return AdapterResult(findings=[...], notes=[...], partial=False)
```

### 2. Register in `ADAPTERS` dict and add to `PROFILES`

```python
ADAPTERS = {
    # ...
    MyNewAdapter().id: MyNewAdapter(),
}

PROFILES = {
    # ...
    "web-deep": (..., "strix-my-new"),
}
```

### 3. Requirements
- Call `checked_destination(target)` FIRST — before any network I/O
- Respect `timeout` (wall clock) and `cancel` (threading.Event)
- Return `AdapterResult` with `partial=True` if coverage incomplete
- Findings must use normalized model (`Finding` from `strix.core.findings`)
- Tool output bounded (16MB), parsed safely (defusedxml for XML)

## Adding a New Finding Category

1. Define in adapter's `_observe` or assessment logic
2. Use standard severity/confidence/verification:
   - Severity: `critical | high | medium | low | info`
   - Confidence: `high | medium | low`
   - Verification: `observed | inferred | unverified`
3. Include defensive fields: `cvss_score`, `business_impact`, `asset_criticality`, `risk_rating`, `exploit_available`, `user_impact`, `compliance_refs`, `remediation_status`
4. CWE required for vulnerability categories
5. Evidence must be redacted (no credentials)

## Scope Document Changes

- `scope.json` is validated by `parse_scope_document()` — unknown fields rejected
- `include` = required non-empty list of hosts/patterns
- `authorized_networks` = CIDR networks (no IPv4-mapped IPv6)
- `allowed_ports` = explicit port list (production should enumerate)
- Networks broader than /8 require `allow_broad_networks: true`

## Testing

```bash
# Unit tests
pytest tests/ -v

# Integration tests (require nmap/nuclei)
pytest tests/integration/ -v

# Lab evaluation (detection benchmark)
python -m strix.lab --report lab-eval.json
```

### Test Patterns
- Adapter tests: mock `available()`, verify `assess()` calls `checked_destination`
- Job tests: verify coverage states, policy binding re-validation
- Scope tests: test Layer 1/2/3 boundaries, special-use addresses, wildcards

## Security Considerations

### Never
- Log raw credentials, tokens, or authorization headers
- Follow redirects in scanners (nuclei `-dr`, probe never follows)
- Accept user-supplied URLs for outbound connections without scope gate
- Store secrets in plaintext (API keys hashed, webhook secrets HMAC'd)
- Use shell=True or string commands for external tools

### Always
- Validate target through scope gate before ANY network I/O
- Pin destination IP to prevent DNS rebinding
- Bound tool output and execution time
- Kill process groups, not just parent PIDs
- Use argument arrays, minimal environment for subprocesses

## Pull Request Process

1. Fork → feature branch → PR
2. All CI gates pass (ruff, mypy, tests, secret scan)
3. Architecture review for:
   - New adapters follow framework contract
   - Scope gate not bypassed
   - Multi-tenant isolation preserved
   - Redaction at new output boundaries
4. Security review for:
   - No credential leakage
   - No SSRF/RCE in tool invocation
   - Authorization checks at trust boundaries
5. Merge (squash) to main

## Release Process

Version in `src/strix/__init__.py`. Tagged releases build Docker image and publish to PyPI.

## Code Style

- **Python 3.12+** — type hints mandatory, `from __future__ import annotations`
- **Dataclasses** over regular classes for data carriers
- **Frozen dataclasses** for immutable config/results
- **ContextVars** for task-scoped state (not threading.local)
- **Structured logging** — `log.exception()` for errors, `log.warning()` for operator alerts
- **No global mutable state** except module-level `_active` scope and adapter registry

## Key Files Reference

| Area | Files |
|------|-------|
| Scope Gate | `src/strix/core/scope.py` |
| Job Orchestration | `src/strix/core/jobs.py` |
| Adapter Base | `src/strix/core/adapter_base.py` |
| Built-in Adapters | `src/strix/core/adapters.py` |
| Findings Model | `src/strix/core/findings.py` |
| Persistence | `src/strix/core/store.py` |
| Engagement Policies | `src/strix/core/policies.py` |
| API Routes | `src/strix/api/routers/` |
| Auth/Rate Limit | `src/strix/api/security.py` |
| Strix Proof | `src/strix/proof.py` |
| CLI Entry | `src/strix/cli.py` |
| Config | `src/strix/config.py` |
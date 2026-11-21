# Adapter Framework Architecture

# Adapter Framework Architecture

How Ishastra runs real security tools with normalized output and Scope Gate enforcement.

## Overview

The Adapter Framework is Ishastra's plugin system for security tools. Every adapter — built-in or external — **re-checks Scope Gate before each connection**.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Adapter Framework                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     Adapter Registry                                  │  │
│  │  HTTPProbeAdapter │ CrawlerAdapter │ DynamicValidationAdapter       │  │
│  │  NmapAdapter      │ NucleiAdapter  │ SQLMapAdapter                  │  │
│  │  NiktoAdapter     │ Custom (SDK)   │                                 │  │
│  └────────────────────────────────┬─────────────────────────────────────┘  │
│                                   │                                        │
│           ┌───────────────────────┼───────────────────────┐               │
│           ▼                       ▼                       ▼               │
│  ┌───────────────┐       ┌───────────────┐       ┌───────────────┐      │
│  │  BaseAdapter  │       │  ScopeGate    │       │  Finding      │      │
│  │  (Abstract)   │◀──────│  (Injected)   │       │  Normalizer   │      │
│  └───────┬───────┘       └───────────────┘       └───────┬───────┘      │
│          │                                               │              │
│          ▼                                               ▼              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Adapter Execution Flow                         │  │
│  │  1. validate_outbound() → Pinned Destination                     │  │
│  │  2. Connect to pinned IP only                                    │  │
│  │  3. Execute tool logic                                           │  │
│  │  4. Normalize findings → Finding objects                         │  │
│  │  5. Return normalized results                                    │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Base Adapter Interface

**File**: `src/ishastra/core/adapters.py` — `BaseAdapter` class

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncIterator

@dataclass
class AdapterConfig:
    scope: ScopeDocument
    target: str
    options: dict
    scope_gate: ScopeGate

@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    location: str
    evidence: dict
    references: list[str]
    metadata: dict

class BaseAdapter(ABC):
    name: str = "base"
    version: str = "1.0.0"
    supported_targets: list[str] = ["http", "https"]

    def __init__(self, config: AdapterConfig):
        self.config = config
        self.scope_gate = config.scope_gate
        self.scope = config.scope

    @abstractmethod
    async def run(self) -> AsyncIterator[Finding]:
        """Execute adapter, yield findings"""
        pass

    async def _authorize_connection(self, url: str) -> Destination:
        """MUST be called before ANY outbound connection"""
        return await self.scope_gate.validate_outbound(url, self.scope)

    async def _make_request(self, method: str, url: str, **kwargs) -> Response:
        """Helper that enforces Scope Gate"""
        dest = await self._authorize_connection(url)
        return await self._connect_to_pinned(dest, method, **kwargs)
```

## Built-in Adapters

### 1. HTTP Probe Adapter

**File**: `src/ishastra/core/adapters.py` — `HTTPProbeAdapter`

**Purpose**: Passive header analysis, security headers, technology detection

**Capabilities**:
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Server/technology fingerprinting
- Cookie security analysis
- HTTP method enumeration
- Redirect chain analysis

**Scope Gate**: Re-validates for each request in redirect chain

```python
class HTTPProbeAdapter(BaseAdapter):
    name = "http_probe"
    supported_targets = ["http", "https"]

    async def run(self) -> AsyncIterator[Finding]:
        dest = await self._authorize_connection(self.config.target)

        # Initial request
        resp = await self._make_request("GET", self.config.target)

        # Security headers
        yield from self._check_security_headers(resp)

        # Technology detection
        yield from self._detect_technology(resp)

        # Cookie analysis
        yield from self._analyze_cookies(resp)

        # Follow redirects (each re-validated)
        async for finding in self._follow_redirects(resp):
            yield finding
```

**Findings Produced**:
| ID Prefix | Severity | Example |
|-----------|----------|---------|
| `HTTP-MISSING-CSP` | MEDIUM | Content-Security-Policy header missing |
| `HTTP-MISSING-HSTS` | HIGH | Strict-Transport-Security missing |
| `HTTP-SERVER-DISCLOSURE` | INFO | Server header reveals version |
| `HTTP-INSECURE-COOKIE` | MEDIUM | Cookie missing Secure/HttpOnly |

---

### 2. Crawler Adapter

**File**: `src/ishastra/core/adapters.py` — `CrawlerAdapter`

**Purpose**: Link discovery, form extraction, JavaScript analysis

**Capabilities**:
- Breadth-first crawling (configurable depth/max pages)
- Form discovery and analysis
- JavaScript endpoint extraction
- API endpoint discovery
- Sitemap/robots.txt parsing

**Scope Gate**: Every discovered URL validated before crawl

```python
class CrawlerAdapter(BaseAdapter):
    name = "crawler"
    supported_targets = ["http", "https"]

    async def run(self) -> AsyncIterator[Finding]:
        dest = await self._authorize_connection(self.config.target)
        visited = set()
        queue = [self.config.target]

        while queue and len(visited) < self.config.options.get("max_pages", 100):
            url = queue.pop(0)
            if url in visited:
                continue

            # Scope Gate check for EACH discovered URL
            try:
                await self._authorize_connection(url)
            except AuthorizationError:
                continue  # Skip unauthorized URLs

            visited.add(url)
            resp = await self._make_request("GET", url)

            # Extract links
            for link in self._extract_links(resp, url):
                if self._in_scope(link):
                    queue.append(link)

            # Extract forms
            yield from self._analyze_forms(resp, url)

            # Extract JS endpoints
            yield from self._extract_js_endpoints(resp, url)
```

**Findings Produced**:
| ID Prefix | Severity | Example |
|-----------|----------|---------|
| `CRAWL-FORM-NO-CSRF` | MEDIUM | Form missing CSRF token |
| `CRAWL-EXPOSED-ADMIN` | HIGH | Admin panel discovered |
| `CRAWL-JS-ENDPOINT` | INFO | API endpoint found in JS |
| `CRAWL-SENSITIVE-PATH` | MEDIUM | `.git`, `.env`, backup files |

---

### 3. Dynamic Validation Adapter

**File**: `src/ishastra/core/adapters.py` — `DynamicValidationAdapter`

**Purpose**: Runtime behavior testing, authentication flows, business logic

**Capabilities**:
- Authentication bypass testing
- Authorization bypass (IDOR, horizontal/vertical)
- Input validation testing (XSS, SQLi, command injection)
- Business logic flaws
- Rate limiting verification

**Scope Gate**: Every test request validated

```python
class DynamicValidationAdapter(BaseAdapter):
    name = "dynamic_validation"
    supported_targets = ["http", "https"]

    async def run(self) -> AsyncIterator[Finding]:
        # Authentication flow tests
        yield from await self._test_auth_bypass()

        # Authorization tests
        yield from await self._test_idor()

        # Input validation
        yield from await self._test_input_validation()

        # Business logic
        yield from await self._test_business_logic()

    async def _test_idor(self) -> AsyncIterator[Finding]:
        # Test object reference manipulation
        for endpoint in self.config.options.get("idor_endpoints", []):
            for test_id in self._generate_test_ids():
                url = f"{endpoint}/{test_id}"
                dest = await self._authorize_connection(url)
                resp = await self._make_request("GET", url)

                if resp.status == 200 and self._is_sensitive_data(resp):
                    yield Finding(
                        id=f"DYN-IDOR-{endpoint}",
                        title="Insecure Direct Object Reference",
                        severity=Severity.HIGH,
                        ...
                    )
```

**Findings Produced**:
| ID Prefix | Severity | Example |
|-----------|----------|---------|
| `DYN-AUTH-BYPASS` | CRITICAL | Authentication bypass |
| `DYN-IDOR` | HIGH | Object reference manipulation |
| `DYN-XSS-REFLECTED` | HIGH | Reflected XSS |
| `DYN-SQLI` | CRITICAL | SQL injection |
| `DYN-RATE-LIMIT-BYPASS` | MEDIUM | Rate limit bypass |

---

## External Tool Adapters

External tools run as subprocesses. Ishastra wraps them with Scope Gate enforcement.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  External Tool Adapter                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │  Target     │───▶│  Scope Gate │───▶│  Pinned     │         │
│  │  URL        │    │  Validate   │    │  Destination│         │
│  └─────────────┘    └─────────────┘    └──────┬──────┘         │
│                                                │                │
│                                                ▼                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Tool Execution Wrapper                      │   │
│  │  1. Build command with pinned IP                        │   │
│  │  2. Inject --host-header for SNI                        │   │
│  │  3. Run subprocess with timeout                         │   │
│  │  4. Parse output → normalized Findings                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Nmap Adapter

```python
class NmapAdapter(BaseAdapter):
    name = "nmap"
    version = "7.94"

    async def run(self) -> AsyncIterator[Finding]:
        dest = await self._authorize_connection(self.config.target)

        # Build nmap command with pinned IP
        cmd = [
            "nmap", "-sS", "-sV", "-O", "--script", "vuln",
            "-oX", "-",  # XML output to stdout
            dest.ip,     # Connect to PINNED IP
        ]

        # Add host header for virtual hosting
        env = {**os.environ, "HOST_HEADER": dest.host}

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=self.config.options.get("timeout", 300)
        )

        yield from self._parse_nmap_xml(stdout)
```

**Key Safety Features**:
- Connects ONLY to pinned IP from Scope Gate
- Timeout enforcement (default 5 min)
- Output parsing with size limits
- No shell injection (uses `create_subprocess_exec`)

### Nuclei Adapter

```python
class NucleiAdapter(BaseAdapter):
    name = "nuclei"
    version = "3.2.0"

    async def run(self) -> AsyncIterator[Finding]:
        dest = await self._authorize_connection(self.config.target)

        # Nuclei supports target specification
        cmd = [
            "nuclei",
            "-target", dest.ip,
            "-H", f"Host: {dest.host}",  # Critical for virtual hosts
            "-silent",
            "-json",
            "-severity", "critical,high,medium,low,info",
        ]

        # Template selection
        if templates := self.config.options.get("templates"):
            cmd.extend(["-t", ",".join(templates)])

        # Rate limiting
        cmd.extend(["-rate-limit", str(self.config.options.get("rate_limit", 150))])

        yield from self._run_and_parse(cmd, self._parse_nuclei_json)
```

### SQLMap Adapter

```python
class SQLMapAdapter(BaseAdapter):
    name = "sqlmap"
    version = "1.8"

    async def run(self) -> AsyncIterator[Finding]:
        dest = await self._authorize_connection(self.config.target)

        cmd = [
            "sqlmap",
            "-u", f"http://{dest.ip}{self.config.options.get('path', '/')}",
            "--host", dest.host,
            "--batch",
            "--output-dir", "/tmp/sqlmap",
            "--flush-session",
            "--fresh-queries",
            "--level", "1",
            "--risk", "1",
        ]

        yield from self._run_and_parse(cmd, self._parse_sqlmap_output)
```

### Nikto Adapter

```python
class NiktoAdapter(BaseAdapter):
    name = "nikto"
    version = "2.5.0"

    async def run(self) -> AsyncIterator[Finding]:
        dest = await self._authorize_connection(self.config.target)

        cmd = [
            "nikto",
            "-h", dest.ip,
            "-host", dest.host,
            "-Format", "json",
            "-output", "/tmp/nikto.json",
            "-timeout", str(self.config.options.get("timeout", 30)),
        ]

        yield from self._run_and_parse(cmd, self._parse_nikto_json)
```

---

## SDK: Custom Adapter Development

### Creating a Custom Adapter

```python
# my_adapters/custom_ssh.py
from ishastra.core.adapters import BaseAdapter, AdapterConfig, Finding
from ishastra.core.scope import Severity

class CustomSSHAdapter(BaseAdapter):
    name = "custom_ssh"
    version = "1.0.0"
    supported_targets = ["ssh"]

    async def run(self) -> AsyncIterator[Finding]:
        dest = await self._authorize_connection(self.config.target)

        # Use pinned IP for SSH connection
        async with asyncssh.connect(
            dest.ip,
            port=dest.port,
            known_hosts=None,  # We trust the pinned IP
        ) as conn:
            # Run SSH-specific checks
            yield from await self._check_ssh_config(conn)
            yield from await self._check_weak_ciphers(conn)
            yield from await self._check_auth_methods(conn)

    async def _check_weak_ciphers(self, conn) -> AsyncIterator[Finding]:
        ciphers = conn.get_ciphers()
        weak = [c for c in ciphers if c in WEAK_CIPHERS]
        if weak:
            yield Finding(
                id="SSH-WEAK-CIPHER",
                title="Weak SSH Ciphers Enabled",
                severity=Severity.MEDIUM,
                category="crypto",
                location=self.config.target,
                evidence={"ciphers": weak},
                references=["https://ishastra.dev/findings/SSH-WEAK-CIPHER"],
                metadata={}
            )
```

### Registering Custom Adapters

```python
# In your application startup
from ishastra.core.adapters import adapter_registry
from my_adapters.custom_ssh import CustomSSHAdapter

adapter_registry.register(CustomSSHAdapter)

# Now available via API
POST /api/v1/assessments
{
  "scope_id": "...",
  "targets": ["ssh://server.example.com"],
  "adapters": ["custom_ssh"]
}
```

### SDK Helper Functions

```python
from ishastra.core.adapters import (
    BaseAdapter,
    AdapterConfig,
    Finding,
    Severity,
    adapter_registry,
    run_adapter_safely,  # Timeout, error handling, Scope Gate
    parse_target_url,
    build_finding_id,
)

# Safe adapter execution with all protections
async def run_my_adapter(config: AdapterConfig) -> list[Finding]:
    return await run_adapter_safely(
        adapter_class=MyAdapter,
        config=config,
        timeout=300,
        max_findings=1000,
    )
```

---

## Finding Normalization

All adapters produce normalized `Finding` objects:

```python
@dataclass
class Finding:
    id: str                    # Unique: ADAPTER-TYPE-VULN
    title: str                 # Human readable
    description: str           # Detailed explanation
    severity: Severity         # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str              # OWASP category, CWE, etc.
    location: str              # URL, endpoint, file:line
    evidence: dict             # Proof: request/response, screenshots
    references: list[str]      # CVE, CWE, advisory URLs
    metadata: dict             # Adapter-specific data
    discovered_at: datetime    # Timestamp
    adapter_name: str          # Source adapter
    adapter_version: str       # Adapter version
```

### Normalization Pipeline

```
Raw Tool Output
      │
      ▼
┌─────────────┐
│ Parse       │  Adapter-specific parser (XML, JSON, text)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Map         │  Tool severity → Ishastra severity
│ Severity    │  Tool IDs → Ishastra finding IDs
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Enrich      │  Add CVE, CWE, CVSS, references
│             │  Add remediation guidance
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Redact      │  Remove PII, secrets, tokens from evidence
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Dedupe      │  Merge duplicate findings (same location+type)
└──────┬──────┘
       │
       ▼
Normalized Finding Objects
```

---

## Adapter Configuration

### Per-Assessment Options

```json
{
  "adapters": {
    "http_probe": {
      "follow_redirects": true,
      "max_redirects": 10
    },
    "crawler": {
      "max_pages": 200,
      "max_depth": 3,
      "respect_robots_txt": true
    },
    "dynamic_validation": {
      "test_auth_bypass": true,
      "test_idor": true,
      "idor_endpoints": ["/api/users/{id}", "/api/orders/{id}"],
      "test_xss": true,
      "test_sqli": true
    },
    "nmap": {
      "scan_type": "syn",
      "version_detection": true,
      "os_detection": true,
      "scripts": ["vuln", "auth"],
      "timeout": 300
    },
    "nuclei": {
      "templates": ["cves/", "vulnerabilities/", "misconfiguration/"],
      "severity": ["critical", "high", "medium"],
      "rate_limit": 100
    },
    "sqlmap": {
      "level": 2,
      "risk": 2,
      "technique": "BEUSTQ",
      "timeout": 600
    }
  }
}
```

---

## Performance & Resource Limits

### Concurrency Control

```python
# In worker, per-adapter semaphores
ADAPTER_SEMAPHORES = {
    "http_probe": 50,
    "crawler": 10,
    "dynamic_validation": 5,
    "nmap": 3,
    "nuclei": 5,
    "sqlmap": 2,
    "nikto": 3,
}
```

### Resource Limits (Docker/K8s)

```yaml
# Per-adapter resource limits
resources:
  http_probe:
    limits:
      cpu: "500m"
      memory: "512Mi"
  nmap:
    limits:
      cpu: "1000m"
      memory: "1Gi"
  nuclei:
    limits:
      cpu: "2000m"
      memory: "2Gi"
  sqlmap:
    limits:
      cpu: "1000m"
      memory: "1Gi"
```

---

## Testing Adapters

### Unit Tests

```python
# tests/unit/test_adapters.py
import pytest
from ishastra.core.adapters import HTTPProbeAdapter, AdapterConfig
from ishastra.core.scope import ScopeDocument

@pytest.fixture
def mock_scope():
    return ScopeDocument(
        version=2,
        authorized_networks=["10.0.0.0/8"],
        include_hosts=["example.com"],
        allowed_ports=[80, 443]
    )

@pytest.mark.asyncio
async def test_http_probe_scope_gate_enforced(mock_scope, mock_gate):
    config = AdapterConfig(scope=mock_scope, target="https://example.com", options={}, scope_gate=mock_gate)
    adapter = HTTPProbeAdapter(config)

    findings = []
    async for f in adapter.run():
        findings.append(f)

    # Verify Scope Gate was called
    mock_gate.validate_outbound.assert_called_once()
```

### Integration Tests

```python
# tests/integration/test_adapter_integration.py
@pytest.mark.integration
@pytest.mark.asyncio
async def test_nmap_adapter_real_scan():
    scope = create_test_scope("10.0.0.0/8")
    config = AdapterConfig(scope=scope, target="http://10.0.0.50", options={}, scope_gate=gate)

    adapter = NmapAdapter(config)
    findings = []
    async for f in adapter.run():
        findings.append(f)

    assert len(findings) > 0
    assert all(f.adapter_name == "nmap" for f in findings)
```

---

## Troubleshooting

### Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| Adapter hangs | Tool waiting for input | Add `--batch`, `--non-interactive` flags |
| Scope Gate denial | Target IP not authorized | Add CIDR to scope, check DNS |
| Tool not found | Binary not in PATH | Install tool, check Docker image |
| Timeout | Target slow/unresponsive | Increase timeout, check network |
| Parsing errors | Tool output format changed | Update parser, pin tool version |

### Debug Mode

```bash
# Enable adapter debug logging
ISHASTRA_LOG_LEVEL=DEBUG ISHASTRA_ADAPTER_DEBUG=1 python -m ishastra

# Run single adapter manually
python -m ishastra.adapters.nmap --target http://example.com --scope scope.json
```

---

## Related

- [Built-in Adapters](../adapters/built-in.md)
- [External Tools](../adapters/external.md)
- [Custom Adapters SDK](../adapters/custom.md)
- [Scope Gate](../scope-gate/concepts.md)
- [API: Assessments](../api/assessments.md)
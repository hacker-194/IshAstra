# Custom Adapter Development

# Custom Adapter Development

Build your own security adapters with automatic Scope Gate integration.

## Overview

Custom adapters integrate seamlessly with Ishastra's adapter framework:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Custom Adapter Structure                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Your Adapter                                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ class MyAdapter(BaseAdapter):                            │   │
│  │     name = "my_adapter"                                  │   │
│  │     async def run(self) -> AsyncIterator[Finding]:      │   │
│  │         dest = await self._authorize_connection(url)   │   │
│  │         # Your logic here                                │   │
│  │         yield Finding(...)                               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            │                                     │
│                            ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                 BaseAdapter (Provides)                   │   │
│  │  ✅ Scope Gate validation (_authorize_connection)       │   │
│  │  ✅ Pinned destination connection (_connect_to_pinned)  │   │
│  │  ✅ Configuration (AdapterConfig)                       │   │
│  │  ✅ Finding normalization                               │   │
│  │  ✅ Timeout/error handling                              │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Create Adapter File

```python
# my_adapters/ssh_audit.py
from ishastra.core.adapters import BaseAdapter, AdapterConfig, Finding
from ishastra.core.scope import Severity
import asyncssh

class SSHAuditAdapter(BaseAdapter):
    name = "ssh_audit"
    version = "1.0.0"
    supported_targets = ["ssh"]

    async def run(self) -> AsyncIterator[Finding]:
        # 1. Scope Gate validation - REQUIRED
        dest = await self._authorize_connection(self.config.target)
        
        # 2. Connect to PINNED IP
        async with asyncssh.connect(
            dest.ip,
            port=dest.port,
            known_hosts=None,  # We trust the pinned IP
            client_keys=[self.config.options.get("private_key")],
            username=self.config.options.get("username", "root"),
        ) as conn:
            # 3. Run your checks
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

### 2. Register Adapter

```python
# In your application startup
from ishastra.core.adapters import adapter_registry
from my_adapters.ssh_audit import SSHAuditAdapter

adapter_registry.register(SSHAuditAdapter)
```

### 3. Use via API

```bash
curl -X POST https://api.ishastra.dev/api/v1/assessments \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "scope_id": "scope-123",
    "targets": ["ssh://server.example.com"],
    "adapters": ["ssh_audit"]
  }'
```

---

## BaseAdapter Reference

### Required Attributes

```python
class MyAdapter(BaseAdapter):
    name: str = "my_adapter"           # Unique identifier
    version: str = "1.0.0"             # Semantic version
    supported_targets: list[str] = ["http", "https"]  # URL schemes
```

### Constructor

```python
def __init__(self, config: AdapterConfig):
    self.config = config
    self.scope_gate = config.scope_gate
    self.scope = config.scope
    self.target = config.target
    self.options = config.options
```

### AdapterConfig

```python
@dataclass
class AdapterConfig:
    scope: ScopeDocument          # Active scope document
    target: str                   # Target URL
    options: dict                 # Adapter-specific options
    scope_gate: ScopeGate         # Scope Gate instance
```

### Required Method

```python
@abstractmethod
async def run(self) -> AsyncIterator[Finding]:
    """Execute adapter, yield findings"""
    pass
```

### Protected Helpers

```python
# Scope Gate validation (MUST call before connections)
async def _authorize_connection(self, url: str) -> Destination:
    return await self.scope_gate.validate_outbound(url, self.scope)

# Safe HTTP request with Scope Gate
async def _make_request(self, method: str, url: str, **kwargs) -> Response:
    dest = await self._authorize_connection(url)
    return await self._connect_to_pinned(dest, method, **kwargs)

# Low-level pinned connection
async def _connect_to_pinned(self, dest: Destination, method: str, **kwargs) -> Response:
    # Connects to dest.ip:dest.port
    # Sets Host: dest.host
    # Verifies TLS for dest.host
    pass
```

---

## Finding Model

```python
@dataclass
class Finding:
    id: str                          # Unique: ADAPTER-TYPE-VULN
    title: str                       # Human readable
    description: str                 # Detailed explanation
    severity: Severity               # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str                    # OWASP category, CWE, etc.
    location: str                    # URL, endpoint, file:line
    evidence: dict                   # Proof: request/response, data
    references: list[str]            # CVE, CWE, advisory URLs
    metadata: dict                   # Adapter-specific data
    discovered_at: datetime          # Auto-set
    adapter_name: str                # Auto-set from self.name
    adapter_version: str             # Auto-set from self.version
```

### Severity Enum

```python
class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
```

---

## Complete Example: SSH Auditor

```python
# my_adapters/ssh_audit.py
"""
SSH Security Auditor Adapter
Checks: weak ciphers, weak MACs, weak KEX, auth methods, host keys
"""
from ishastra.core.adapters import BaseAdapter, AdapterConfig, Finding
from ishastra.core.scope import Severity
import asyncssh
import re

WEAK_CIPHERS = {
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "3des-cbc", "blowfish-cbc", "cast128-cbc",
    "arcfour", "arcfour128", "arcfour256",
}

WEAK_MACS = {
    "hmac-md5", "hmac-md5-96", "hmac-sha1-96",
    "hmac-sha2-256-96", "hmac-sha2-512-96",
}

WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
}

class SSHAuditAdapter(BaseAdapter):
    name = "ssh_audit"
    version = "1.0.0"
    supported_targets = ["ssh"]

    async def run(self) -> AsyncIterator[Finding]:
        dest = await self._authorize_connection(self.config.target)
        
        # Connection options from config
        username = self.config.options.get("username", "root")
        private_key = self.config.options.get("private_key")
        password = self.config.options.get("password")
        timeout = self.config.options.get("timeout", 10)
        
        try:
            async with asyncssh.connect(
                dest.ip,
                port=dest.port,
                username=username,
                client_keys=[private_key] if private_key else None,
                password=password,
                known_hosts=None,
                connect_timeout=timeout,
            ) as conn:
                # Run all checks
                async for finding in self._check_all(conn):
                    yield finding
                    
        except asyncssh.DisconnectError as e:
            yield Finding(
                id="SSH-DISCONNECT",
                title="SSH Connection Failed",
                severity=Severity.INFO,
                category="connection",
                location=self.config.target,
                evidence={"reason": str(e)},
                references=[],
                metadata={}
            )
        except Exception as e:
            yield Finding(
                id="SSH-ERROR",
                title="SSH Audit Error",
                severity=Severity.LOW,
                category="error",
                location=self.config.target,
                evidence={"error": str(e)},
                references=[],
                metadata={}
            )

    async def _check_all(self, conn) -> AsyncIterator[Finding]:
        yield from await self._check_ciphers(conn)
        yield from await self._check_macs(conn)
        yield from await self._check_kex(conn)
        yield from await self._check_host_key(conn)
        yield from await self._check_auth_methods(conn)
        yield from await self._check_banner(conn)

    async def _check_ciphers(self, conn) -> AsyncIterator[Finding]:
        ciphers = conn.get_ciphers()
        weak = [c for c in ciphers if c in WEAK_CIPHERS]
        if weak:
            yield Finding(
                id="SSH-WEAK-CIPHER",
                title="Weak SSH Encryption Ciphers",
                description=f"Server supports weak ciphers: {', '.join(weak)}",
                severity=Severity.MEDIUM,
                category="crypto",
                location=self.config.target,
                evidence={"weak_ciphers": weak, "all_ciphers": ciphers},
                references=["https://ishastra.dev/findings/SSH-WEAK-CIPHER"],
                metadata={"check": "ciphers"}
            )

    async def _check_macs(self, conn) -> AsyncIterator[Finding]:
        macs = conn.get_macs()
        weak = [m for m in macs if m in WEAK_MACS]
        if weak:
            yield Finding(
                id="SSH-WEAK-MAC",
                title="Weak SSH MAC Algorithms",
                description=f"Server supports weak MACs: {', '.join(weak)}",
                severity=Severity.MEDIUM,
                category="crypto",
                location=self.config.target,
                evidence={"weak_macs": weak, "all_macs": macs},
                references=["https://ishastra.dev/findings/SSH-WEAK-MAC"],
                metadata={"check": "macs"}
            )

    async def _check_kex(self, conn) -> AsyncIterator[Finding]:
        kex = conn.get_kex_algorithms()
        weak = [k for k in kex if k in WEAK_KEX]
        if weak:
            yield Finding(
                id="SSH-WEAK-KEX",
                title="Weak SSH Key Exchange Algorithms",
                description=f"Server supports weak KEX: {', '.join(weak)}",
                severity=Severity.HIGH,
                category="crypto",
                location=self.config.target,
                evidence={"weak_kex": weak, "all_kex": kex},
                references=["https://ishastra.dev/findings/SSH-WEAK-KEX"],
                metadata={"check": "kex"}
            )

    async def _check_host_key(self, conn) -> AsyncIterator[Finding]:
        host_key = conn.get_host_key()
        key_type = host_key.get_algorithm()
        key_bits = host_key.get_key_size()
        
        # Check for weak key types
        if key_type in ("ssh-rsa", "ssh-dss") and key_bits < 2048:
            yield Finding(
                id="SSH-WEAK-HOST-KEY",
                title="Weak SSH Host Key",
                description=f"Host key {key_type} {key_bits} bits is below recommended 2048",
                severity=Severity.HIGH,
                category="crypto",
                location=self.config.target,
                evidence={"key_type": key_type, "key_bits": key_bits},
                references=["https://ishastra.dev/findings/SSH-WEAK-HOST-KEY"],
                metadata={"check": "host_key"}
            )

    async def _check_auth_methods(self, conn) -> AsyncIterator[Finding]:
        auth_methods = conn.get_auth_methods()
        if "password" in auth_methods:
            yield Finding(
                id="SSH-PASSWORD-AUTH",
                title="SSH Password Authentication Enabled",
                description="Server allows password authentication (should use keys only)",
                severity=Severity.MEDIUM,
                category="auth",
                location=self.config.target,
                evidence={"auth_methods": auth_methods},
                references=["https://ishastra.dev/findings/SSH-PASSWORD-AUTH"],
                metadata={"check": "auth_methods"}
            )

    async def _check_banner(self, conn) -> AsyncIterator[Finding]:
        banner = conn.get_server_version()
        if "OpenSSH" in banner:
            match = re.search(r"OpenSSH_(\d+\.\d+)", banner)
            if match:
                version = match.group(1)
                major, minor = map(int, version.split("."))
                if major < 8 or (major == 8 and minor < 6):
                    yield Finding(
                        id="SSH-OUTDATED-OPENSSH",
                        title="Outdated OpenSSH Version",
                        description=f"OpenSSH {version} may have known vulnerabilities",
                        severity=Severity.MEDIUM,
                        category="outdated",
                        location=self.config.target,
                        evidence={"version": version, "banner": banner},
                        references=["https://www.openssh.com/security.html"],
                        metadata={"check": "banner"}
                    )
```

---

## SDK Helper Functions

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

### run_adapter_safely

```python
async def run_adapter_safely(
    adapter_class: type[BaseAdapter],
    config: AdapterConfig,
    timeout: int = 300,
    max_findings: int = 1000,
) -> list[Finding]:
    """Run adapter with timeout, error handling, finding limit"""
    findings = []
    adapter = adapter_class(config)
    
    try:
        async with asyncio.timeout(timeout):
            async for finding in adapter.run():
                findings.append(finding)
                if len(findings) >= max_findings:
                    break
    except asyncio.TimeoutError:
        findings.append(Finding(
            id=f"{adapter.name}-TIMEOUT",
            title="Adapter Timeout",
            severity=Severity.LOW,
            category="error",
            location=config.target,
            evidence={"timeout": timeout},
            references=[],
            metadata={}
        ))
    except Exception as e:
        findings.append(Finding(
            id=f"{adapter.name}-ERROR",
            title="Adapter Error",
            severity=Severity.LOW,
            category="error",
            location=config.target,
            evidence={"error": str(e)},
            references=[],
            metadata={}
        ))
    
    return findings
```

---

## Testing Custom Adapters

### Unit Test Template

```python
# tests/test_ssh_audit.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from my_adapters.ssh_audit import SSHAuditAdapter
from ishastra.core.adapters import AdapterConfig
from ishastra.core.scope import ScopeDocument

@pytest.fixture
def mock_scope():
    return ScopeDocument(
        version=2,
        authorized_networks=["10.0.0.0/8"],
        include_hosts=["example.com"],
        allowed_ports=[22]
    )

@pytest.fixture
def mock_gate():
    gate = AsyncMock()
    gate.validate_outbound.return_value = Destination(
        scheme="ssh", host="example.com", port=22,
        ip="10.0.0.50", resolved_at=0, ttl=300
    )
    return gate

@pytest.mark.asyncio
async def test_ssh_audit_weak_ciphers(mock_scope, mock_gate):
    config = AdapterConfig(
        scope=mock_scope,
        target="ssh://example.com",
        options={"username": "test"},
        scope_gate=mock_gate
    )
    
    adapter = SSHAuditAdapter(config)
    
    # Mock asyncssh connection
    with patch("asyncssh.connect") as mock_connect:
        mock_conn = AsyncMock()
        mock_conn.get_ciphers.return_value = ["aes128-cbc", "aes256-gcm"]
        mock_conn.get_macs.return_value = ["hmac-sha2-256"]
        mock_conn.get_kex_algorithms.return_value = ["curve25519-sha256"]
        mock_conn.get_host_key.return_value = MagicMock(
            get_algorithm=MagicMock(return_value="ssh-ed25519"),
            get_key_size=MagicMock(return_value=256)
        )
        mock_conn.get_auth_methods.return_value = ["publickey"]
        mock_conn.get_server_version.return_value = "OpenSSH_9.2"
        
        mock_connect.return_value.__aenter__.return_value = mock_conn
        
        findings = []
        async for f in adapter.run():
            findings.append(f)
    
    # Verify Scope Gate was called
    mock_gate.validate_outbound.assert_called_once()
    
    # Verify weak cipher finding
    weak_cipher_findings = [f for f in findings if f.id == "SSH-WEAK-CIPHER"]
    assert len(weak_cipher_findings) == 1
    assert "aes128-cbc" in weak_cipher_findings[0].evidence["weak_ciphers"]
```

### Integration Test

```python
# tests/integration/test_custom_adapter.py
@pytest.mark.integration
@pytest.mark.asyncio
async def test_ssh_audit_real_server(test_ssh_server, test_scope):
    config = AdapterConfig(
        scope=test_scope,
        target=f"ssh://{test_ssh_server.host}:{test_ssh_server.port}",
        options={"username": "testuser", "password": "testpass"},
        scope_gate=test_gate
    )
    
    adapter = SSHAuditAdapter(config)
    findings = []
    async for f in adapter.run():
        findings.append(f)
    
    assert len(findings) > 0
    assert all(f.adapter_name == "ssh_audit" for f in findings)
```

---

## Packaging & Distribution

### Project Structure

```
my-ishastra-adapters/
├── pyproject.toml
├── src/
│   └── my_ishastra_adapters/
│       ├── __init__.py
│       ├── ssh_audit.py
│       ├── tls_check.py
│       └── dns_audit.py
├── tests/
│   ├── test_ssh_audit.py
│   └── test_tls_check.py
└── README.md
```

### pyproject.toml

```toml
[project]
name = "my-ishastra-adapters"
version = "1.0.0"
description = "Custom Ishastra security adapters"
requires-python = ">=3.12"
dependencies = [
    "ishastra-core>=3.5.0",
    "asyncssh>=2.14",
]

[project.entry-points."ishastra.adapters"]
ssh_audit = "my_ishastra_adapters.ssh_audit:SSHAuditAdapter"
tls_check = "my_ishastra_adapters.tls_check:TLSCheckAdapter"
dns_audit = "my_ishastra_adapters.dns_audit:DNSAuditAdapter"
```

### Auto-registration

```python
# src/my_ishastra_adapters/__init__.py
from ishastra.core.adapters import adapter_registry

def register_all():
    from .ssh_audit import SSHAuditAdapter
    from .tls_check import TLSCheckAdapter
    from .dns_audit import DNSAuditAdapter
    
    adapter_registry.register(SSHAuditAdapter)
    adapter_registry.register(TLSCheckAdapter)
    adapter_registry.register(DNSAuditAdapter)

# Call on import
register_all()
```

---

## Best Practices

### 1. Always Use Scope Gate

```python
# ✅ GOOD
dest = await self._authorize_connection(url)
async with asyncssh.connect(dest.ip, ...) as conn:
    ...

# ❌ BAD - Bypasses authorization
async with asyncssh.connect(url, ...) as conn:
    ...
```

### 2. Handle Errors Gracefully

```python
try:
    async with asyncssh.connect(...) as conn:
        yield from checks
except asyncssh.DisconnectError:
    yield Finding(id="...", severity=Severity.INFO, ...)
except Exception as e:
    yield Finding(id="...", severity=Severity.LOW, evidence={"error": str(e)}, ...)
```

### 3. Use Structured Evidence

```python
yield Finding(
    evidence={
        "raw_output": "...",      # Tool raw output
        "parsed": {...},          # Structured data
        "context": {...},         # Additional context
    }
)
```

### 4. Limit Findings

```python
MAX_FINDINGS_PER_CHECK = 50

async def _check_something(self):
    count = 0
    for issue in issues:
        if count >= MAX_FINDINGS_PER_CHECK:
            break
        yield Finding(...)
        count += 1
```

### 5. Add References

```python
references=[
    "https://cwe.mitre.org/data/definitions/326.html",
    "https://owasp.org/www-community/attacks/...",
    "https://ishastra.dev/findings/SSH-WEAK-CIPHER",
]
```

---

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| Adapter not found | Not registered | Call `adapter_registry.register()` |
| Scope Gate DENY | Target IP not in scope | Add CIDR to scope |
| Import error | Missing dependency | Add to pyproject.toml |
| Timeout | Check too slow | Increase timeout, optimize |
| No findings | Logic error | Add debug logging |

---

## Related

- [Built-in Adapters](../adapters/built-in.md)
- [External Tools](../adapters/external.md)
- [Adapter SDK](../adapters/sdk.md)
- [Architecture: Adapters](../architecture/adapters.md)
- [Scope Gate](../scope-gate/concepts.md)
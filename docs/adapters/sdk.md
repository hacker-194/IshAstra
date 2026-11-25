# Adapter SDK Reference

# Adapter SDK Reference

Complete API reference for building custom adapters.

## Core Classes

### BaseAdapter

```python
from ishastra.core.adapters import BaseAdapter, AdapterConfig, Finding
from ishastra.core.scope import Severity, Destination, ScopeDocument
from typing import AsyncIterator

class BaseAdapter(ABC):
    # Class attributes (required)
    name: str
    version: str
    supported_targets: list[str]
    
    # Instance attributes (set by constructor)
    config: AdapterConfig
    scope_gate: ScopeGate
    scope: ScopeDocument
    target: str
    options: dict
    
    def __init__(self, config: AdapterConfig):
        ...
    
    @abstractmethod
    async def run(self) -> AsyncIterator[Finding]:
        ...
    
    # Protected helpers
    async def _authorize_connection(self, url: str) -> Destination:
        ...
    
    async def _make_request(self, method: str, url: str, **kwargs) -> Response:
        ...
    
    async def _connect_to_pinned(self, dest: Destination, method: str, **kwargs) -> Response:
        ...
```

### AdapterConfig

```python
@dataclass
class AdapterConfig:
    scope: ScopeDocument          # Active scope document
    target: str                   # Target URL (e.g., "https://api.example.com")
    options: dict                 # Adapter-specific options from assessment config
    scope_gate: ScopeGate         # Scope Gate instance for validation
```

### Finding

```python
@dataclass
class Finding:
    # Required fields
    id: str                       # Unique identifier: ADAPTER-TYPE-VULN
    title: str                    # Human-readable title
    description: str              # Detailed description
    severity: Severity            # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str                 # Category: crypto, auth, injection, etc.
    location: str                 # URL, endpoint, or file:line
    evidence: dict                # Structured proof data
    references: list[str]         # Reference URLs (CVE, CWE, advisories)
    metadata: dict                # Adapter-specific metadata
    
    # Auto-populated
    discovered_at: datetime       # Set on creation
    adapter_name: str             # Set from adapter.name
    adapter_version: str          # Set from adapter.version
```

### Severity

```python
class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
```

### Destination

```python
@dataclass(frozen=True)
class Destination:
    scheme: str                   # "http", "https", "ssh", etc.
    host: str                     # Original hostname
    port: int                     # Destination port
    ip: str                       # PINNED IP address (validated)
    resolved_at: float            # Unix timestamp
    ttl: int                      # Remaining TTL in seconds
```

### ScopeDocument

```python
@dataclass
class ScopeDocument:
    version: int                  # Must be 2
    metadata: ScopeMetadata
    authorized_networks: list[str]  # CIDR allowlist
    include_hosts: list[str]      # Host allowlist (suffix match)
    exclude_hosts: list[str]      # Host blocklist (suffix match)
    allowed_ports: list[int]      # Port allowlist
    dns_resolver: str             # "system", "cloudflare", "google", "quad9", "custom"
    dns_timeout: int              # Seconds
    dns_servers: list[str]        # Custom DNS servers
    break_glass: BreakGlassConfig # Emergency access config
    signing: SigningConfig        # Ed25519 signing config
```

---

## Scope Gate API

### ScopeGate

```python
class ScopeGate:
    def __init__(
        self,
        scope: ScopeDocument,
        cache_ttl: int = 300,
        max_cache_size: int = 10000,
        observers: list[GateObserver] = None,
    ):
        ...
    
    async def validate_outbound(self, url: str, scope: ScopeDocument = None) -> Destination:
        """
        Validate outbound connection through all three layers.
        
        Args:
            url: Target URL to validate
            scope: Optional scope override (uses instance scope if not provided)
            
        Returns:
            Destination: Pinned destination for connection
            
        Raises:
            AuthorizationError: If any layer denies
            ResolutionError: If DNS resolution fails
        """
        ...
    
    def validate_config(self) -> bool:
        """Validate scope document configuration"""
        ...
    
    @classmethod
    def from_file(cls, path: str, **kwargs) -> "ScopeGate":
        """Create ScopeGate from scope file"""
        ...
```

### AuthResult

```python
@dataclass
class AuthResult:
    decision: Decision            # ALLOW, DENY, DEFER
    reason: str                   # Reason for decision
    layer: int                    # Layer that produced result (1, 2, 3)
    addresses: list[str] | None   # Resolved IPs (Layer 2/3)
```

### Decision

```python
class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    DEFER = "defer"
```

---

## Observer API

### GateObserver Protocol

```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class GateObserver(Protocol):
    def on_check(self, ctx: CheckContext, result: AuthResult):
        """Called for every Layer 1/2/3 check"""
        ...
    
    def on_destination(self, ctx: CheckContext, dest: Destination):
        """Called when Layer 3 returns pinned destination"""
        ...
    
    def on_error(self, ctx: CheckContext, error: Exception):
        """Called on resolution/validation errors"""
        ...
```

### CheckContext

```python
@dataclass
class CheckContext:
    task_id: str                  # Unique task identifier
    scope_id: str                 # Scope document ID
    url: str                      # Original URL
    layer: int                    # 1, 2, or 3
    timestamp: float              # Unix timestamp
    metadata: dict                # Custom fields
```

### IshAstraProofObserver

```python
class IshAstraProofObserver:
    def __init__(
        self,
        signer: Ed25519PrivateKey,
        key_id: str,
        storage: ProofStorage,
        jwks_manager: JWKSManager,
    ):
        ...
    
    def on_check(self, ctx: CheckContext, result: AuthResult):
        ...
    
    def on_destination(self, ctx: CheckContext, dest: Destination):
        ...
    
    def finalize_proof(self, assessment_id: str, grant_receipt: GrantReceipt) -> ProofReceipt:
        ...
```

---

## Registry API

### Adapter Registry

```python
from ishastra.core.adapters import adapter_registry

# Register custom adapter
adapter_registry.register(MyAdapter)

# Get adapter class by name
adapter_class = adapter_registry.get("my_adapter")

# List all registered adapters
adapters = adapter_registry.list()

# Check if adapter exists
exists = adapter_registry.has("my_adapter")
```

---

## Utility Functions

### run_adapter_safely

```python
from ishastra.core.adapters import run_adapter_safely

findings = await run_adapter_safely(
    adapter_class=MyAdapter,
    config=config,
    timeout=300,           # Seconds
    max_findings=1000,     # Finding limit
)
```

### parse_target_url

```python
from ishastra.core.adapters import parse_target_url

parsed = parse_target_url("https://api.example.com:8443/path?query=1")
# Returns ParsedURL(scheme="https", host="api.example.com", port=8443, path="/path", query="query=1")
```

### build_finding_id

```python
from ishastra.core.adapters import build_finding_id

fid = build_finding_id("my_adapter", "weak_cipher", "aes128-cbc")
# Returns "MY_ADAPTER-WEAK_CIPHER-AES128_CBC"
```

---

## Finding Helpers

### Standard Categories

Use consistent categories for better organization:

| Category | Use For |
|----------|---------|
| `crypto` | Weak ciphers, certificates, key exchange |
| `auth` | Authentication bypass, weak auth |
| `injection` | SQLi, command injection, XSS |
| `headers` | Missing security headers |
| `network` | Open ports, services |
| `config` | Misconfigurations, defaults |
| `outdated` | Old versions, EOL software |
| `exposure` | Information disclosure, sensitive files |
| `business` | Business logic flaws |
| `rate_limit` | Rate limiting issues |
| `csrf` | CSRF vulnerabilities |
| `idor` | Insecure Direct Object References |

### Evidence Structure

```python
evidence = {
    "raw_output": "...",           # Tool raw output (truncated)
    "parsed": {...},               # Structured parsed data
    "request": {...},              # Request that triggered finding
    "response": {...},             # Response showing issue
    "context": {...},              # Additional context
    "remediation": "Fix by...",    # Suggested fix
}
```

### Reference URLs

Include standard references:

```python
references = [
    "https://cwe.mitre.org/data/definitions/XXX.html",  # CWE
    "https://owasp.org/www-community/...",               # OWASP
    "https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX",   # CVE
    "https://example.com/findings/ADAPTER-TYPE-VULN",     # IshAstra finding docs
]
```

---

## Configuration Schema

### Adapter Options in Assessment

```json
{
  "adapters": {
    "my_adapter": {
      "option1": "value1",
      "option2": 42,
      "nested": {
        "key": "value"
      }
    }
  }
}
```

### Accessing Options in Adapter

```python
class MyAdapter(BaseAdapter):
    async def run(self):
        option1 = self.options.get("option1", "default")
        option2 = self.options.get("option2", 0)
        nested = self.options.get("nested", {})
        ...
```

### Scope Document Options

```json
{
  "version": 2,
  "metadata": {...},
  "authorized_networks": [...],
  "adapter_options": {
    "my_adapter": {
      "global_option": "value"
    }
  }
}
```

```python
# Access scope-level options
scope_options = self.scope.adapter_options.get("my_adapter", {})
```

---

## Error Handling

### Standard Exceptions

```python
from ishastra.core.adapters import (
    AdapterError,
    AuthorizationError,
    ResolutionError,
    TimeoutError,
    ConfigurationError,
)
```

### Error Finding Pattern

```python
async def run(self) -> AsyncIterator[Finding]:
    try:
        dest = await self._authorize_connection(self.config.target)
        async for finding in self._do_checks(dest):
            yield finding
    except AuthorizationError as e:
        yield Finding(
            id=f"{self.name}-AUTH-DENIED",
            title="Scope Gate Authorization Denied",
            severity=Severity.INFO,
            category="authorization",
            location=self.config.target,
            evidence={"reason": str(e)},
            references=[],
            metadata={"gate_error": True}
        )
    except ResolutionError as e:
        yield Finding(
            id=f"{self.name}-DNS-FAILED",
            title="DNS Resolution Failed",
            severity=Severity.LOW,
            category="error",
            location=self.config.target,
            evidence={"error": str(e)},
            references=[],
            metadata={}
        )
    except Exception as e:
        yield Finding(
            id=f"{self.name}-ERROR",
            title="Adapter Error",
            severity=Severity.LOW,
            category="error",
            location=self.config.target,
            evidence={"error": str(e), "type": type(e).__name__},
            references=[],
            metadata={}
        )
```

---

## Async Patterns

### Concurrent Requests

```python
async def _check_multiple_endpoints(self, endpoints: list[str]):
    semaphore = asyncio.Semaphore(10)
    
    async def check_one(endpoint):
        async with semaphore:
            dest = await self._authorize_connection(endpoint)
            return await self._make_request("GET", endpoint)
    
    tasks = [check_one(ep) for ep in endpoints]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for endpoint, result in zip(endpoints, results):
        if isinstance(result, Exception):
            yield Finding(...)
        else:
            yield from self._analyze_response(result)
```

### Pagination Handling

```python
async def _fetch_all_pages(self, base_url: str):
    page = 1
    while True:
        url = f"{base_url}?page={page}"
        dest = await self._authorize_connection(url)
        resp = await self._make_request("GET", url)
        
        data = resp.json()
        yield from self._process_page(data)
        
        if not data.get("has_next"):
            break
        page += 1
```

---

## Testing Utilities

### Mock Scope Gate

```python
from unittest.mock import AsyncMock
from ishastra.core.scope import Destination

def create_mock_gate(dest_ip="10.0.0.50"):
    gate = AsyncMock()
    gate.validate_outbound.return_value = Destination(
        scheme="https",
        host="example.com",
        port=443,
        ip=dest_ip,
        resolved_at=time.time(),
        ttl=300
    )
    return gate
```

### Test Config Factory

```python
def create_test_config(
    target="https://example.com",
    networks=["10.0.0.0/8"],
    options={},
    scope_id="test-scope"
):
    from ishastra.core.scope import ScopeDocument, ScopeMetadata
    from ishastra.core.adapters import AdapterConfig
    
    scope = ScopeDocument(
        version=2,
        metadata=ScopeMetadata(name="Test", owner="test@example.com"),
        authorized_networks=networks,
    )
    
    return AdapterConfig(
        scope=scope,
        target=target,
        options=options,
        scope_gate=create_mock_gate()
    )
```

---

## Version Compatibility

| IshAstra Version | SDK Version | Notes |
|---------------|-------------|-------|
| 3.5.x | 1.0.x | Current |
| 3.4.x | 0.9.x | Legacy |
| 3.3.x | 0.8.x | Deprecated |

Check compatibility:

```python
import ishastra
print(ishastra.__version__)  # "3.5.0"
```

---

## Related

- [Custom Adapters](../adapters/custom.md)
- [Built-in Adapters](../adapters/built-in.md)
- [External Tools](../adapters/external.md)
- [Architecture: Adapters](../architecture/adapters.md)
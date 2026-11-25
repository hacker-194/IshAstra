# ishastra-adapter-hello

Minimal Ishastra adapter example — demonstrates the complete adapter contract.

## Install

```bash
pip install -e examples/adapter-hello
```

Or from a clean venv:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e examples/adapter-hello
```

## Verify Installation

After installing, the adapter appears in the Ishastra adapter registry:

```bash
# List all registered adapters
ishastra adapter list

# Or via Python
python -c "
from ishastra.core.adapters import adapter_registry
print(adapter_registry.list())
# ['hello', 'http', 'nuclei', 'nikto', 'sqlmap', ...]
"
```

## Run the Adapter Directly

```bash
python -m ishastra_adapter_hello
```

Output:
```
Finding(id='HELLO-REACHABLE', title='Target reachable via Scope Gate', severity=<Severity.INFO: 'info'>, category='network', location='https://httpbin.org/get', evidence={'pinned_ip': '...', 'port': 443, 'scheme': 'https', 'resolved_at': ...}, references=['https://ishastra.dev/docs/adapters/sdk'], metadata={'adapter_version': '0.1.0', 'gate_layer': 3})
```

## Use in an Assessment

```bash
# Create a scope allowing httpbin.org
cat > scope.json << 'EOF'
{
  "version": 2,
  "program": "Hello Adapter Demo",
  "authorized_by": "Test User",
  "authorization_ref": "hello-2024-001",
  "include": ["httpbin.org"],
  "exclude": [],
  "authorized_networks": ["0.0.0.0/0"],
  "allowed_ports": [443],
  "allow_broad_networks": false
}
EOF

# Run assessment with the hello adapter
ishastra assess run \
  --target https://httpbin.org/get \
  --scope scope.json \
  --profile web \
  --output result.sarif
```

The SARIF output will include the `HELLO-REACHABLE` finding alongside built-in adapter findings.

## Adapter Contract

This example demonstrates the minimal required implementation:

1. **Inherit from `BaseAdapter`** — provides Scope Gate integration, HTTP helpers, finding emission
2. **Define class attributes** — `name`, `version`, `supported_targets`
3. **Implement `async def run(self) -> AsyncIterator[Finding]`** — the only required method
4. **Use `self._authorize_connection()`** — validates target through all 3 Scope Gate layers
5. **Yield `Finding` objects** — structured results with evidence, references, metadata
6. **Register via entry point** — `pyproject.toml` `[project.entry-points."ishastra.adapters"]`

## Files

| File | Purpose |
|------|---------|
| `pyproject.toml` | Package metadata + entry point registration |
| `ishastra_adapter_hello.py` | Adapter implementation (~50 lines) |
| `README.md` | This file |

## Next Steps

- Add adapter-specific options via `self.options` (from assessment config)
- Implement concurrent checks with `asyncio.Semaphore`
- Add pagination handling for API targets
- Write unit tests using `create_mock_gate()` and `create_test_config()` from SDK docs

See [Adapter SDK Reference](https://ishastra.dev/docs/adapters/sdk) for full API.
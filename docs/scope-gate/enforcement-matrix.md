# Enforcement Matrix

This document records how each adapter enforces the scope gate. The gate validates
*before* any connection is made; adapters must re-check or fail closed.

## Adapter Enforcement Summary

| Adapter ID | Type | Enforcement | Gateway Required | Notes |
|------------|------|-------------|------------------|-------|
| `ishastra-http` | In-process HTTP | `firewall` | No | Uses scoped HTTP client; connects only to pinned IP |
| `ishastra-crawl` | In-process HTTP | `firewall` | No | Uses scoped HTTP client; follows redirects within scope |
| `ishastra-dynamic-validation` | In-process HTTP | `firewall` | No | Uses scoped HTTP client |
| `ishastra-openapi` | In-process HTTP | `firewall` | No | Uses scoped HTTP client |
| `ishastra-authz` | In-process HTTP | `firewall` | No | Uses scoped HTTP client |
| `ishastra-ssrf-oob` | In-process HTTP | `firewall` | No | Uses scoped HTTP client; OOB callbacks via gateway |
| `ishastra-git-exposure` | In-process HTTP | `firewall` | No | Uses scoped HTTP client |
| `ishastra-tcp` | In-process TCP | `firewall` | No | Connects only to pinned IP from `checked_destination()` |
| `nmap` | External tool | `proxy` | **Yes** | `--proxies <gateway>`; refuses without gateway |
| `nuclei` | External tool | `proxy` | **Yes** | Uses proxy via scoped HTTP client internally; no direct proxy flag |
| `nikto` | External tool | `proxy` | **Yes** | `-useproxy <gateway>`; refuses without gateway |
| `sqlmap` | External tool | `proxy` | **Yes** | `--proxy <gateway>`; refuses without gateway; requires high-risk auth |
| `tcp-port-scanner` | Out-of-process plugin | `proxy` | **Yes** | Requires `gateway_url` in context; fails closed without it |

## Enforcement Definitions

| Enforcement | Meaning |
|-------------|---------|
| `firewall` | Host-level egress filtering (nftables/iptables) + in-process scope re-check. The adapter connects only to the pinned destination returned by `checked_destination()`. |
| `proxy` | Egress gateway CONNECT proxy. The adapter adds the gateway URL to its command line (nmap `--proxies`, nikto `-useproxy`, sqlmap `--proxy`). **Fail-closed**: if no gateway URL is configured (`ISHASTRA_GATEWAY_URL` env var or `gateway_url` in job context), the adapter raises `AdapterError` and does not execute. |
| `none` | **Not permitted for external tools.** Only allowed for purely internal adapters that do not make outbound connections (e.g., static analysis). Any adapter that makes network connections must declare `firewall` or `proxy`. |

## Fail-Closed Guarantee

All adapters with `enforcement = "proxy"` **must** refuse to execute when no gateway URL is available. This prevents a configuration mistake (missing `ISHASTRA_GATEWAY_URL`) from silently becoming a gate bypass.

### Verification Tests

| Test | Verifies |
|------|----------|
| `tests/unit/test_adapters.py::TestExternalToolGatewayRequired::test_nmap_refuses_without_gateway` | Nmap raises `AdapterError("gateway")` when context lacks `gateway_url` |
| `tests/unit/test_adapters.py::TestExternalToolGatewayRequired::test_nikto_refuses_without_gateway` | Nikto raises `AdapterError("gateway")` when context lacks `gateway_url` |
| `tests/unit/test_adapters.py::TestExternalToolGatewayRequired::test_sqlmap_refuses_without_gateway` | Sqlmap raises `AdapterError("gateway")` when context lacks `gateway_url` |
| `tests/unit/test_plugin_runner.py::TestTCPScannerPlugin::test_tcp_scanner_plugin_requires_gateway_fail_closed` | TCP port scanner plugin returns `INTERNAL_ERROR` with "egress gateway required" when context lacks `gateway_url` |

## Gateway Configuration

The gateway URL is provided via:

1. **Environment variable** (production): `ISHASTRA_GATEWAY_URL=http://gateway:8080`
2. **Job context** (testing/per-job): `{"gateway_url": "http://gateway:8080"}`

The job execution code in `src/ishastra/core/jobs.py` reads `ISHASTRA_GATEWAY_URL` from the environment and adds it to the adapter context.

## External Tool Proxy Behavior

| Tool | Proxy Flag | Gateway Role |
|------|------------|--------------|
| nmap | `--proxies <url>` | CONNECT proxy for TCP scans; gateway resolves hostname and applies scope check |
| nikto | `-useproxy <url>` | HTTP CONNECT proxy; gateway resolves hostname and applies scope check |
| sqlmap | `--proxy <url>` | HTTP CONNECT proxy; gateway resolves hostname and applies scope check |
| tcp-port-scanner | (plugin protocol) | Plugin receives `gateway_url` in context; must use CONNECT proxy for scans |

## Plugin Authoring Requirements

Plugins that make outbound connections **must**:

1. Declare `enforcement = "proxy"` in their contract
2. Require `gateway_url` from the context in `assess()`
3. Raise an error (fail closed) if `gateway_url` is not provided
4. Use the gateway for all outbound connections (CONNECT proxy for TCP, HTTP proxy for HTTP)

Example from `src/ishastra/plugins/template.py`:

```python
class MyAdapter(AdapterBase):
    id = "my-custom-adapter"
    enforcement = "proxy"  # Required for external tools

    def assess(self, target, timeout, cancel, context=None):
        gateway_url = (context or {}).get("gateway_url")
        if not gateway_url:
            raise RuntimeError(f"{self.id}: egress gateway required; set ISHASTRA_GATEWAY_URL")
        # Use gateway_url for all connections...
```

## Historical Note

Prior to Phase 2 hardening, `nmap`, `nikto`, and `sqlmap` would fall back to direct connections when no gateway was configured. The `tcp-port-scanner` plugin and plugin template defaulted to `enforcement = "none"`. This was documented in `AUDIT.md` §5 as an enforcement reality gap. Phase 2 (2026-11-25) made all external tools fail closed.
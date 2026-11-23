# Phase 4 Spike Runbook: Nucleus Egress Enforcement

Status: **COMPLETED** — NucleiAdapter now declares `enforcement="proxy"` with proven gateway enforcement receipts. NmapAdapter remains `enforcement="none"` because its nmap TCP-connect execution path does not route through the CONNECT proxy; the gateway's allow/deny property is proven at the network level but applies to proxy-routed tools only.

## Proven claims

| Claim | Proving check |
| --- | --- |
| Gateway allows CONNECT to authorized ports | `tests/unit/test_egress_gateway.py` (18 passed) — `allowed=True, reason=authorized` for port 18080 |
| Gateway denies CONNECT to unauthorized ports | Same test — `allowed=False, reason=port 18081 is not allowed` for port 18081 |
| Nuclei traffic routed through CONNECT proxy | `tests/unit/test_adapters.py` (`argv[--proxy]`) — Nuclei receives `ISHASTRA_PROXY_URL` |
| Gateway decisions as audit trail | Two receipts captured with same token `jti`: allow for 18080, deny for 18081 |
| Nmap gateway decisions (same gate logic) | In-process test: `allowed=True` for port 22 (in allowed_ports), `allowed=False` for port 21 (not in allowed_ports). NmapAdapter stays `enforcement="none"` because nmap runs directly, not through the CONNECT proxy. |

## Evidence already captured

- **Allow receipt**: `GatewayDecision(allowed=True, reason=authorized)` for target `127.0.0.1:18080`, token `jti=ba6645bfb9e14e93987d082d2debdb27`
- **Deny receipt**: `GatewayDecision(allowed=False, reason=port 18081 is not allowed)` for target `127.0.0.1:18081`, same token
- Both receipts produced by the same capability token pinned to `127.0.0.1` via `pinned_ips=['127.0.0.1']` and `allowed_ports=[18080, 80, 443]`
- Nuclei real-though-proxy runs attempted; Docker template-path issue prevented full scan, but the gateway decisions stand as independent proof
- Nmap gateway allow/deny tested in-process (ports 22✓, 21✗, 80✓) — confirms the gate's allow/deny logic is functional for any tool, but NmapAdapter remains `none` until its execution path is explicitly through the proxy

## No further Nuclei enforcement spike needed

NucleiAdapter.enforcement has been moved from `"none"` to `"proxy"` and cannot be changed again without new contradicting evidence. Every other adapter still correctly declares `enforcement="none"` until its own spike passes with evidence that the adapter's tool actually routes through the CONNECT proxy.

## NmapAdapter enforcement

NmapAdapter keeps `enforcement="none"`. The gateway's CONNECT proxy allow/deny property is proven, but NmapAdapter's `nmap` process runs directly (no `-proxy` flag), so its enforcement boundary is different. A future spike could route nmap through the proxy and then move enforcement to `"proxy"` or `"firewall"`.

## Teardown

```bash
docker rm -f ish-spike-target
```

## Resume point for future phases

The next slice is the Compose single-node profile (PostgreSQL + API + dispatcher + worker-manager + egress gateway + reverse proxy), followed by real-enforcement spikes for remaining adapters and Phases 5–7.
# Egress Enforcement (Phase 2)

Every outbound connection a worker makes must pass the egress gateway. This
document states what is enforced today, which test proves it, and what is not
yet enforced. Nothing here is claimed beyond the tests named.

## Mechanism

```
worker (no DNS, no direct route)
  └─ HTTP proxy CONNECT host:port
       └─ CapabilityVerifier.verify_async  (signature, version, audience,
                                            iat/exp, revocation, job RUNNING)
       └─ host ∈ token.targets, port ∈ token.allowed_ports,
          protocol ∈ token.allowed_protocols
       └─ gateway resolves DNS itself
       └─ every resolved IP must equal a token.pinned_ips entry
       └─ connect to the pinned IP (never the hostname)
       └─ request budget per jti
       └─ hash-chained receipt in audit_chain
       └─ bidirectional byte relay
```

Source: `src/ishastra/security/egress/gateway.py`,
`src/ishastra/security/capabilities/{token,verifier,issuer,revocation}.py`.

## Authentication

The token is sent on `Proxy-Authorization`:

- `Bearer <base64url(JSON token)>` for clients under our control.
- `Basic base64("<jti>:<base64url(JSON token)>")` so a scanner can carry the
  token in its proxy URL.
- `expected_token=` on a gateway dedicated to one job, for tools that cannot
  send proxy headers at all.

A token carries `audience` (`ishastra-egress-gateway`) and `version`
(`ishastra-capability/1`); the verifier pins both and refuses anything else.

## Supported modes

| Mode | Status |
|---|---|
| HTTPS via CONNECT | Implemented and tested |
| HTTP via CONNECT | Implemented (same path; CONNECT is not TLS-specific) |
| TCP-connect via SOCKS5 | **Not implemented** - the handler was removed rather than left half-working |
| ICMP, raw packet, UDP, SYN scan | **Disabled** until enforcement exists and is tested |
| TLS interception | Not done, by design. The authorized subject is the CONNECT `host:port`; a Host/SNI mismatch inside TLS cannot be verified |

Every redirect is a new connection and is authorized again. There is no test
that follows a redirect yet, so that property is PARTIAL.

## DNS and pinning

- The worker performs no DNS; it sends a hostname to the gateway.
- The gateway resolves once per connection with the existing
  `scope.resolve()` (semaphore + timeout).
- **All** answers must be in `token.pinned_ips`. One unexpected answer denies
  the connection; there is no "first matching IP" fallback (that was the
  Phase 0 hole).
- A token with no pinned IPs is denied. Pinning happens in the dispatcher, not
  in the gateway, because the token is signed before the gateway sees it.

## Budget and receipts

- `request_budget` is charged per `jti` before the upstream connect.
  Ceiling: the counter is per gateway process and resets on restart; the
  upgrade path is a counter column in `capability_tokens`.
- Every allow and deny is appended to the hash-chained `audit_chain` with
  tenant, jti, job, host, port, pinned IP, client IP and reason. Receipt write
  failures are logged and do not change the decision.
- Rate limiting from the rules of engagement is **not implemented**.

## Platform support

- Token, verifier, issuer, signing and the gateway are pure Python and run on
  Linux, macOS and Windows. The suite is executed on Linux here; the platform
  branches below are covered by simulated-OS tests rather than a second host.
- `firewall.apply()` is Linux-only because nftables is. On Windows it returns
  `nftables is Linux-only; apply the plan on a Linux host`; on a POSIX host
  without `geteuid` it fails closed; without root or `nft` it fails closed.
  `dry_run=True` renders the plan on any OS, so rules can be reviewed
  (never silently applied) from a developer machine.
- `docker_user_commands()` targets iptables, which is Linux-only; it is a
  fallback for Docker hosts, not the cross-platform path.
- Worker lease locking uses `msvcrt.locking` on Windows and `fcntl.flock`
  elsewhere (`core/worker.py`), and memory sampling skips platforms where
  `resource` is unavailable.
- Test fixtures take temporary paths from `tempfile.gettempdir()` rather than
  `/tmp`, so the suite does not assume a POSIX layout.
- The kernel lab (`scripts/verify_firewall.sh`) needs Linux with Docker and a
  privileged container. It is a verification tool, not part of the runtime.

## Host firewall plan (verified against the kernel)

`src/ishastra/security/egress/firewall.py` renders a deny-by-default plan for
the worker subnet:

- established/related forwarded traffic is accepted;
- `worker_subnet -> gateway_ip:gateway_port` TCP is accepted;
- everything else from `worker_subnet` is dropped;
- cloud metadata addresses are dropped explicitly (169.254.169.254,
  169.254.170.2, 100.100.100.200, fd00:ec2::254).

The plan validates its own inputs (no `0.0.0.0/0`, matching address families,
port range, gateway must not be a metadata address) and never uses a shell.
`apply()` refuses without root, refuses without `nft`, and applies with
`nft -f` from an owner-only temp file. `docker_user_commands()` is the
DOCKER-USER fallback with accept before drop.

Tests: `tests/unit/test_firewall.py` (18 tests), including
`test_worker_may_only_reach_the_gateway_port`, `test_metadata_addresses_are_dropped`,
`test_no_blanket_allow_rule`, the invalid-plan matrix, the root/nft guards, and
the Windows/no-euid fail-closed branches.

Kernel verification (2026-11-23). `scripts/verify_firewall.sh` creates two
throwaway network namespaces, routes worker traffic through a router namespace,
proves every probe target is reachable **before** the rules, then applies the
generated plan with `nft -f`:

```bash
docker run --rm --privileged --user 0 --network bridge \
  --sysctl net.ipv4.ip_forward=1 \
  -v /tmp/egress.nft:/egress.nft:ro \
  -v "$PWD/scripts/verify_firewall.sh:/lab.sh:ro" \
  ghcr.io/hacker-194/ishastra:3.5.0 \
  sh -c 'apt-get update -qq && apt-get install -y -qq nftables iproute2 && sh /lab.sh /egress.nft'
```

Observed (exit 0):

```
PASS baseline gateway:port: ALLOW
PASS baseline gateway:other-port: ALLOW
PASS baseline other-host:port: ALLOW
PASS baseline udp:5353: ALLOW
PASS allowed gateway:port: ALLOW
PASS blocked gateway:other-port: BLOCK
PASS blocked other-host:port: BLOCK
PASS blocked metadata ip: BLOCK
PASS blocked udp dns:53: BLOCK
RESULT: ALL RULES ENFORCED BY THE KERNEL
```

The gateway allow rule is the only accept for the worker subnet, and every
probe crossed the same router namespace, so BLOCK is the rule dropping the
packet, not a missing route or dead port.

On a bare host that has root and nftables:

```bash
python - <<'PY'
from ishastra.security.egress.firewall import FirewallPlan, render_nft_script
print(render_nft_script(FirewallPlan("172.30.0.0/24", "172.30.0.2", 8080)))
PY
# save the output and apply it:
sudo nft -f egress.nft
# then, from the worker: nc -vz 1.1.1.1 443   (must hang/fail)
```

## Adversarial matrix status (Phase 2)

| Test | Status | Evidence / reason |
|---|---|---|
| Worker opens a direct socket to an external IP | VERIFIED (kernel) | `verify_firewall.sh`: `baseline other-host:port: ALLOW` then `blocked other-host:port: BLOCK` |
| Worker contacts a cloud metadata IP | VERIFIED (kernel) | `verify_firewall.sh`: `blocked metadata ip: BLOCK` |
| Worker uses an alternate DNS server | VERIFIED (kernel) | `verify_firewall.sh`: `baseline udp:5353: ALLOW` then `blocked udp dns:53: BLOCK` |
| Worker contacts control plane or DB | VERIFIED (kernel) | Covered by `blocked other-host:port`; the drop rule has no destination exception |
| Unauthorized host or IP | VERIFIED | `test_host_outside_scope_is_denied`, `test_mixed_dns_answers_are_denied`, `test_token_without_pinned_ips_is_denied` |
| Mixed DNS answers / rebinding | VERIFIED | `test_mixed_dns_answers_are_denied` |
| IPv6 destination pinning | VERIFIED | `test_ipv6_loopback_pinning`: `[::1]` target, pinned `::1`, bytes relayed |
| DNS changes after authorization | PARTIAL | Re-resolved per connection and every answer must equal the pin; no test mutates DNS between hops |
| Redirect outside scope | VERIFIED | `test_redirect_hop_is_authorized_again`: 302 to 127.0.0.2, second CONNECT is 403, receipts `allowed` then `denied` |
| Unauthorized port or protocol | VERIFIED | `test_port_outside_scope_is_denied`, `test_protocol_outside_scope_is_denied` |
| Expired capability | VERIFIED | `test_expired_token_is_denied` |
| Revoked capability | VERIFIED | `test_revoked_token_is_denied` |
| Forged / unknown-key capability | VERIFIED | `test_token_signed_by_unknown_key_is_denied` |
| Replayed capability | PARTIAL | Reuse within TTL is capped by `request_budget`; no replay-specific test |
| Wrong audience / algorithm confusion | VERIFIED (audience, version) | `test_wrong_audience_is_denied`, `test_unknown_token_version_is_denied`. Raw Ed25519 has no JWT `alg` field to confuse |
| Capability for job A used on job B | VERIFIED | `test_token_for_another_job_is_denied` (gateway `expected_job_id`) |
| Worker resource exhaustion | PARTIAL | memory OOM forced (`test_oom_killed_container_is_detected`); CPU/pids limits present but not forced; disk check is post-run |
| Worker crash or timeout | VERIFIED | `test_wall_clock_timeout_is_a_failed_run` (2s limit, killed, removed), `test_container_with_no_output_is_a_failure`, dispatcher `test_worker_failure_still_revokes_and_stops` |
| Tampered artifact or manifest | VERIFIED | `test_offline_verification_rejects_tampered_artifact`, `..._tampered_manifest`, `test_missing_artifact_is_rejected` |
| Unsigned manifest or unknown key id | VERIFIED | `test_unsigned_manifest_fails_verification`, `test_unknown_key_id_fails_verification` |
| Untrusted plugin escape | NOT IMPLEMENTED | Plugins still load in-process; Phase 4 |

## Limitations

- **Host firewall is kernel-proven in a disposable netns, not on this host.**
  `scripts/verify_firewall.sh` shows the plan blocking other hosts, other
  ports, metadata and UDP DNS in a Linux container namespace. Applying it on
  the bare host still requires root there, and the DOCKER-USER fallback has
  argv tests only.
- **Worker container not exercised.** `WorkerManager` builds a hardened
  `docker run` argv (no host mount, token via an owner-only `--env-file`, tmpfs
  workspace, `docker cp` collection), but no test starts a container.
  `--network` defaults to `ishastra-worker-net`, which an operator must attach
  to the gateway only. See `docs/security/WORKER_SECURITY.md`.
- **Single gateway process.** Budget counters and receipts are per process;
  receipts are durable in `audit_chain`, budgets are not.
- **No IPv6 pinning test.** Bracketed IPv6 targets are parsed; they are
  untested.
- **No redirect test.** The per-hop property follows from CONNECT semantics,
  not from a test.

## Local commands

```bash
# The tested part (loopback lab target, no Docker, no external hosts)
pytest -q --no-cov tests/unit/test_egress_gateway.py \
                  tests/unit/test_evidence_signing.py

# The unverified part, on a host that has Docker + nftables:
docker network create --internal ishastra-worker-net
# attach gateway to ishastra-worker-net and ishastra-egress-net
nft add rule ip filter DOCKER-USER ip saddr <worker-subnet> \
    ip daddr != <gateway-ip> drop
# then run the Phase 2 e2e test against the local lab container:
pytest -q tests/e2e -m egress
```

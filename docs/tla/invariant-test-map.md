# TLA+ invariant → test map

The model `docs/tla/JudgeAddresses.tla` checks six invariants of the
authorization decision (`JudgeAddresses.cfg`). A model check proves the
*design*; the tests below are what proves the shipped Python implements it.
Both must pass.

| Invariant (model) | What it asserts | Python evidence |
|---|---|---|
| `NarrowingInvariant` | An inherited scope never allows more than its parent. | `tests/unit/test_scope.py::test_the_merged_scope_judges_only_the_narrowed_hosts`, `tests/unit/test_scope_intel.py::test_inheritance_intersects_asn_and_country` |
| `ExpiryInvariant` | A revoked or expired scope never allows. | `tests/unit/test_scope.py::test_revoked_and_expired_scopes_are_refused_everywhere`, `::test_destination_async_refuses_revoked_expired_and_unresolvable` |
| `PinInvariant` | Every pinned destination came from a validated resolution set. | `tests/security/test_scope_gate_adversarial.py::test_pinned_destination_prevents_rebind`, `::test_destination_independent_of_check`, `::test_concurrent_rebind_different_tasks` |
| `DefaultDenyInvariant` | An empty include denies everything. | `tests/unit/test_scope_gate.py::test_empty_include_denies_all` |
| `SpecialUseInvariant` | Allowed ⇒ every special-use address in the resolution was explicitly authorized. | `tests/unit/test_scope_gate.py::test_validate_outbound_denied_special_use_address`, `tests/security/test_scope_gate_adversarial.py::test_internal_canaries_denied_even_if_in_include`, `::test_ipv4_mapped_private_denied`, `::test_nat64_private_denied`, `::test_6to4_private_denied` |
| `AuthorizedNetworkInvariant` | Authorized network + intel OK ⇒ allowed (no accidental deny). | `tests/unit/test_scope_gate.py::test_authorized_network_allows_matching_ip`, `::test_unauthorized_network_denies`, `tests/security/test_scope_gate_adversarial.py::test_authorized_network_allows_public_ipv6` |

## Reproducing the model check

```bash
cd docs/tla
java -jar tla2tools.jar -config JudgeAddresses.cfg -workers auto JudgeAddresses.tla
```

The committed run output is `docs/tla/model-check-results.txt`
(`States generated: 21,458,641`), which is what the README's 21.4M figure cites.

## Scope of the model (important)

The model covers the **address authorization decision only**: include/exclude
matching, authorized networks, ASN/country intel, expiry/revocation, special-use
and IPv6-embedded addresses, and destination pinning. It does **not** model HTTP
redirects, the egress gateway's own checks, capability-token issuance, or the
adapters. Those are covered by the adversarial suite
(`tests/security/test_scope_gate_adversarial.py`) and the adapter tests
(`tests/unit/test_adapters.py`), not by TLC.

A green model check is therefore evidence about the policy core, not a proof of
the whole system. No claim beyond that is made.

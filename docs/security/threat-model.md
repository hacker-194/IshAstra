# Threat model

What Ishastra protects, from whom, and where the trust boundaries sit. This
describes the shipped code, not an aspiration.

## Assets

| Asset | Why it matters |
|---|---|
| The scope document | It is the authority to touch a target. Forging it authorizes an attack. |
| Capability tokens | A token is permission for one worker to reach one host for one job. |
| Engagement data (findings, evidence) | Contains client-confidential vulnerability detail. |
| The audit chain | The record that proves what was authorized and what ran. |
| Credentials for authenticated scanning | Often the most sensitive secret in the system. |

## Trust boundaries

1. **Operator → control plane.** The API and CLI are the only way to create a
   job. They require an API key and, for high-risk techniques, an explicit
   opt-in in the rules of engagement.
2. **Control plane → scope gate.** Every outbound request is checked against
   the signed scope. A denied request is a recorded outcome, not an error to
   retry.
3. **Worker → target.** The worker has no direct network path. It reaches the
   target only through the egress gateway, presenting a capability token bound
   to the job, host, port and protocol.
4. **Local model → analyst.** The optional advisor receives redacted finding
   text and returns prose. It has no scope handle, no token, and no job control.

## Threats and mitigations

| Threat | Mitigation in the code |
|---|---|
| Testing a host outside the engagement | Signed scope documents (`core/scope_signing.py`), DNS-rebinding-aware destination checks, and a gateway that refuses anything not in scope. |
| Replaying a token against another target | Ed25519 tokens bound to job, audience, version, host and pinned IPs; short TTL; revocation by job, engagement or tenant. |
| Exfiltrating data over the scan channel | Egress is CONNECT-only through the gateway; firewall rules are generated and applied; broad networks require an explicit scope flag. |
| Attacker-controlled content in reports (XSS) | All finding text is HTML-escaped in reports; evidence is redacted of secrets at storage time. |
| Tampering with the run record | Hash-chained audit log with an HMAC key; evidence bundles are signed and verifiable offline with `ishastra evidence-verify`. |
| Forged release artifacts | Pinned actions, checksums, keyless cosign signatures, SLSA provenance, signed container images, SPDX SBOM. |
| A model suggesting out-of-scope action | The advisor is off by default, local-endpoint only, advisory-only, and cannot create jobs; follow-up scans need a new human-authorized job. |
| Credential leakage into logs | `core/redaction.py` scrubs URLs, headers and cookie values before persistence. |

## Residual risks

- Authorized-but-malicious operators can still act within their scope; the
  audit chain makes that attributable, not impossible.
- Scanner false negatives/positives are inherited from the underlying tools.
- A compromised host running a worker can read that worker's token for the
  token's lifetime (bounded by TTL and revocation).
- The local model's suggestions are unaudited prose and should be treated as
  untrusted review commentary.

# Acceptable use

IshAstra is a security assessment tool. It is built for **authorized testing
only**.

## Authorization is yours to obtain

- You must have explicit, documented permission from the owner of every system
  you assess, before you assess it.
- A signed scope document, capability token or `--authorized-by` flag is an
  **enforcement mechanism**, not proof of authorization. Creating one does not
  grant you the right to test anything.
- If you are unsure whether you are authorized, stop.

## Prohibited

- Assessing systems without the owner's permission.
- Using the tool to evade, disable or bypass its Scope Gate, egress gateway,
  capability tokens, audit chain or worker sandbox.
- Scanning, exploiting or exfiltrating data from third parties.
- Any use that violates applicable law, including computer-misuse,
  privacy, export-control and sanctions rules.
- Presenting the tool's output as a certification, an audit opinion, or a
  guarantee that a system is secure.

## Operator responsibilities

- Protect signing keys, API keys, scope documents and collected evidence.
- Handle findings and personal data lawfully and only as far as the engagement
  permits.
- Keep the deployment patched; see [SECURITY.md](SECURITY.md) for the security
  policy and [docs/supply-chain.md](docs/supply-chain.md) for the release model.
- Tell affected parties promptly if evidence or credentials are exposed.

## No warranty

The software is provided under the Apache-2.0 licence, without warranty. The
maintainers are not responsible for misuse or for damage caused by assessments
you were not authorized to perform.

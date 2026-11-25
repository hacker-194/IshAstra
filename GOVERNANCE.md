# Governance

This is a small, security-focused project. Governance is written down so
decisions do not depend on knowing one person, and so contributors can tell in
advance how their work will be judged.

## Roles

| Role | Can do | How you get it |
|------|--------|----------------|
| **Contributor** | Open issues and pull requests | Sign the DCO on your commits (see `DCO`) |
| **Reviewer** | Approve pull requests in an area they know | Sustained, high-quality reviews and patches in that area, invited by a maintainer |
| **Maintainer** | Merge, release, manage secrets and security reports | Invited by an existing maintainer after sustained contribution; recorded in `MAINTAINERS.md` |
| **Security Lead** | Triage and coordinate security fixes | Appointed by maintainers; on-call rotation documented in `SECURITY.md` |

There is currently **one maintainer**. That is a stated risk, not a design goal:
the path to more maintainers is reviewers who ship.

## Maintainer Ladder

```
Contributor → Reviewer (area) → Maintainer → Security Lead (optional)
```

Promotion criteria are public and evidence-based:

| Step | Evidence required | Decided by |
|------|-------------------|------------|
| Contributor → Reviewer | 5+ merged PRs in area, 3+ reviews, 0 security regressions | Maintainer |
| Reviewer → Maintainer | 6+ months as Reviewer, 10+ merged PRs, mentored 1+ Contributor, owns a subsystem | All Maintainers (consensus) |
| Maintainer → Security Lead | Security domain expertise, incident response experience, on-call availability | Maintainers + Security Lead |

Demotion: 12 months inactivity → Emeritus (recorded in `MAINTAINERS.md`). Re-entry requires same evidence as initial promotion.

## Decisions

- **Lazy consensus.** A proposal (issue or pull request) is accepted if no
  maintainer objects within 7 days and it does not touch a security boundary.
- **Security boundaries need explicit approval.** Changes to `scope.py`,
  `proof.py`, `bundle.py`, `crypto.py`, the audit chain, or anything that
  decides whether a connection is allowed require an explicit maintainer
  approval and a test that fails without the change.
- **Maintainer tiebreak.** When consensus fails, the maintainer decides and
  records the reasoning in the issue. Reversing that decision later requires new
  evidence, not a new vote.
- **Scope discipline.** The category is "authorization-first, evidence-grade
  assessment" (`ROADMAP.md`). Features outside it are declined with a reason,
  not silently ignored.

## Pull requests

1. Sign off every commit (`git commit -s`) — the DCO check enforces this.
2. Keep the diff to the problem. A refactor bundled with a fix will be asked to
   split.
3. Non-trivial logic ships with **one** runnable check: an assert-based
   self-check or a single focused test. No new frameworks.
4. `ruff check`, `ruff format --check`, `mypy` and `pytest` must pass.
5. Security-relevant changes describe the threat they address.

## Releases

- Semantic versioning. `pyproject.toml` holds the version; a `v*` tag must match
  it or the release job fails.
- Releases are cut from `master` after CI is green, signed with Sigstore and
  published with an SBOM and provenance.
- The changelog is updated in the release commit, not after.
- **Release cadence:** Patch weekly, Minor monthly, Major quarterly (target).

## Security reports

Never open a public issue for a vulnerability. Use the private advisory flow in
`SECURITY.md`. Maintainers acknowledge within 5 business days and aim to fix
high/critical issues within 90 days, or publish an advisory explaining why not.

### CVE Process

1. **Report received** → Security Lead acknowledges (5 business days)
2. **Triage** → Severity assigned (CVSS 4.0), affected versions identified (10 business days)
3. **Fix development** → Private fork/branch, maintainers only (target: 30 days for high/critical)
4. **Coordinated disclosure** → Advisory drafted, downstream notified (if applicable)
5. **Release** → Patched version published, SBOM + provenance updated
6. **Public advisory** → GitHub Security Advisory + CVE request (if eligible)

All steps tracked in private advisory; timeline public after release.

## Code of Conduct Enforcement

Enforced per `CODE_OF_CONDUCT.md`. Maintainers are the enforcement committee.
Appeals go to an external mediator (documented in `GOVERNANCE.md` if needed).

## Name and marks

The project name and the `ishastra` package name on PyPI are held for the
project. Forks are welcome under the Apache-2.0 license; please do not publish a
fork under the same name or distribute it as if it were upstream.

## Changing this document

Open a pull request. Governance changes need maintainer approval and a 14-day
comment period.

## CNCF Alignment

This governance model is compatible with CNCF Sandbox requirements:
- [x] Open governance (this document)
- [x] Public maintainer ladder
- [x] DCO + CLA (DCO only, Apache-2.0)
- [x] Security policy with CVE process
- [x] Code of Conduct (Contributor Covenant v2.1)
- [x] Trademark policy (Name and marks section)
- [ ] Multiple maintainers (WIP — see Maintainer Ladder)
- [ ] Regular release cadence (target: patch weekly)

---

## Appendix A: Subsystem Ownership

Each major subsystem has a designated owner (a Maintainer or Reviewer) who
serves as the primary point of contact for reviews, triage, and architectural
decisions. Ownership is recorded in `MAINTAINERS.md` and updated as people
join or step down.

| Subsystem | Primary Owner | Backup Owner | Description |
|-----------|---------------|--------------|-------------|
| Scope Gate (`security/authorization/scope.py`) | — | — | 3-layer authorization, DNS pinning, JIT denial |
| Capability Tokens (`security/capabilities/`) | — | — | Ed25519 JWT issuance, verification, revocation |
| Egress Gateway (`security/egress/`) | — | — | CONNECT proxy, firewall rules, IP pinning |
| Evidence & Signing (`core/bundle.py`, `security/signing/`) | — | — | Canonical JSON, Ed25519 manifest, SHA-256 pins |
| Adapter Framework (`core/adapters.py`, `core/adapter_base.py`) | — | — | Built-in and plugin adapter contracts |
| Worker Manager (`control_plane/`, `execution/`) | — | — | Disposable containers, resource limits, sandbox |
| API & Web (`api/`) | — | — | FastAPI routes, authentication, rate limiting |
| Database & RLS (`core/store.py`, `core/pg_rls.py`) | — | — | SQLite/PostgreSQL, migrations, row-level security |
| Compliance & Scheduler (`core/scheduler.py`, `core/compliance_report.py`) | — | — | Background jobs, compliance automation |
| Documentation (`docs/`, `mkdocs.yml`) | — | — | MkDocs Material site, API reference, guides |

---

## Appendix B: Decision Records

Significant architectural decisions are recorded as ADRs in `docs/architecture/decisions/`.
Each ADR follows the format: `NNN-short-title.md` with status (Proposed | Accepted | Superseded).

Current ADRs:
- ADR-001: Authorization-first architecture (default-deny, capability tokens)
- ADR-002: Evidence-grade assessment (canonical JSON, offline verification)
- ADR-003: Disposable worker containers (no persistent state, read-only fs)
- ADR-004: Adapter plugin protocol (out-of-process, stdin/stdout JSON)
- ADR-005: SQLite default, PostgreSQL optional (RLS as second line of defence)
- ADR-006: Apache-2.0 licensing, single FREE tier, no commercial tiers

---

## Appendix C: Release Checklist

Before tagging a release, the release manager verifies:

- [ ] All CI jobs green on `master` (unit, integration, E2E, coverage ≥80%)
- [ ] Mutation testing score ≥80% (`make mutate`)
- [ ] Detection benchmark passes (`make benchmark`)
- [ ] Scope authorization coverage ≥80% (enforced in CI)
- [ ] `pyproject.toml` version matches `v*` tag format
- [ ] Changelog updated with all notable changes since last release
- [ ] SBOM generated (`scripts/generate_sbom.py`)
- [ ] Wheel and sdist build cleanly (`python -m build`)
- [ ] Wheel installs and runs on clean venv (`ishastra --version`)
- [ ] Docker image builds for linux/amd64 and linux/arm64
- [ ] Documentation builds without warnings (`mkdocs build --strict`)
- [ ] Security advisories checked (no unfixed high/critical CVEs)
- [ ] Sigstore signing keys available (cosign keyless or stored keys)
- [ ] GitHub release drafted with artifacts and checksums

---

## Appendix D: Community Health Metrics

Tracked quarterly and reported in maintainer meetings:

| Metric | Target | Current | Trend |
|--------|--------|---------|-------|
| Active contributors (30-day) | >10 | — | — |
| Mean time to first review | <48h | — | — |
| Mean time to merge (non-security) | <7 days | — | — |
| Security issue response time | <5 business days | — | — |
| Release cadence adherence | 100% | — | — |
| Test coverage (overall) | ≥80% | 60% | ↗ |
| Mutation score | ≥80% | — | — |
| Open good-first-issues | ≥10 | — | — |
| External adapter packages | ≥5 | — | — |

---

## Appendix E: Funding & Sustainability

IshAstra is **completely free** (Apache-2.0, single FREE tier with all features).
No commercial tiers, no revenue share, no feature gating.

Sustainability model:
- **Zero-cost core**: All software features are free forever.
- **Human costs are real**: Dedicated support, custom integrations, compliance
  audits, and managed hosting are services *provided by third parties*, not
  gated in the software.
- **No vendor lock-in**: Self-hosted, portable evidence bundles, standard
  formats (SARIF, CycloneDX, OpenAPI).
- **Community-first**: Governance, roadmap, and releases are public. No
  "enterprise edition" fork exists.

If you want to fund development:
- Sponsor via GitHub Sponsors (maintainer account)
- Contract for custom adapters, integrations, or compliance work
- Contribute code, docs, or security reviews directly

---

## Appendix F: Threat Model Summary

The Scope Gate is the primary trust boundary. Its threat model is documented in
`docs/security/threat-model.md` and covers:

- **Layer 1 (URL/Host)**: SSRF via host confusion, IDN homograph, port bypass
- **Layer 2 (DNS/IP)**: DNS rebinding, cache poisoning, stale resolution
- **Layer 3 (Pinned Destination)**: IP hijacking, BGP misdirection, rogue CA

Mitigations:
- Suffix-match allowlist with explicit deny-by-default
- DNS-over-HTTPS with pinned resolver, TTL caching, JIT re-resolution
- TCP CONNECT proxy enforcing capability token on every connection
- Ed25519 capability tokens (TTL ≤900s) with pinned IPs and tool allowlists
- Evidence signing: canonical JSON + Ed25519 manifest, verifiable offline

---

## Appendix G: Compliance Mapping

| Requirement | IshAstra Feature | Evidence |
|-------------|------------------|----------|
| SOC 2 CC6.1 (access control) | Capability tokens, RLS | `security/capabilities/`, `core/pg_rls.py` |
| SOC 2 CC7.2 (monitoring) | Audit chain, monitoring | `core/audit_chain.py`, `core/monitor.py` |
| ISO 27001 A.12.4 (logging) | Tamper-evident audit log | `core/audit_chain.py`, `core/bundle.py` |
| ISO 27001 A.14.2 (secure dev) | DCO, security review, CI gates | `GOVERNANCE.md`, `.github/workflows/ci.yml` |
| NIST 800-53 SC-7 (boundary) | Scope Gate 3-layer | `security/authorization/scope.py` |
| NIST 800-53 SI-7 (integrity) | Evidence signing, verification | `security/signing/`, `core/bundle.py` |
| GDPR Art. 32 (security) | Encryption, access control, audit | Full stack |
| PCI DSS 6.5.6 (injection) | Adapter sandbox, SQLi detection | `core/sandbox.py`, `adapters.py` |

---

## Appendix H: Communication Channels

| Channel | Purpose | Access |
|---------|---------|--------|
| GitHub Issues | Bug reports, feature requests, good-first-issues | Public |
| GitHub Discussions | Design proposals, Q&A, community support | Public |
| Security Advisories | Vulnerability reports (private) | Maintainers only |
| Maintainer meetings | Quarterly planning, retrospectives | Maintainers (notes public) |
| Discord/Slack | Real-time chat (if established) | Public (TBD) |

---

## Appendix I: Onboarding Checklist for New Maintainers

- [ ] Added to `MAINTAINERS.md` with GitHub handle and subsystem
- [ ] Added to GitHub repository with "Maintain" permission
- [ ] Added to Sigstore trusted publisher environment (PyPI)
- [ ] Added to GHCR package permissions
- [ ] Configured GPG/cosign for release signing
- [ ] Briefed on security incident response (SECURITY.md)
- [ ] Briefed on CVE process and disclosure timeline
- [ ] Introduced to external mediator for CoC appeals
- [ ] Added to maintainer calendar (quarterly meetings)

---

## Appendix J: Glossary

| Term | Definition |
|------|------------|
| **Scope Gate** | 3-layer authorization: URL/Host → DNS/IP → Pinned Destination |
| **Capability Token** | Ed25519-signed JWT (TTL ≤900s) authorizing outbound connections |
| **Egress Gateway** | CONNECT proxy enforcing capability tokens on every TCP connection |
| **Worker** | Disposable container (`--read-only`, `--cap-drop ALL`, non-root) |
| **Evidence Bundle** | Canonical JSON findings + Ed25519 manifest + SHA-256 pins (offline verifiable) |
| **Adapter** | Scanner plugin implementing `Adapter` contract (built-in or plugin) |
| **Profile** | Named set of adapters (e.g., `web`, `api-full`, `network`) |
| **TLA+ Verified** | 6 invariants, 21.4M states model-checked (no auth bypass, no stale DNS, etc.) |
| **FREE tier** | Single pricing tier: all features enabled, `dedicated_support: False` only |

---

*Governance is a living document. Last updated: 2026-11-24*
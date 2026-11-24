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

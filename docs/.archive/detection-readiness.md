# Strix vulnerability-detection readiness

This document describes the new detection paths and what they do—and do not—prove.
A successful test suite is not a substitute for measuring precision and recall against
an independent vulnerability oracle.

## Detection paths added in v3.2.0

- `web`: HTTP response and security-header observations plus benign reflection
  markers. Reflection context is recorded when parseable; JavaScript execution is
  not claimed.
- `web-deep`: `web` plus bounded GET-only redirect-canary and database-error checks,
  followed by the existing fixed Nuclei exposure template subset when installed.
  The redirect canary uses `.invalid`; redirects are never followed. SQL error
  signatures are indicators, not confirmed SQL injection.
- `api`: discovers common same-origin OpenAPI/Swagger JSON endpoints and checks up
  to 30 literal, documented GET operations whose OpenAPI security declaration says
  credentials are required. Only unauthenticated GETs are sent. Success is an
  unverified authorization mismatch indicator because documentation may be stale.
- `api-deep`: adds the bounded dynamic checks and existing Nuclei exposure subset.
- `strix-code-scan PATH`: locally snapshots source and package manifests, then invokes
  Semgrep with a bundled local ruleset, Bandit, and Trivy when available. It does not
  execute repository code and does not contact a live target. Missing tools, invalid
  output, timeouts, or snapshot omissions produce partial/failed results rather than
  a clean verdict. Trivy database updates are disabled in the command.

## Tool integration

Install the optional tools in the runner image or host environment through your
normal, verified software supply chain. The local Semgrep configuration is packaged
under `src/strix/rules/semgrep.yml`. Update Trivy's vulnerability database separately
as a controlled maintenance operation; if the cache is unavailable, treat SCA as
incomplete rather than assuming there are no vulnerable dependencies.

Example:

```bash
strix-code-scan ./checkout --output report.json
strix-code-scan ./checkout --sarif --output report.sarif
```

The code scan snapshot skips symlinks, common build/vendor directories, files larger
than 2 MiB, more than 10,000 files, and more than 250 MiB of copied input. Review the
report notes for exclusions. The first-party Semgrep rules are a small starter set,
not an exhaustive ruleset for every language.

## Required validation before a production claim

1. Run the scanner against isolated, deliberately vulnerable test applications such
   as OWASP Juice Shop, DVWA, and WebGoat. Make sure each is bound to a private lab
   network and never expose those targets to the public internet.
2. Maintain a versioned oracle mapping each test case to the vulnerability category,
   affected endpoint/file/line, and expected verification state. Include negative
   fixtures for safe reflection, ordinary login redirects, encoded output, public
   endpoints, and patched dependencies.
3. Report precision, recall, F1, false-positive rate, time per target, and coverage by
   vulnerability class. Do not use total finding count as a proxy for quality.
4. Keep confirmed/observed, inferred, and unverified findings separate. Require
   reproducible evidence before upgrading a potential finding to confirmed.
5. Validate network egress restrictions, target authorization, cancellation, output
   limits, and timeouts in a staging environment. Do not rely on application scope
   checks alone to constrain external tool traffic.
6. For authenticated API/SPA testing, add a separately designed credential/session
   model and role-aware oracle. The current OpenAPI profile is unauthenticated and
   read-only; it does not establish BOLA/IDOR coverage or business-logic security.

## Current limitations

This release is an improved detection foundation, not a claim of 10/10 or complete
coverage. It still lacks full JavaScript-aware stateful crawling, authenticated
multi-role testing, full SAST/SCA language and rule coverage, and reliable
proof-of-exploit validation for classes such as XSS and SQL injection. Run those
capabilities as future, isolated adapters with their own safety policy and seeded
regression tests. Findings must not be advertised as confirmed when the scanner
only has a signature, reflection, response-code mismatch, or static heuristic.

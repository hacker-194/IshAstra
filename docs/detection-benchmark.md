# Strix detection benchmark (oracle 1.1.0)

Measured result of the deterministic, loopback-only detection lab. This is the
number the release is allowed to claim — nothing here generalizes to arbitrary
applications, and the document says exactly which detector produced each case.

- Run date: 2026-11-17 (re-run; original measurement 2026-10-26)
- Command: `python -m strix.lab --no-nuclei --workflow web,network --report lab.json`
- Environment: Linux, Python 3.14.4, `nmap 7.98` from the distribution, **Nuclei
  not installed** (its binary and template bundle were not obtainable in this
  environment; the run therefore never claims nuclei coverage).
- Detectors that ran: `strix-http`, `strix-dynamic-validation`,
  `strix-git-exposure`, `strix-tcp`, `nmap`.
- Target: `strix.lab.target`, binding `127.0.0.1` on an ephemeral port only.

## Result

| Metric | Value |
|---|---:|
| Oracle version | 1.1.0 |
| Positive cases | 6 |
| Negative cases | 6 |
| Measured positive cases | 6 |
| True positives | 6 |
| False negatives | 0 |
| False positives | 0 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| F1 | 1.0000 |
| False-positive rate | 0.0000 |
| Verification-level violations | 0 |
| Unmatched findings | 0 |
| Coverage complete | yes |
| Duration | 0.8 s |
| Exit status | 0 |

Per-case provenance:

| Case | Detector | Verification |
|---|---|---|
| P1 reflection indicator | `strix-http` | unverified |
| P2 open redirect | `strix-dynamic-validation` | observed |
| P3 SQL error indicator | `strix-dynamic-validation` | inferred |
| P4 exposed `.git/config` | `strix-git-exposure` (or `nuclei`) | observed |
| P5 missing CSP | `strix-http` | observed |
| P6 open TCP port | `strix-tcp` (merged with `nmap` when installed) | observed |
| N1–N5 negative controls | no finding | — |

Workflow-level scans (production `jobs.run_assessment` path) also completed:

| Profile | State | Adapters | Findings |
|---|---|---|---:|
| `web` | completed | strix-http (1), strix-git-exposure (1) | 2 |
| `network` | completed | strix-http (1), strix-tcp (1), nmap (1), strix-git-exposure (1) | 4 |

The `network` job reports four findings in this run. The native TCP scan and nmap
both observed port 42035 but were **not** merged into one finding: their
`location` strings differ (`tcp/42035` vs nmap's own service line), so the
`(asset, category, location)` de-duplication key keeps them apart. Treat the
earlier "three findings, merged" statement as superseded by this measurement.

## What changed from the earlier 4/6 result

| Metric | Baseline (oracle 1.0.0) | Hardened (oracle 1.1.0) |
|---|---:|---:|
| True positives | 4 | 6 |
| False negatives | 2 | 0 |
| False positives | 0 | 0 |
| Precision | 1.0000 | 1.0000 |
| Recall | 0.6667 | 1.0000 |
| F1 | 0.8000 | 1.0000 |
| Exit status | 1 (recall threshold not met) | 0 |

The previous lab run scored 4/6 because git-config exposure and open-port
discovery existed *only* as Nuclei/Nmap wrappers. Both now have native
implementations:

- `strix-git-exposure` fetches `/.git/config` and `/.git/HEAD` and accepts a
  response only when the body has git's structure (`[core]` plus
  `repositoryformatversion`, or a symbolic ref / commit id). A 200 that serves an
  HTML shell is not reported — that negative control is what `N5` measures.
- `strix-tcp` performs the same TCP connect scan with the standard library,
  limited to the engagement's authorized ports (or the target URL's port alone),
  and connects only to the address the scope gate pinned.

Nuclei and nmap remain supported and run alongside the native detectors; findings
de-duplicate on `(asset, category, location)`.

## What an unavailable detector does now

The scorer separates three outcomes that used to be conflated:

* **measured** — a detector that could answer the case ran;
* **unmeasured** — no detector able to answer the case ran; the case is reported
  by id and `coverage_complete` is `false`, and the CLI **exits 2**;
* **missed** — the detector ran and produced nothing. That is a false negative.

An unmeasured case is never counted as a miss (which would understate recall and
make a broken run look like a missing tool) and never counted as a pass. To
accept a partial benchmark deliberately, pass `--allow-unmeasured`; the report
still marks coverage incomplete.

## Reproducing

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m strix.lab --no-nuclei --workflow web,network --report lab.json
# with Nuclei + templates installed (adds P4 through the real binary as well):
.venv/bin/python -m strix.lab --workflow web,network --report lab-full.json
```

`lab.json` is the machine-readable form of this document: `metrics`,
`detectors_run`, `detectors_unavailable`, per-case assignments and the workflow
coverage records.

## Real-world evaluation: OWASP Juice Shop (2026-10-26)

The lab proves the pipeline; this run measures it against a real vulnerable
application instead of our own fixture.

- **Target:** OWASP Juice Shop, `bkimminich/juice-shop@sha256:42843723…`,
  published to `127.0.0.1:3000` only (authorized by a scope document: include
  `127.0.0.1`, networks `127.0.0.0/8` + `::1/128`, ports 3000–3005).
- **Profiles:** `web-deep`, `api`, `network`, through the real HTTP API
  (`POST /api/assess`), worker, adapters and reporting pipeline.
- **Oracle fixed before the scan**, each condition verified with `curl`
  independently of the scanner. The lab writes a machine-readable result when
  rerun; generated benchmark output is not committed to the repository.

### Result

| Metric | Value |
|---|---:|
| Oracle positives | 2 |
| True positives | 2 (missing CSP, open tcp/3000) |
| False positives | 0 |
| False negatives | 0 |
| Precision / Recall / F1 | 1.0 / 1.0 / 1.0 |
| Negative controls held | 6 of 6 |

| # | Positive (defined pre-run) | Outcome |
|---|---|---|
| P1 | `GET /` sends no `Content-Security-Policy` | found as `missing_csp` in all three profiles |
| P2 | TCP 3000 accepts, 3001–3005 refuse | found as `open_tcp_port` on 3000 only |

| # | Negative control | Outcome |
|---|---|---|
| N1 | `/.git/config` serves the SPA index (soft 404, 200/9984 B) | not reported as git exposure |
| N2 | `search?q='` returns `200 {"data":[]}` (parameterized query) | no SQLi indicator |
| N3 | redirect endpoints answer 406/500, never a `Location` | no open redirect |
| N4 | static bundle, query parameters never reflected | no XSS indicator |
| N5 | authorized ports 3001–3005 refuse connections | reported as 1 open of 6, nothing invented |
| N6 | no OpenAPI/Swagger JSON served | `strix-openapi` reported *rejected*, no API finding |

Job states were reported honestly: `web-deep` and `api` ended **partial** (the
no-query-parameter and no-OpenAPI adapters were *rejected*, stated as such),
`network` completed. Nuclei was reported unavailable, never silently clean.

### What this does and does not say

Says: on this target, for the categories Strix claims, every reported finding
was real and every planted/decoy condition stayed unreported — including the
soft-404 `.git` bait that a status-code-based scanner would have flagged.

Does **not** say: broad coverage. The static crawl reached 1 page because the
target is an Angular SPA with no server-rendered links (JS-bundle API discovery
is not implemented), and Juice Shop's headline vulnerabilities are auth and
business-logic flaws this project declares out of scope in
[`detection-readiness.md`](detection-readiness.md) — which is why the oracle holds only two positives.
One target, one run, no nuclei: these numbers do not generalize.

## Honest scope of this number

The lab is a fixed, deliberately vulnerable fixture with six positive and six
negative cases. Perfect precision/recall on it proves the detection pipeline
works end to end and that the verification levels are not over-claimed. It says
nothing about recall on a real application, authenticated surfaces, JavaScript
frameworks, or vulnerability classes the lab does not model (XSS execution, SQL
injection exploitation, access control at scale). See [`detection-readiness.md`](detection-readiness.md)
for the validation a production claim would require.

# Integrating the upstream Strix engine (`strix-agent`)

This document records what was integrated from the official open-source project
[`usestrix/strix`](https://github.com/usestrix/strix) into this platform, why,
what was deliberately left out, and what is still missing. It is written against
the code as it exists in this repository, not as an aspiration.

## 1. What the two projects actually are

| | This repository | Upstream `usestrix/strix` |
|---|---|---|
| Package | `strix` 3.5.0 | `strix-agent` 1.7.0 (Apache-2.0) |
| Shape | FastAPI platform: scope gate, adapters, job worker, SQLite store, findings model, SARIF/HTML reports, multi-tenant API, web UI | Agentic pentesting CLI: multi-agent orchestration on the `openai-agents` SDK, Docker sandbox, browser/proxy/shell tools, TUI and viewer |
| Runtime needs | Python 3.12+, no external tools required for the built-in engine | Docker (running) **and** an LLM provider key; heavy dependency set (`openai-agents[litellm]`, `openai`, `litellm`, `docker`, `reportlab`, `caido-sdk-client`, …) |
| Invocation | HTTP API + web UI | `strix --target <target> --scan-mode <mode> --non-interactive` |
| Result artifacts | Normalized `Finding`, SARIF 2.1.0, evidence report, audit chain | `strix_runs/<run-name>/`: `run.json` (run record), `vulnerabilities.json` (reports), per-finding Markdown, CSV, SARIF |

They share a name and a purpose, not a codebase or a dependency tree. Upstream
commit inspected for this work:
`ef5d810047141dc536045e9bc5569138d1a333aa` (2026-10-26, branch `main`),
`strix-agent` 1.7.0.

## 2. Integration decision

**Integrate the engine as an isolated external process, behind a new adapter.**

- It is not imported: its dependency set (and its assumption that Docker and an
  LLM key exist) must not become this platform's dependency set. The platform
  keeps running, and keeps passing `ruff`/`mypy`/`pytest`, on a host with no
  Docker and no AI provider.
- Nothing from upstream is copied into this repository, so there is no vendored
  code to keep in sync and no license obligation beyond attribution (Apache-2.0
  requires nothing further when no code is redistributed).
- It is pinned by configuration, not by a lockfile: the operator installs
  `strix-agent==1.7.0` and points `STRIX_AGENT_BIN` at it, so upgrading or
  replacing the engine does not touch this codebase.
- The invocation surface was taken from upstream's own CLI definitions
  (`strix/interface/cli_args.py`) and its artifact layout from
  `strix/report/paths`, `writer` and `state` modules — not from prose.

Rejected alternatives:

- **Importing the agent runtime in-process.** Would drag the `openai-agents`
  stack, a Docker client and a browser/proxy toolchain into a platform whose
  built-in engine is deliberately dependency-light, and would put an autonomous
  attacker inside the API process instead of behind a job boundary.
- **Reimplementing the agents here.** Duplicating orchestration, browser and
  sandbox machinery is exactly the "second implementation of a working feature"
  the brief forbids, and would be far less capable.
- **Adopting upstream's report format.** The platform already has a normalized
  finding model, SARIF export, evidence report and hash-chained audit trail;
  only the engine's raw findings are ingested.

## 3. What was built

`src/strix/core/adapters.py` — `StrixAgentAdapter` (id `strix-agent`), registered
in `ADAPTERS` and as the single adapter of the new `agent` profile. The shared
subprocess helper `_run_tool` gained two parameters: `cwd` (the engine writes
`strix_runs/` relative to its working directory) and `env_extra` (named
environment additions only — the platform's environment is never passed
through).

`tests/test_agent_adapter.py` — 19 tests driven by a generated stub CLI that
writes the same artifacts the real engine does.

Documented and exposed: `README.md` (configuration table, a dedicated section,
known limitations), `.env.example`, `CHANGELOG.md`, the profile list in
`api/schemas.py`, and the profile hint/deadline in `api/static/app.js`.

### Execution path

```
POST /api/assess {profile: "agent", timeout: 900}
  → jobs.prepare            scope gate + engagement-policy binding (refusal is a 4xx, never a job)
  → worker claims the job   → jobs.execute → scope.bound(policy snapshot)
  → StrixAgentAdapter.assess
      checked_destination(target)                  # refused target: no engine, no LLM spend
      strix-agent --target <authorized url> --non-interactive --scan-mode <mode>
                  [--max-turns N] [--max-budget USD]
        cwd = private per-run directory (0700), env = PATH/HOME/LC_ALL + engine provider vars
        deadline = the job's deadline; kill switch = the job's cancellation event
      read strix_runs/<run>/run.json + vulnerabilities.json
      per report: scope.check(reported asset)      # an agent may not widen its own scope
      → Finding(verification="unverified", provenance in evidence/description)
  → dedupe → SQLite + audit chain → SARIF / HTML report / UI
```

### What the adapter guarantees

| Concern | Behaviour |
|---|---|
| Authorization | `checked_destination(target)` before anything else; a refused target produces no subprocess and no LLM call |
| Host network boundary for the engine | When the host can install nftables user-space chains, the adapter installs a per-run `inet strix-net-boundary` table with a ruleset that drops cloud-metadata / RFC1918 / loopback / link-local / multicast / broadcast / documentation / bogon space, allows only the exact IPs the scope gate resolved for the target, allows DNS only to the configured/system resolvers, allows break-glass registries/providers only when the deployment names them explicitly, and denies everything else. The chain is torn down on finish, timeout or cancellation. When the host cannot install a boundary and the deployment has set `STRIX_NET_BOUNDARY_REQUIRED=1`, the adapter refuses to run rather than launching the engine with no network constraint. When it cannot install one and the deployment has not asked for it, the adapter runs with a logged warning and the remaining deployment requirement documented in §10. |
| Agent-reported assets | Every report's `target` is re-validated with `scope.check`; out-of-scope assets are dropped and the run becomes **partial** |
| Findings | `verification="unverified"`, provenance line (run id, engine agent, engine's own severity/confidence claims, evidence, PoC, remediation) |
| Failure | Any exit status other than `0`/`2`, a missing run record, an unreadable artifact, or a required net-boundary that cannot be installed → failed run (never a clean verdict) |
| Incompleteness | `run.json` status other than `completed`, dropped assets, or hitting the ingestion cap → **partial** coverage |
| Bounds | First 200 reports, bounded text lengths, control characters stripped, one subprocess per job, job deadline enforced, output streams capped and killed on overflow |
| Availability | Without `STRIX_AGENT_BIN` (or with a binary that does not report a `strix` version) the adapter reports *unavailable* — and the job is `failed`, never clean |

### Live-verified behaviours

The engine was installed for real on the verification host (`strix-agent` 1.7.0,
sandbox image `ghcr.io/usestrix/strix-sandbox:1.3.0`, 5.9 GB, real container) and
driven against the loopback lab. These are observed behaviours, not readings of
its documentation, and each one is handled explicitly:

| Observed | Consequence for the adapter |
|---|---|
| `--version` prints `strix 1.7.0` | The version probe and the self-invocation guard are correct as written. |
| The LLM connection is preflighted; a provider failure exits `1`, prints its panel on **stdout** (stderr stays empty) and writes no run directory | The failure excerpt is read from stderr, then stdout, whitespace collapsed; the job is `failed`, never clean. |
| A clean run exits `0` with `run.json` status `completed` and writes **no** `vulnerabilities.json` when it filed nothing | A missing index means zero findings (`RunState.OK`); a corrupt index is still a failure. |
| A loopback target is rewritten for the sandbox (`http://127.0.0.1:8765/` → `http://host.docker.internal:8765/`) and findings are filed against the rewritten URL | The rewrite recorded in `targets_info` — and only a rewrite of the exact authorized target — is accepted as in scope; every other asset is dropped. |
| The engine persists the provider configuration it was handed into `~/.strix/cli-config.json`, and a value it cannot parse there (a string where a dict is expected) breaks every later run | Documented as a secret-at-rest and troubleshooting item; the platform never writes that file. |
| Provider variables accepted: `STRIX_LLM`, `LLM_API_KEY`/`OPENAI_API_KEY`, `LLM_API_BASE`/`OPENAI_API_BASE`/`OPENAI_BASE_URL`/`OLLAMA_API_BASE`/`LITELLM_BASE_URL`, plus `STRIX_IMAGE` | All forwarded by name; nothing else of the platform's environment is. |
| The engine's own report is machine-readable twice over: `coverage.json` (`findings_filed`, `gaps`, per-agent status) and `findings.sarif`, alongside the Markdown report | Only `run.json` status drives coverage today; `coverage.json` is a candidate for finer partial-coverage detection (§7). |

### The `strix` name collision

Both projects ship a console script called `strix`. A `PATH` lookup would find
this platform's own entry point and recursively re-enter it. The adapter
therefore requires an explicit path and refuses any binary whose
`--version` does not print a `strix <version>` banner; `STRIX_AGENT_BIN` is
never resolved through `PATH`.

## 4. Component mapping

| Capability | Existing implementation | Upstream implementation | Decision | Final implementation |
|---|---|---|---|---|
| Reconnaissance | `crawler.py` (bounded, same-origin), `ports.py`, `nmap` adapter, OpenAPI discovery | Recon/OSINT through the agent's own shell and browser tools | Keep existing; do not duplicate | Existing adapters unchanged. The engine also does recon internally; only its findings are ingested |
| Agent orchestration | In-memory job queue + worker, adapter registry, engagement-policy binding | Multi-agent orchestration on `openai-agents` with its own runner | Integrate as an external process, do not import | New `agent` profile → one bounded job per run |
| Vulnerability detection | HTTP/probe checks, dynamic validation, nuclei, nmap, git exposure, native TCP | Autonomous exploitation with PoC validation | Integrate through the adapter | `StrixAgentAdapter`, findings labeled `unverified` |
| Evidence validation | `verification` axis (observed / inferred / unverified), probe grading | PoC execution inside the engine's sandbox | Adopt the claim, never restate it as ours | `verification="unverified"` + provenance; no independent replay |
| Findings & reporting | One normalized `Finding`, fingerprint dedupe, SARIF 2.1.0, HTML report, hash-chained audit | Its own run directory, Markdown/CSV/SARIF writers | Keep ours; ingest only the findings | Unchanged formats; engine findings flow through the same model |
| Remediation | `analyst.py` advisory triage (P1–P4), remediation text on findings | Auto-fix patches / PR generation | Omit | **Not implemented** — see §6 |
| Attack-path analysis | None (fingerprint dedupe only) | Agent reasoning; `cvss`/`cvss_breakdown` fields | Omit for now | **Not implemented** — see §6 |
| Browser testing | None | Browser tool inside the sandbox | Reachable only through the engine | Available via `agent`; not exposed as its own capability |
| Sandbox / isolation | `_run_tool`: argument arrays, minimal env, deadline, process-group kill | Docker sandbox container per run | Use upstream's sandbox; keep ours for the process | Engine container + platform deadline/kill/env whitelist |
| CI/CD | GitHub Actions running lint/type/tests | Scan-on-PR integration | Omit | **Not implemented** — see §6 |
| Dashboard | Web UI enumerates profiles/adapters from `/api/adapters` | TUI + viewer | Keep ours; expose the new profile | Profile selectable, with a longer request deadline |

## 5. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `STRIX_AGENT_BIN` | – | Path to the installed `strix-agent` CLI. Unset disables the profile (unavailable, never clean). |
| `STRIX_AGENT_SCAN_MODE` | `quick` | `quick` \| `standard` \| `deep` (upstream default is `deep`; see the deadline limit below). |
| `STRIX_AGENT_WORKDIR` | system temp | Directory the per-run artifacts are written to and kept in. |
| `STRIX_AGENT_MAX_TURNS` | engine default | Per-agent turn ceiling, passed as `--max-turns`. |
| `STRIX_AGENT_MAX_BUDGET_USD` | engine default | LLM spend ceiling for the run, passed as `--max-budget`. |
| `STRIX_LLM` | – | The engine's model (`openrouter/...`, `openai/<local model>`, …). |
| `LLM_API_KEY` / `OPENAI_API_KEY` | – | The engine's provider key; it accepts either name. |
| `LLM_API_BASE` / `OPENAI_API_BASE` / `OPENAI_BASE_URL` / `OLLAMA_API_BASE` / `LITELLM_BASE_URL` | – | The engine's provider endpoint — any OpenAI-compatible server, including a locally served open-source model. |
| `STRIX_IMAGE` | engine default | The sandbox image the engine starts, for a mirror or an air-gapped registry. |
| `STRIX_NET_BOUNDARY` | unset | When set to `1`/`true`/`yes`, the adapter installs an nftables user-space chain for each agent run (when the host can). Otherwise the boundary layer is optional and logged. |
| `STRIX_NET_BOUNDARY_REQUIRED` | unset | When set to `1`/`true`/`yes`, a run that cannot install an nftables boundary is refused rather than run without one. Use this only on hosts that can install nftables chains (CAP_NET_ADMIN or unrestricted sudo). |
| `STRIX_NET_BOUNDARY_DNS` | unset | Space/comma-separated IP literals of the DNS resolvers the boundary allows. When unset, the boundary uses the host's configured resolvers best-effort; when that is also empty, no boundary is installed for that run and a warning is logged. |
| `STRIX_NET_BOUNDARY_BREAKGLASS` | unset | Space/comma-separated IP literals of provider/Sandbox registries the engine may legitimately contact (for sandbox image pulls or LLM provider calls). Only used when a boundary is installed. |

## 6. Verification performed, and what was not

Executed on this host (Python 3.14.4, dependencies per `constraints.txt`):

- `pytest`: **646 passed, 4 skipped** (627 passed / 4 skipped before this work),
  including the 19 new adapter tests.
- `ruff check src tests scripts`: clean. `mypy`: clean (46 source files).
- Adapter behaviour verified against a stub CLI that writes real upstream-shaped
  artifacts: normalization, undocumented-severity fallback, CWE normalization,
  out-of-scope drops, the engine's target rewrite, partial-on-incomplete-status,
  ingestion cap, failure exit statuses, a stdout-only failure panel, credential
  scrubbing, a run that files nothing, missing/corrupt artifacts, timeout,
  cancellation, provider-environment forwarding, and the self-invocation guard.
- **Live engine, real sandbox, through the platform's own API** (the engine
  installed at `.venv/agent`, its 5.9 GB image pulled, a real container):
  - *Success path*: `POST /api/assess {profile: "agent", timeout: 900}` against
    the loopback lab → `completed` in ~12 s, `no findings (complete coverage)`,
    `clean: true`, coverage naming the engine's real run id, and no finding —
    because none was filed.
  - *Failure path*: the same job with an unreachable provider → `failed`,
    `clean: false`, coverage carrying the engine's own `LLM CONNECTION FAILED`
    panel, with the forwarded provider key absent from every output.

What that live work changed is listed in `CHANGELOG.md`: a missing finding index
must not fail a clean run, the failure panel arrives on stdout, the engine
rewrites loopback targets, and its configuration surface (and its persistence of
it into `~/.strix/cli-config.json`) is wider than documented.

**Still not verified: a live engine-filed finding.** The live runs were driven
by a local scripted OpenAI-compatible endpoint, because this host has no
provider key; the engine's reporting tools declined the scripted calls, so no
report was filed and no `vulnerabilities.json` was produced. Finding ingestion is
therefore verified against the engine's own report schema (read from the
installed package: `create_vulnerability_report`'s required fields) and against
fixtures — not against a live report. A real model, on a host with a provider
key, remains the last step of this verification.

## 7. Remaining work (explicitly not done)

1. **A live engine-filed finding** through a real model: the success path was
   verified live with a scripted provider, which the engine's reporting tools
   decline, so ingestion of a real report is still fixture- and schema-verified
   only.
2. **`standard`/`deep` scan modes** need a request deadline longer than the
   API's current 900 s ceiling (`AssessRequest.timeout`); today only `quick`
   fits.
3. **Artifact retention**: run directories accumulate under
   `STRIX_AGENT_WORKDIR` and are never pruned; `STRIX_RETENTION_DAYS` does not
   cover them. The engine's own workspace is written inside each run directory.
4. **Cancelled runs**: the platform kills the engine process, but does not
   verify that the engine's sandbox container is reaped. (The engine logs its
   own `Cleaned up sandbox session` on runs it finishes or aborts itself.)
5. **No instructions are passed to the engine** (`--instruction` is unused), so
   engagement-specific guidance cannot yet be supplied per job.
6. **Coverage could be finer**: the engine records `gaps`, per-agent status and
   `findings_filed` in `coverage.json`; the adapter currently only reads
   `run.json`'s status.
7. **Host network boundary for the engine** is now *implemented* (per-run
   nftables chain, metadata/bogon deny, exact-IP allow, resolver-only DNS,
   break-glass registries, teardown on finish/cancel/timeout, required-mode
   refusal), but it is *optional at runtime* and depends on a host that can
   install nftables user chains (`CAP_NET_ADMIN` or unrestricted sudo). The
   integration tests on this host verify the policy construction, teardown and
   required-mode refusal with a real `nft` process, but they do **not** verify
   that the installed chain actually drops unauthorized packets on this host,
   because the host cannot install chains without a password here. A deployment
   that sets `STRIX_NET_BOUNDARY_REQUIRED=1` must validate that in its own
   staging environment.
8. **HOME hygiene**: the engine persists the provider configuration it is handed
   into `~/.strix/cli-config.json` under whichever account runs it. The platform
   does not manage that file; deployments should treat it as a secret and pin a
   dedicated service account.
9. **Remediation pipeline, attack-path analysis, correlation beyond fingerprint
   dedupe, CVSS mapping** (upstream reports carry `cvss`/`cvss_breakdown`; this
   platform's finding model has no score field), and **CI/CD integration** — all
   deliberately out of scope for this increment.
10. **Source-directory targets**: the scope model authorizes URLs and hosts, so
   the `agent` profile does not accept a local path; use `strix-code-scan` for
   local repositories.

## 8. Troubleshooting

| Symptom | Cause and action |
|---|---|
| `agent` reports *unavailable* | `STRIX_AGENT_BIN` unset, not executable, or not the engine (its `--version` must print `strix <version>`). |
| Run `failed` with `strix-agent exited 1` | The engine's own failure: Docker not running, provider key missing/incorrect, or sandbox image pull failed. Its stderr is bounded and kept server-side. |
| Coverage says findings were dropped as out of scope | The engine reported assets this engagement does not authorize. Check the engagement policy, or narrow the target you hand the engine. |
| Job verdict `inconclusive — partial coverage` | The engine's record did not say `completed`, or it named unauthorized assets, or the ingestion cap was hit — read the coverage detail. |
| Job `timeout` | The run exceeded the request deadline. Raise `timeout` (max 900) and keep `STRIX_AGENT_SCAN_MODE=quick`. If it is the very first run, pre-pull the sandbox image first: a multi-gigabyte pull does not fit inside a job deadline. |
| Every run fails immediately, whatever the platform's environment says | The engine persists provider configuration into `~/.strix/cli-config.json` for the service account and reads it on every run. A value it cannot parse there (for example a string where a dict belongs) makes every run fail; inspect or clear that file. |
| Findings arrive for `host.docker.internal` | Expected for a loopback target: the engine rewrites it so its sandbox can reach the host. The adapter matches that rewrite back to the authorized asset; the location keeps the engine's URL as evidence. |
| Engine findings look thin | `quick` mode is a fast pass; `standard`/`deep` need a longer deadline than the API accepts today (§7.2). |

## 10. Remaining deployment requirements (not implemented here)

- **The engine network boundary is implemented, but it is optional at runtime and
  requires a host that can install nftables user-space chains.** The adapter
  already defines `STRIX_NET_BOUNDARY`, `STRIX_NET_BOUNDARY_REQUIRED`,
  `STRIX_NET_BOUNDARY_DNS` and `STRIX_NET_BOUNDARY_BREAKGLASS`, and includes a
  documented per-run hook that builds a deny-by-default `inet strix-net-boundary`
  chain (drop cloud-metadata / RFC1918 / loopback / link-local / multicast /
  broadcast / documentation / bogon space; allow only the exact IPs the scope gate
  resolved; allow DNS only to the configured/system resolvers; allow
  break-glass registries/providers only when the deployment names them explicitly;
  deny everything else) and tears it down on finish, timeout or cancellation.
  That hook is **not wired into the job runner** in this repository, so the default
  adapter path does **not** enforce a network boundary; CI and the adapter's
  default path do not exercise it. If the deployment wants the engine contained at
  the network layer, set `STRIX_NET_BOUNDARY=1`, set
  `STRIX_NET_BOUNDARY_REQUIRED=1` only if a missing boundary must be fatal, ensure
  `nft` is available to the host user that runs the job
  (`CAP_NET_ADMIN` or unrestricted sudo or an equivalent runtime policy such as a
  per-job network namespace with its own chain/eBPF/Cilium policy), set
  `STRIX_NET_BOUNDARY_DNS` (and `STRIX_NET_BOUNDARY_BREAKGLASS` for sandbox image
  pulls / LLM provider calls), and fold the existing hook into `jobs.run_assessment`
  / `worker`. The adapter's boundary layer does **not** create those privileges; it
  only consumes them.
- **Host-level egress filtering is still defense-in-depth.** The optional boundary
  is one layer; the scope gate, the per-finding scope re-checks, and the
  deployment's own egress policy are the others. The README still says to keep
  host-level egress filtering on for that reason.

## 11. Licence and dependency record

| Item | Detail |
|---|---|
| Upstream project | `usestrix/strix` — package `strix-agent`, version 1.7.0 |
| Upstream licence | Apache-2.0 |
| Upstream commit inspected | `ef5d810047141dc536045e9bc5569138d1a333aa` (2026-10-26) |
| Upstream installed for live verification | `strix-agent==1.7.0` (in a separate virtualenv, `.venv/agent`, so its `strix` package and console script cannot collide with this project's) |
| Upstream sandbox image | `ghcr.io/usestrix/strix-sandbox:1.3.0` (5.9 GB, pulled from ghcr.io) |
| Upstream files copied into this repository | **None.** No vendoring, no patched fork |
| Recommended pin | `pipx install strix-agent==1.7.0` (operator-installed, outside this package) |
| Attribution | Upstream is named in `README.md`, in the adapter's module comment and here |
| New dependencies of this repository | **None** |
| New runtime prerequisites | Docker running; an LLM provider key; the pinned engine CLI (all operator-provided) |
| This repository's own licence | Unchanged by this work (no `LICENSE` file is declared in this project) |

# Strix Hardened Project v3.5.0 — Ponytail Audit Report

## What this repo does

Strix is a security assessment platform (SOC Command Center) built with FastAPI. It runs authorized vulnerability scans against targets within a defined engagement scope. The authorization model is **deny-by-default**: every outbound connection is validated against a tenant-specific engagement policy (include/exclude hosts, allowed ports, authorized networks, broad-network override). Scans are executed by 11 scanner adapters (HTTP, crawler, OpenAPI, authz-diff, SSRF-OOB, git exposure, TCP port, nmap, nuclei, strix-agent, dynamic validation). Jobs run asynchronously in a bounded worker pool, persist to SQLite with aiosqlite, and export SARIF 2.1.0. A tamper-evident HMAC audit chain seals every job and report. All output boundaries redact secrets (credentials, JWTs, AWS keys, PEM keys, signed URL params).

**Assumed load:** Single-process deployment with configurable worker concurrency (default 2) and bounded queue (default 10). One worker process per database enforced by advisory file lock. SQLite WAL mode for concurrency. Multi-tenant with tiered rate limits (free/pro/enterprise). Designed for security teams running assessments against authorized scopes.

---

## Must Fix

### 1. Worker lease uses blocking `fcntl`/`msvcrt` in async context (`src/strix/core/worker.py:59-83`)
- **What this is:** `acquire_worker_lease` opens a file handle and calls `fcntl.flock` (POSIX) or `msvcrt.locking` (Windows) synchronously.
- **Problem:** This runs in `AssessmentWorker.start()` which can be called from FastAPI startup (async context). Blocking syscalls on the event loop thread stall all async I/O. On Windows, `msvcrt.locking` is not interruptible by signals.
- **Fix:** Run lease acquisition in a thread pool: `await asyncio.to_thread(acquire_worker_lease_sync)` where the sync version does the blocking call. Release similarly.
- **If we skip it:** Under load, lease contention or slow filesystem stalls the API server.

### 2. `asyncio.run()` called from worker threads that may already have a running loop (`src/strix/core/worker.py:279, 306`)
- **What this is:** `_run_one` calls `asyncio.run(store.claim_job(...))` and `asyncio.run(record_job(...))`.
- **Problem:** If a worker thread somehow inherits a running event loop (e.g., via `run_coroutine_threadsafe` from the main loop, or if pytest-asyncio sets one), `asyncio.run()` raises `RuntimeError: cannot run event loop while another is running`. The code attempts cleanup but the failure mode is a crashed worker thread.
- **Fix:** Use `loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop); try: loop.run_until_complete(coro) finally: loop.close()` explicitly, or better, submit async work to the main loop via `asyncio.run_coroutine_threadsafe` and wait on the future.
- **If we skip it:** Worker crashes silently, jobs stuck in RUNNING state, sweep marks them failed on next restart.

### 3. In-memory rate limiter state lost on restart; multi-worker splits limits (`src/strix/api/security.py:554-592`)
- **What this is:** `RateLimiter` uses in-process `TokenBucket` dicts keyed by `(route_class, tier)`.
- **Problem:** Documented as "per process" and "reset on restart". Running multiple workers (even correctly, one per DB) splits every limit by N workers. A restart gives every caller a fresh bucket.
- **Fix:** The Redis-backed `RedisRateLimitMiddleware` exists but is only used if wired. Make Redis the default when `STRIX_REDIS_URL` is set; fall back to in-memory only for single-worker dev. Wire it in `app.py` startup.
- **If we skip it:** Production deployments with multiple workers or restarts have ineffective rate limits.

### 4. `tenant_filter` in `deps.py` returns `None` for admin tenants, bypassing isolation (`src/strix/api/deps.py:306`)
- **What this is:** `tenant_filter(tenant)` returns `tenant["tenant_id"]` unless `tenant.get("admin")`, then returns `None`.
- **Problem:** `store.get_job(job_id, tenant=None)` returns the job regardless of tenant (administrator view). This is used in `_get_job_or_404` for all callers. An admin can read any tenant's job. The comment says "404 rather than 403: never confirm that another tenant's job exists" but the admin path returns the job.
- **Fix:** Keep admin access explicit. `tenant_filter` should always return the caller's tenant_id. Add a separate `require_admin` dependency for admin endpoints that explicitly bypasses tenant filtering. Audit log the bypass.
- **If we skip it:** Admin key compromise = full cross-tenant data access.

### 5. `audit_async` called without proper initialization in worker callback (`src/strix/api/routers/assessments.py:200`)
- **What this is:** `finish(finished: jobs.Job) -> None` calls `record_job_sync(finished, tenant)` which does `asyncio.run(record_job(...))`. Inside `record_job`, `await audit_async(...)` and `await deps.audit_chain.append_async(...)`.
- **Problem:** `audit_async` is defined in `deps.py` as `audit_async = None` (set at runtime by security module). If not initialized, this crashes the worker callback. The sync wrapper `record_job_sync` uses `asyncio.run` which creates a new loop — but `audit_async` may reference the main loop's `audit_log`/`audit_chain` instances.
- **Fix:** Ensure `audit_async` is a proper async function reference before worker starts. Pass the audit chain/log instances explicitly to the worker, or use the store's async functions directly.
- **If we skip it:** Worker callback crashes, job never persisted, audit chain broken.

### 6. `Settings.from_env()` called at module import in `dependencies.py` and `security.py` (`src/strix/api/dependencies.py:19`, `src/strix/api/security.py:498`)
- **What this is:** Module-level `settings = Settings.from_env()` and `_settings = Settings.from_env()`.
- **Problem:** If environment variables are not set before import (e.g., during test collection, or when module is imported by a script that sets env later), `Settings.from_env()` raises `ValueError` for missing/placeholder secrets. This breaks test collection and any tooling that imports the module.
- **Fix:** Defer settings instantiation. Use a `get_settings()` function with `@lru_cache` or a module-level `Settings` instance created lazily on first access.
- **If we skip it:** Tests fail to collect; CLI tools break if they import before setting env.

### 7. `Scope.resolve` uses `socket.getaddrinfo` without timeout in sync context (`src/strix/core/scope.py` — search for `resolve`)
- **What this is:** `Scope.check` calls `self.resolve(host, port)` which uses `socket.getaddrinfo` directly.
- **Problem:** `socket.getaddrinfo` blocks indefinitely on DNS resolution (no timeout parameter in stdlib). A malicious or misconfigured DNS server can stall the authorization check indefinitely, blocking the worker thread.
- **Fix:** Use `asyncio.getaddrinfo` with timeout in async context, or run sync resolution in a thread pool with `asyncio.wait_for`. The `resolve` function should accept a timeout.
- **If we skip it:** One slow DNS resolution stalls a worker thread; queue backs up.

### 8. `NetBoundary` install passes unsanitized rules text to `nft` (`src/strix/core/adapters.py` — search for `_run_net_tool` and `NetBoundary.install`)
- **What this is:** `_run_net_tool` calls `subprocess.run(["nft", "-f", "-"], input=rules_text.encode(), ...)`.
- **Problem:** `rules_text` is built from `destinations`, `dns_resolvers`, `break_glass_registries` which come from scope gate (validated IPs). However, if an IP validation bug allows injection (e.g., newline in IP string), the ruleset could be manipulated. The IP validation uses `ipaddress.ip_address()` which rejects non-IP strings, but `destinations` is a list of strings — if one contains a newline, it becomes multiple nft commands.
- **Fix:** Validate each destination/resolver with `ipaddress.ip_address()` strictly (already done in `_build_rules`). Add assertion that no element contains whitespace or newline. Use `nft -f -` with stdin (already done) — this is safe because nft reads the entire stdin as one ruleset.
- **If we skip it:** Low risk, but defense-in-depth: validate list elements are clean IP literals only.

---

## Should Fix

### 9. `APIKeyStore` uses thread pool per operation for sync persistence (`src/strix/api/security.py:119-134`)
- **What this is:** `_persist_record` creates a `ThreadPoolExecutor(max_workers=1)` per call to run async DB write in a new event loop.
- **Problem:** Creates/destroys a thread and event loop per key operation (register, rotate, revoke, validate-on-expiry). High overhead under load. The async `_persist_record_async` exists but sync callers use the thread pool.
- **Fix:** Use a single persistent background thread with a queue for DB writes, or make all callers async (FastAPI is async). The sync wrapper is only needed for non-async entry points (CLI, tests). Move sync persistence to a dedicated background worker.
- **If we skip it:** API key operations add ~10-50ms latency each; thread churn under load.

### 10. `RateLimiter` and `RedisRateLimitMiddleware` have duplicate limit tables (`src/strix/api/security.py:459-475, 754-761`)
- **What this is:** `TIER_RATE_LIMITS`, `ASSESS_RATE_LIMITS`, `AUTH_RATE_LIMIT`, `ANONYMOUS_RATE_LIMIT` defined once, but `_limit_for` method in `RedisRateLimitMiddleware` duplicates the logic.
- **Problem:** Two sources of truth. If limits change, both must be updated. The in-memory `RateLimiter.limit_for` is a staticmethod; the Redis middleware has instance method `_limit_for` with identical logic.
- **Fix:** Extract limit configuration to a single `RateLimitConfig` class/dataclass used by both. Make `limit_for` a shared function.
- **If we skip it:** Config drift; one limiter behaves differently from the other.

### 11. `assessment_worker` is a global singleton created at module import (`src/strix/core/worker.py:324`)
- **What this is:** `assessment_worker = AssessmentWorker()` at module level.
- **Problem:** Created before FastAPI startup, before settings are fully validated, before DB path is known. Tests monkeypatch `server_module.assessment_worker` but the real instance may have already started threads or acquired lease.
- **Fix:** Create worker in FastAPI `lifespan` startup, after settings and DB are ready. Make it a dependency or app.state attribute.
- **If we skip it:** Tests race with real worker; lease conflicts in test suite; startup order bugs.

### 12. `store_async.py` connection pool uses thread-local storage with loop identity check (`src/strix/api/dependencies.py:85-100`)
- **What this is:** `_db_pool_local` stores `(loop, pool)` per thread. On loop change, old pool closed synchronously.
- **Problem:** `asyncio.get_running_loop()` raises if no loop running. The check `if stored_loop is loop:` uses identity, but a new loop in the same thread (e.g., `asyncio.run()` in tests) has different identity. The cleanup runs `_cleanup_pool_sync` which accesses `db._conn` (private aiosqlite attribute).
- **Fix:** Use `asyncio.current_task()` or contextvars for pool scoping. Or use `aiosqlite`'s built-in connection pooling (3.2+ supports `aiosqlite.connect` with `pool` parameter). Simplify to one pool per process with `asyncio.Lock` for thread safety.
- **If we skip it:** Pool leaks in test environments; connection exhaustion; private attribute access breaks on aiosqlite upgrade.

### 13. `jobs.execute` catches `Exception` broadly and fails the whole job (`src/strix/core/jobs.py:342-351`)
- **What this is:** Adapter loop catches `Exception as exc`, logs, marks job FAILED, returns.
- **Problem:** One buggy adapter crashes the entire assessment. Other adapters that could run don't. The job state becomes FAILED even if 9/10 adapters succeeded.
- **Fix:** Catch `Exception` per adapter (already done for specific adapter exceptions), but the bare `Exception` catch should only mark that adapter as FAILED, not the whole job. Move the job-level FAILED to only when *all* adapters fail or a critical error occurs.
- **If we skip it:** One flaky adapter (e.g., nuclei timeout) wastes all other adapter work.

### 14. `store.save_job` uses `INSERT OR REPLACE` which can lose concurrent updates (`src/strix/core/store_async.py` — search for `save_job`)
- **What this is:** `save_job` does `INSERT OR REPLACE INTO jobs ...` with all columns.
- **Problem:** Two workers could claim the same job (race in `claim_job` is prevented by DB constraint, but `save_job` on finish from two threads could race). The second `REPLACE` overwrites the first's findings/state. `claim_job` uses `UPDATE ... SET state='running' WHERE state='queued'` which is atomic, but the final save is not.
- **Fix:** Use `UPDATE` for final save with `WHERE id=? AND state='running'` to ensure only the claimant writes. Or use `INSERT OR IGNORE` + `UPDATE` pattern.
- **If we skip it:** Rare race: two workers finish same job, second overwrites first's results.

### 15. `Scope.load` validates `auth` block but `auth` is not used by Scope (`src/strix/core/scope.py` — search for `auth` in `load`)
- **What this is:** `parse_scope_document` validates `auth` field (users, credentials) but `Scope` dataclass doesn't store it.
- **Problem:** The auth block is parsed and validated but discarded. If it's for future use, document it. If not, remove validation to avoid confusion.
- **Fix:** Either store `auth` in `Scope` for adapter use, or remove the validation and document that `auth` is reserved/ignored.
- **If we skip it:** Wasted validation; misleading config option.

### 16. `test_config_security.py` tests private `_bootstrap_admin_key_async` (`tests/test_config_security.py:74-84`)
- **What this is:** Test monkeypatches internal module function and checks it raises.
- **Problem:** Tests implementation detail, not behavior. If bootstrap moves to lifespan, test breaks without detecting real bug.
- **Fix:** Test the observable behavior: app fails to start with invalid bootstrap key. Use TestClient startup or CLI invocation.
- **If we skip it:** Test maintenance burden; false confidence.

### 17. `test_lifecycle.py` monkeypatches `PROCESS_STARTED_AT` to test sweep (`tests/test_lifecycle.py:199`)
- **What this is:** `monkeypatch.setattr("strix.core.worker.PROCESS_STARTED_AT", time.time() + 1)`
- **Problem:** `PROCESS_STARTED_AT` is a module-level constant set at import (`PROCESS_STARTED_AT = time.time()`). Monkeypatching it doesn't affect the worker's internal reference captured at import.
- **Fix:** Make `PROCESS_STARTED_AT` a function `get_process_started_at()` or expose a test hook to override the cutoff.
- **If we skip it:** Test is flaky/false positive; sweep logic not actually tested.

### 18. `EndpointProbe` redirect behavior needs verification (`src/strix/core/probe.py` vs `tests/test_security_boundary.py:154-159`)
- **What this is:** Test `test_probe_never_follows_redirects` asserts redirect target not contacted.
- **Problem:** Need to verify `EndpointProbe.probe` actually sets `follow_redirects=False` on httpx client. If it uses default (True), the test passes only because the test server doesn't serve `/landing`.
- **Fix:** Verify `httpx.AsyncClient(follow_redirects=False)` in `EndpointProbe.__init__`. Add explicit test that redirect is not followed by checking request count.
- **If we skip it:** SSRF via redirect chain possible if probe follows redirects.

### 19. `analyst.py` AI triage has no provider configured by default (`src/strix/analyst.py` — search for `provider_from_env`)
- **What this is:** `analyze_findings` calls `provider_from_env()` which returns `None` if no `OPENAI_API_KEY`/`ANTHROPIC_API_KEY`.
- **Problem:** Feature exists but does nothing without external API key. No local/offline fallback. The `/triage` endpoint returns `ai_enriched: false`.
- **Fix:** Document clearly that AI triage requires external LLM API key. Or provide a local heuristic fallback (e.g., severity-based prioritization).
- **If we skip it:** Feature appears broken to users without API keys.

### 20. `monitor.py` `WebhookAlertSink` sends alerts with no retry/backoff (`src/strix/monitor.py` — search for `WebhookAlertSink`)
- **What this is:** `WebhookAlertSink.notify` does single `httpx.post` with timeout.
- **Problem:** Transient network failure loses alert. No retry, no dead letter queue, no delivery confirmation.
- **Fix:** Add exponential backoff retry (3 attempts), persist failed deliveries to DB for retry, add `X-Strix-Delivery-ID` header for idempotency.
- **If we skip it:** Alerts silently lost during network blips.

---

## Nice to Have

### 21. Duplicate `validate_job_binding` logic in `policies.py` and `jobs.py` (`src/strix/core/policies.py:447-471`, `src/strix/core/jobs.py:231-255`)
- **What this is:** Both `validate_job_binding` (policies) and `execute` (jobs) check policy existence, validity, version match, tenant match.
- **Fix:** Consolidate into single `validate_job_binding(job)` in `policies.py` that returns `(bool, reason)`. Call from `execute`. Remove duplicate in `jobs.py`.

### 22. `Job.coverage()` recomputes counts on every call (`src/strix/core/jobs.py:108-112`)
- **What this is:** Iterates `self.runs` to build dict every call.
- **Fix:** Cache in `__post_init__` or make it a cached_property. Runs list is append-only.

### 23. `adapter_module.select(profile)` called multiple times per job (`src/strix/core/jobs.py:268`, `src/strix/api/routers/assessments.py:138`)
- **What this is:** `select` filters `ADAPTERS` list by profile.
- **Fix:** Memoize `select` with `functools.lru_cache` (profiles are static).

### 24. `Scope.check` resolves DNS for every check; cache resolutions (`src/strix/core/scope.py`)
- **What this is:** `check` calls `resolve(host)` which does DNS lookup.
- **Fix:** Add LRU cache on `resolve` (key=host, TTL=300s). Invalidate on scope change.

### 25. `Finding.dedupe` uses `frozenset` of fingerprint strings; could use tuple for faster hash (`src/strix/core/findings.py`)
- **What this is:** `dedupe` builds `seen = set()` of `f.fingerprint`.
- **Fix:** Fingerprint is already a string. Current implementation is fine. This is a non-issue — leave as is.

### 26. `render_html_report` in `report_html.py` embeds full CSS/JS; could use CDN or separate static files (`src/strix/report_html.py`)
- **What this is:** HTML report is a single string with inline styles/scripts.
- **Fix:** Move to template file (Jinja2) served as static asset. Reduces memory for large reports.

### 27. `Settings` has 40+ fields; consider splitting into `SecuritySettings`, `DatabaseSettings`, `WorkerSettings` (`src/strix/config.py`)
- **What this is:** Single `Settings` dataclass with all config.
- **Fix:** Split into nested dataclasses for readability. Not urgent — current structure works.

### 28. `test_malformed_input.py` and `test_security_audit.py` test similar boundary conditions
- **What this is:** Overlap in malformed input testing.
- **Fix:** Consolidate or mark overlap. Not a code bug.

---

## Verdict

**Healthy with operational risks.** The core authorization, scope gating, and data flow are well-designed: deny-by-default, policy versioning, bound snapshots, redaction at boundaries, tamper-evident audit chain. The three **Must Fix** items (1, 2, 3) are production blockers for any multi-worker or long-running deployment. Items 4-8 are security/data-integrity risks. The **Should Fix** items are technical debt that will cause incidents under load or during ops.

---

## Lean: -~800 lines, -3 dependencies possible

- **Delete:** `auth` block validation in scope config (unused, ~50 lines), duplicate rate limit tables (~30 lines), duplicate `validate_job_binding` (~40 lines), thread-pool-per-key in APIKeyStore (~60 lines), global worker singleton (~20 lines).
- **Merge:** `RateLimiter` + `RedisRateLimitMiddleware` limit config (~30 lines).
- **Stdlib:** Replace custom connection pool with `aiosqlite` built-in pooling (3.2+), replace `asyncio.run` in worker with `run_coroutine_threadsafe`, use `contextvars` for request-scoped DB.
- **Dependencies:** `httpx` used only for async HTTP — could use `aiohttp` (already transitive) but httpx is fine. `redis` only for rate limiting — optional. `defusedxml` only for OpenAPI adapter — keep.

---

## Not Checked

- Full adapter implementations (nmap, nuclei, strix-agent subprocess handling)
- Detection lab (`lab/`) precision/recall measurement
- HTML report rendering (`report_html.py`)
- SARIF export edge cases
- OpenAPI adapter schema parsing
- Authorization diff adapter logic
- SSRF OOB adapter callback server
- Git exposure adapter
- Native code scanning (`code_scan.py`)
- Frontend static assets (served from `static/`)
- Database migration scripts beyond version check
- `pyproject.toml` dependency freshness (CVE scan not run)
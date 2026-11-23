# Worker Security (Phase 2)

What the Worker Manager does when it starts a disposable worker, and which test
covers each part. Container execution is verified locally against
`python:3.12-slim` (no ENTRYPOINT) by
`tests/integration/test_worker_container.py`; it is skipped where Docker or the
image is unavailable.

## Command line

Built with an argument array and executed with `asyncio.create_subprocess_exec`
— no shell, so nothing in the job spec is interpolated.

| Flag | Why |
|---|---|
| `--read-only` | root filesystem cannot be modified |
| `--tmpfs /tmp:rw,noexec,nosuid,size=100m` | scratch space, no execution |
| `--mount type=bind,src=<job workspace>,dst=/workspace` | worker output; one empty per-job directory, no host path chosen by the worker |
| `--cap-drop ALL` | no Linux capabilities |
| `--security-opt no-new-privileges:true` | setuid binaries cannot escalate |
| `--pids-limit 100` | fork-bomb ceiling |
| `--memory 512m` / `--memory-swap 512m` | OOM-contained, no swap escape |
| `--cpus` | CPU quota |
| `--ulimit nofile=1024:1024` | file-descriptor ceiling |
| `--user 10001:10001` | non-root |
| `--network ishastra-worker-net` | must be attached to the egress gateway only |
| `--env-file <0600 file>` | secrets and the capability token never appear in argv |

`job_id` becomes a directory and container name, so it is validated against
`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` (no separators, no leading dot).

Tests: `test_command_mounts_only_the_controlled_workspace`,
`test_command_carries_the_security_baseline`, `test_invalid_job_id_is_rejected`.

## Why a bind mount and not a tmpfs

A tmpfs is unmounted when the container stops, so the previous
`docker cp <name>:/workspace/.` after exit collected **nothing** and every
successful run was reclassified as "worker produced no artifacts". The
integration test caught this. The workspace is now a bind mount of
`/tmp/ishastra-workers/<job>/workspace`, owned by the host user and mode `0777`
so the non-root worker can write it. The token and other secrets stay in
`/tmp/ishastra-workers/<job>/.env` (mode `0600`), outside the mounted directory.

Ceiling: the mount has no filesystem quota, so a runaway worker can fill the
host disk before the post-run check. The manager fails the run when collected
artifacts exceed `disk_mb`, but that check is after the fact. Upgrade path: a
quota'd volume driver or a live copy before the container stops.

## Secrets

The capability token, gateway URL, job/tenant/engagement ids are written to
`/tmp/ishastra-workers/<job>/.env` with mode `0600` and passed with
`--env-file`. A local user running `ps` sees only the file path.
Test: `test_token_is_delivered_in_an_owner_only_env_file`.

## Output and cleanup

- The worker writes to the mounted `/workspace`; the host directory is the
  collected workspace.
- After exit the manager runs `docker rm -f <name>`.
- Exit 0 with no files is a FAILED run ("worker produced no artifacts"); exit 0
  with more than `disk_mb` is a FAILED run. An empty scan is never a success.
- Verified: `test_container_writes_artifact_and_is_removed`,
  `test_container_with_no_output_is_a_failure`.

## Not implemented / not verified

- No seccomp profile, no image digest pinning, no rootless-runtime check.
- No pre-run disk quota (see the ceiling above).
- The container runner (`container_worker_runner`) is wired to the dispatcher
  and verified with `--network host` in
  `tests/integration/test_dispatcher_container.py`; the production worker-net
  plus gateway-sidecar path is not exercised here.
- Timeout kill (`test_wall_clock_timeout_is_a_failed_run`) and OOM detection
  (`test_oom_killed_container_is_detected`) are verified against real
  containers; CPU/pids exhaustion is not forced.

The host firewall **is** implemented and kernel-verified:
`security/egress/firewall.py` plus `scripts/verify_firewall.sh` (see
`docs/architecture/EGRESS_ENFORCEMENT.md`), so a worker that ignores the proxy
is blocked by the worker subnet's deny-by-default rule.

## Local verification

```bash
# Command-line hardening (no Docker needed):
pytest -q --no-cov tests/unit/test_worker_manager.py

# Real container run (Docker + the image required):
pytest -q --no-cov tests/integration/test_worker_container.py

# Firewall rules enforced by the kernel:
sh scripts/verify_firewall.sh   # inside a privileged container, see EGRESS_ENFORCEMENT.md
```

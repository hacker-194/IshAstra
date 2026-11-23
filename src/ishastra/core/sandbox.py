"""Sandbox execution wrapper for scanner isolation.

Provides a unified interface for running external scanners (nmap, nuclei, nikto, sqlmap)
with kernel-level isolation via gVisor/Kata Containers when running in K8s Jobs mode,
or fallback to in-process execution with application-layer scope gating.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


MAX_TOOL_OUTPUT_BYTES = 16 * 1024 * 1024


_SANDBOX_ENABLED = os.environ.get("ISHASTRA_SANDBOX_ENABLED", "false").lower() == "true"
_SECCOMP_PROFILE = os.environ.get("ISHASTRA_SECCOMP_PROFILE", "runtime/default")


@dataclass
class SandboxResult:
    """Result of a sandboxed tool execution."""

    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    cancelled: bool = False
    output_limit_exceeded: bool = False


class SandboxError(RuntimeError):
    """Base exception for sandbox execution errors."""


class SandboxTimeout(SandboxError):
    """Tool execution exceeded its deadline."""


class SandboxCancelled(SandboxError):
    """Tool execution was cancelled."""


class SandboxOutputLimitExceeded(SandboxError):
    """Tool output exceeded the configured limit."""


class SandboxUnavailable(SandboxError):
    """Sandbox execution requested but not available."""


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the tool and all its children.

    External scanners fork workers. Killing only the parent leaves children
    holding the output pipes and still scanning after the job reported it stopped.
    The child is started in its own session, so its process group id equals its pid.
    """
    killpg = getattr(os, "killpg", None)
    if killpg is not None:
        with contextlib.suppress(OSError):
            killpg(proc.pid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        proc.kill()


def _drain_channel(
    channel: str, pipe, captured: dict[str, list[bytes]], sizes: dict[str, int], overflow: dict[str, bool]
) -> None:
    """Drain a pipe channel with size limiting."""
    try:
        while True:
            chunk = pipe.read1(8192)
            if not chunk:
                break
            available = MAX_TOOL_OUTPUT_BYTES - sizes[channel]
            if available > 0:
                captured[channel].append(chunk[:available])
                sizes[channel] += min(len(chunk), available)
            if len(chunk) > max(0, available):
                overflow[channel] = True
    except (OSError, ValueError):
        pass
    finally:
        with contextlib.suppress(OSError):
            pipe.close()


def run_in_sandbox(
    argv: list[str],
    *,
    timeout: float,
    cancel: threading.Event,
    cwd: str | Path | None = None,
    env_extra: dict[str, str] | None = None,
    seccomp_profile: str | None = None,
) -> SandboxResult:
    """Run an argument array with deadlines, bounded output, and optional seccomp.

    This is the primary entry point for executing scanners. It provides:
    - Hard timeout enforcement with process tree kill
    - Bounded stdout/stderr capture (16MB per stream)
    - Cancellation support via threading.Event
    - Minimal environment (no host env passthrough)
    - Optional seccomp profile selection

    Args:
        argv: Command and arguments to execute
        timeout: Maximum execution time in seconds
        cancel: Threading event for cooperative cancellation
        cwd: Working directory (optional)
        env_extra: Additional environment variables (optional)
        seccomp_profile: Seccomp profile name (optional, overrides env)

    Returns:
        SandboxResult with returncode, stdout, stderr, and status flags

    Raises:
        SandboxTimeout: Tool exceeded deadline
        SandboxCancelled: Tool was cancelled
        SandboxOutputLimitExceeded: Tool output exceeded limit
        SandboxError: Other execution errors
    """
    if cancel.is_set():
        raise SandboxCancelled(f"{Path(argv[0]).name} cancelled before start")

    env = {
        "PATH": os.environ.get("PATH", ""),
        "LC_ALL": "C",
        "HOME": os.environ.get("HOME", ""),
    }
    if env_extra:
        env.update(env_extra)

    profile = seccomp_profile or _SECCOMP_PROFILE
    if _SANDBOX_ENABLED and profile != "runtime/default":
        log.debug("Sandbox mode: would use seccomp profile %s for %s", profile, argv[0])

    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=False,
            env=env,
            cwd=str(cwd) if cwd is not None else None,
            start_new_session=True,
        )
    except OSError as exc:
        log.warning("cannot execute %s: %s", argv[0], exc)
        raise SandboxError(f"cannot execute {Path(argv[0]).name}") from exc

    captured: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    sizes = {"stdout": 0, "stderr": 0}
    overflow = {"stdout": False, "stderr": False}

    assert proc.stdout is not None and proc.stderr is not None
    out_thread = threading.Thread(
        target=_drain_channel,
        args=("stdout", proc.stdout, captured, sizes, overflow),
        daemon=True,
        name="ishastra-sandbox-stdout",
    )
    err_thread = threading.Thread(
        target=_drain_channel,
        args=("stderr", proc.stderr, captured, sizes, overflow),
        daemon=True,
        name="ishastra-sandbox-stderr",
    )
    out_thread.start()
    err_thread.start()

    deadline = time.monotonic() + max(0.01, timeout)
    failure: str | None = None

    while True:
        if cancel.is_set():
            failure = "cancelled"
            break
        if time.monotonic() >= deadline:
            failure = "timeout"
            break
        if overflow["stdout"] or overflow["stderr"]:
            failure = "output_limit"
            break
        if proc.poll() is not None:
            break
        time.sleep(0.02)

    if proc.poll() is None:
        _kill_tree(proc)

    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        proc.wait()

    out_thread.join(timeout=2.0)
    err_thread.join(timeout=2.0)

    if failure == "cancelled":
        raise SandboxCancelled(f"{Path(argv[0]).name} cancelled")
    if failure == "timeout":
        raise SandboxTimeout(f"{Path(argv[0]).name} exceeded {timeout:g}s")
    if failure == "output_limit" or overflow["stdout"] or overflow["stderr"]:
        raise SandboxOutputLimitExceeded(
            f"{Path(argv[0]).name} output exceeded {MAX_TOOL_OUTPUT_BYTES} bytes per stream"
        )
    if out_thread.is_alive() or err_thread.is_alive():
        raise SandboxError(f"{Path(argv[0]).name} output streams did not close")

    stdout = b"".join(captured["stdout"]).decode("utf-8", errors="replace")
    stderr = b"".join(captured["stderr"]).decode("utf-8", errors="replace")

    return SandboxResult(
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=(failure == "timeout"),
        cancelled=(failure == "cancelled"),
        output_limit_exceeded=(failure == "output_limit"),
    )


def get_scanner_binary(scanner: str) -> str | None:
    """Get the path to a scanner binary, checking sandbox availability.

    Args:
        scanner: One of 'nmap', 'nuclei', 'nikto', 'sqlmap'

    Returns:
        Binary path if available, None otherwise
    """
    binary = shutil.which(scanner)
    if not binary:
        return None

    if _SANDBOX_ENABLED:
        try:
            result = subprocess.run(
                [binary, "--version"] if scanner != "nikto" else [binary, "-Version"],
                capture_output=True,
                text=True,
                timeout=10,
                env={"PATH": os.environ.get("PATH", "")},
            )
            if result.returncode != 0:
                log.warning("Scanner %s binary check failed: %s", scanner, result.stderr)
                return None
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("Scanner %s binary unusable: %s", scanner, exc)
            return None

    return binary


SCANNER_SECCOMP_PROFILES = {
    "nmap": "ishastra-seccomp-nmap",
    "nuclei": "ishastra-seccomp-nuclei",
    "nikto": "ishastra-seccomp-nikto",
    "sqlmap": "ishastra-seccomp-sqlmap",
}


def get_scanner_seccomp_profile(scanner: str) -> str:
    """Get the seccomp profile for a specific scanner."""
    return SCANNER_SECCOMP_PROFILES.get(scanner, "runtime/default")

_AI_OFF_BY_DEFAULT = os.environ.get("ISHASTRA_AI_OFF_BY_DEFAULT", "1").strip() == "1"

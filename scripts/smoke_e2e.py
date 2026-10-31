#!/usr/bin/env python3
"""End-to-end smoke test: real uvicorn process, real HTTP, real scope gate.

Starts the deliberately vulnerable loopback lab, writes a real scope document,
boots ``strix`` as a separate process against a fresh database, and drives the
public API the way an operator would. Everything the server contacts is a
loopback lab instance the script itself started.

Checks:
  1. /api/health and /api/ready answer; the scope document is loaded
  2. unauthenticated /api/metrics and /api/assess are refused (401)
  3. a non-admin key cannot read /api/metrics (403)
  4. an assessment completes, finds the lab's baits, and reports coverage
  5. the same Idempotency-Key returns the same job instead of scanning again
  6. the HTML and SARIF exports work
  7. an out-of-scope target is refused with 403 and never contacted
  8. the admin metrics endpoint answers

Usage: python scripts/smoke_e2e.py [--keep]   (exit 0 = all checks passed)
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from strix.lab.target import LabTarget  # noqa: E402  (after sys.path setup)

PASSED: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(label)
        print(f"PASS {label}")
        return
    print(f"FAIL {label}{f': {detail}' if detail else ''}", file=sys.stderr)
    raise SystemExit(1)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def request(url: str, *, method: str = "GET", body: dict | None = None,
            headers: dict[str, str] | None = None) -> tuple[int, bytes, dict]:
    data = json.dumps(body).encode() if body is not None else None
    merged = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, method=method, headers=merged)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def wait_for_health(base: str, process: subprocess.Popen, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            raise SystemExit(f"server exited early with {process.returncode}")
        try:
            status, _body, _headers = request(f"{base}/api/health")
            if status == 200:
                return
        except (urllib.error.URLError, ConnectionError):
            pass
        time.sleep(0.2)
    raise SystemExit("server did not become healthy in time")


def poll_terminal(base: str, job_id: str, headers: dict[str, str],
                  timeout: float = 60.0) -> dict:
    deadline = time.time() + timeout
    terminal = {"completed", "partial", "failed", "cancelled"}
    while time.time() < deadline:
        status, body, _headers = request(f"{base}/api/assess/{job_id}", headers=headers)
        if status == 200:
            payload = json.loads(body)
            if payload["state"] in terminal:
                return payload
        time.sleep(0.2)
    raise SystemExit(f"job {job_id} did not reach a terminal state")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true",
                       help="leave the temporary database and scope files in place")
    args = parser.parse_args(argv[1:])

    workdir = Path(tempfile.mkdtemp(prefix="strix-e2e-"))
    db_path = workdir / "strix.db"
    scope_path = workdir / "scope.json"
    port = free_port()
    api_key = f"smoke-{secrets.token_urlsafe(32)}"   # adopted as the admin bootstrap key

    process: subprocess.Popen | None = None
    with LabTarget() as lab:
        scope_path.write_text(json.dumps({
            "program": "strix e2e smoke",
            "authorized_by": "scripts/smoke_e2e.py",
            "authorization_ref": "local-loopback-only",
            "include": ["127.0.0.1"],
            "authorized_networks": ["127.0.0.0/8", "::1/128"],
            "allowed_ports": [lab.port],
        }))
        env = {
            **os.environ,
            "STRIX_DB": str(db_path),
            "STRIX_SCOPE_FILE": str(scope_path),
            "STRIX_API_KEY": api_key,
            "STRIX_SCOPE_MODE": "global",
            "STRIX_WORKERS": "1",
            "STRIX_LOG_LEVEL": "WARNING",
            "PYTHONPATH": str(REPO_ROOT / "src"),
        }
        base = f"http://127.0.0.1:{port}"
        process = subprocess.Popen(
            [sys.executable, "-m", "strix", "--host", "127.0.0.1", "--port", str(port)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            wait_for_health(base, process)

            status, body, _headers = request(f"{base}/api/ready")
            ready = json.loads(body)
            check("readiness reports a loaded scope",
                  status == 200 and ready["ready"] and ready["scope_configured"],
                  str(ready))

            check("unauthenticated metrics refused",
                  request(f"{base}/api/metrics")[0] == 401)
            check("unauthenticated assessment refused",
                  request(f"{base}/api/assess", method="POST", body={"target": lab.base_url})[0] == 401)

            auth = {"Authorization": f"Bearer {api_key}"}
            tenant_key = json.loads(request(
                f"{base}/api/keys/create", method="POST",
                body={"tenant": "e2e-tenant", "tier": "free"}, headers=auth)[1])["api_key"]
            tenant_auth = {"Authorization": f"Bearer {tenant_key}"}
            check("non-admin cannot read platform metrics",
                  request(f"{base}/api/metrics", headers=tenant_auth)[0] == 403)

            idem_headers = {**tenant_auth, "Idempotency-Key": "e2e-scan-1"}
            status, body, _headers = request(
                f"{base}/api/assess", method="POST",
                body={"target": f"{lab.base_url}/search?q=smoke", "profile": "network",
                      "timeout": 120.0},
                headers=idem_headers)
            check("assessment accepted asynchronously", status == 202, f"{status} {body[:200].decode()}")
            job_id = json.loads(body)["id"]
            done = poll_terminal(base, job_id, tenant_auth)
            check("assessment completed with full coverage",
                  done["state"] == "completed", f"{done['state']}: {done.get('error')}")
            categories = {finding["category"] for finding in done["findings"]}
            check("reflection bait detected", "xss" in categories, str(sorted(categories)))
            check("git exposure bait detected", "git_config_exposed" in categories,
                  str(sorted(categories)))
            check("open port observed", "open_tcp_port" in categories, str(sorted(categories)))
            check("coverage names every adapter that ran",
                  {run["adapter"] for run in done["coverage"]["adapters"]}
                  >= {"strix-http", "strix-git-exposure", "strix-tcp"},
                  str(done["coverage"]["adapters"]))

            status, body, _headers = request(
                f"{base}/api/assess", method="POST",
                body={"target": f"{lab.base_url}/search?q=smoke", "profile": "network"},
                headers=idem_headers)
            repeated = json.loads(body)
            check("repeated submission is deduplicated",
                  repeated["id"] == job_id and repeated.get("deduplicated") is True, str(repeated)[:200])

            check("HTML report renders",
                  request(f"{base}/api/assess/{job_id}/report.html",
                          headers=tenant_auth)[0] == 200)
            sarif_status, sarif_body, _headers = request(
                f"{base}/api/assess/{job_id}/sarif", headers=tenant_auth)
            check("SARIF export is valid JSON",
                  sarif_status == 200 and json.loads(sarif_body)["version"] == "2.1.0")

            check("out-of-scope target refused",
                  request(f"{base}/api/assess", method="POST",
                          body={"target": "http://169.254.169.254/latest/meta-data/"},
                          headers=tenant_auth)[0] == 403)

            check("admin metrics readable",
                  request(f"{base}/api/metrics", headers=auth)[0] == 200)
        finally:
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            if not args.keep:
                for path in (db_path, db_path.with_name(db_path.name + "-wal"),
                             db_path.with_name(db_path.name + "-shm"), scope_path):
                    path.unlink(missing_ok=True)

    print(f"\nOK: {len(PASSED)} end-to-end checks passed on a live server (lab {lab.base_url})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

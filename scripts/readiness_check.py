"""End-to-end release gate for a real-world Ishastra deployment.

Starts the API in production mode against a throwaway database, runs a real
assessment against a local HTTP target, and proves the trust layer end to end:
scope refusal, SARIF export, audit verification, backup/restore and the
grant -> gate -> proof -> verify chain. Everything runs on loopback with a
temporary directory; nothing outside the workspace is modified.

Exit status 0 means every check passed. Any failure prints the check, the
observed value, and exits 1.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_port(port: int, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict | None = None,
    timeout: float = 15.0,
) -> tuple[int, bytes]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class Gate:
    def __init__(self) -> None:
        self.checks: list[tuple[str, bool, str]] = []

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append((name, ok, detail))
        return ok

    def summary(self) -> int:
        width = max(len(name) for name, _, _ in self.checks)
        for name, ok, detail in self.checks:
            marker = "PASS" if ok else "FAIL"
            print(f"{marker}  {name.ljust(width)}  {detail}")
        failed = [name for name, ok, _ in self.checks if not ok]
        print()
        if failed:
            print(f"NOT READY: {len(failed)} check(s) failed: {', '.join(failed)}")
            return 1
        print(f"READY: {len(self.checks)} checks passed")
        return 0


def run(args: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> tuple[int, str]:
    proc = subprocess.run(
        args,
        cwd=str(cwd or ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def main() -> int:
    gate = Gate()
    work = Path(tempfile.mkdtemp(prefix="ishastra-readiness-"))
    target_port = free_port()
    api_port = free_port()
    gate_port = free_port()
    api_key = secrets.token_urlsafe(32)
    # Hex: a urlsafe token can start with "-", which argparse reads as an option.
    hmac_key = secrets.token_hex(32)
    encryption_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    processes: list[subprocess.Popen] = []

    scope_path = work / "scope.json"
    scope_path.write_text(
        json.dumps(
            {
                "program": "readiness-gate",
                "authorized_by": "scripts/readiness_check.py",
                "authorization_ref": "local-loopback-only",
                "include": ["127.0.0.1"],
                "authorized_networks": ["127.0.0.0/8"],
                "allowed_ports": [target_port],
                "allow_broad_networks": True,
            }
        )
    )

    env = {
        **os.environ,
        "ISHASTRA_ENV": "production",
        "ISHASTRA_API_KEY": api_key,
        "ISHASTRA_AUDIT_HMAC_KEY": hmac_key,
        "ISHASTRA_ENCRYPTION_KEY": encryption_key,
        "ISHASTRA_DB": str(work / "ishastra.db"),
        "ISHASTRA_DATABASE_URL": "",
        "ISHASTRA_SCOPE_FILE": str(scope_path),
        "ISHASTRA_SCOPE_MODE": "global",
        "ISHASTRA_LOG_LEVEL": "WARNING",
        "ISHASTRA_WORKERS": "1",
        "ISHASTRA_QUEUE_MODE": "inprocess",
        "ISHASTRA_RETENTION_DAYS": "0",
    }
    auth = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    base = f"http://127.0.0.1:{api_port}"

    try:
        target = subprocess.Popen(
            [PY, "-m", "http.server", str(target_port), "--bind", "127.0.0.1"],
            cwd=str(work),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        processes.append(target)

        api = subprocess.Popen(
            [
                PY,
                "-m",
                "uvicorn",
                "ishastra.api.app:create_app",
                "--factory",
                "--host",
                "127.0.0.1",
                "--port",
                str(api_port),
            ],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        processes.append(api)

        if not gate.check("api starts", wait_port(api_port), f"uvicorn on {api_port}"):
            return gate.summary()

        gate.check("health", request(f"{base}/api/health")[0] == 200)
        gate.check("ready", request(f"{base}/api/ready")[0] == 200)
        gate.check("ui", request(f"{base}/")[0] == 200)
        docs_status, _ = request(f"{base}/docs")
        gate.check("docs disabled in production", docs_status == 404, f"status {docs_status}")
        unauth_status, _ = request(f"{base}/api/findings")
        gate.check("unauthenticated read refused", unauth_status == 401, f"status {unauth_status}")
        metrics_status, _ = request(f"{base}/api/metrics")
        gate.check("metrics requires admin", metrics_status == 401, f"status {metrics_status}")

        ok_status, payload = request(
            f"{base}/api/assess",
            method="POST",
            headers=auth,
            body={"target": f"http://127.0.0.1:{target_port}/", "profile": "web"},
        )
        created = json.loads(payload) if payload else {}
        job_id = created.get("id") or created.get("job_id", "")
        gate.check("authorized assessment accepted", ok_status in (200, 202), f"status {ok_status}")

        state = ""
        coverage: dict = {}
        deadline = time.monotonic() + 60
        while job_id and time.monotonic() < deadline:
            status, payload = request(f"{base}/api/assess/{job_id}", headers=auth)
            if status == 200:
                job = json.loads(payload)
                state = job.get("state", "")
                coverage = job.get("coverage") or {}
                if state in {"completed", "partial", "failed", "cancelled"}:
                    break
            time.sleep(0.5)
        gate.check(
            "assessment reached a terminal state",
            state in {"completed", "partial"},
            f"state={state or 'timeout'}",
        )
        gate.check(
            "coverage recorded (partial is not reported clean)",
            isinstance(coverage, dict) and "total" in coverage,
            f"coverage={coverage.get('ok', '?')}/{coverage.get('total', '?')} ok",
        )

        gate.check(
            "SARIF export",
            request(f"{base}/api/assess/{job_id}/sarif", headers=auth)[0] == 200,
        )
        out_status, _ = request(
            f"{base}/api/assess",
            method="POST",
            headers=auth,
            body={"target": "http://example.com/", "profile": "web"},
        )
        gate.check("out-of-scope target refused", out_status == 403, f"status {out_status}")
        gate.check("audit chain verifies", request(f"{base}/api/audit/verify", headers=auth)[0] == 200)
    finally:
        for proc in reversed(processes):
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    drill_code, drill_out = run(
        [
            PY,
            str(ROOT / "scripts" / "operational_check.py"),
            "--db",
            str(work / "ishastra.db"),
            "--hmac-key",
            hmac_key,
            "--out",
            str(work / "restore.db"),
        ]
    )
    gate.check(
        "backup/restore + audit chain", drill_code == 0, drill_out.splitlines()[-1] if drill_out else ""
    )

    proof = work / "proof"
    proof.mkdir()
    grant_code, _ = run(
        [
            PY,
            "-m",
            "ishastra",
            "grant",
            "--program",
            "readiness",
            "--authorized-by",
            "readiness-gate",
            "--ref",
            "loopback",
            "--include",
            "93.184.216.34",
            "--port",
            "80",
            "--days",
            "1",
            "--out",
            str(proof / "grant.json"),
            "--key-out",
            str(proof / "issuer.key"),
        ]
    )
    gate.check("grant signs", grant_code == 0)

    gate_proc = subprocess.Popen(
        [
            PY,
            "-m",
            "ishastra",
            "gate",
            "--grant",
            str(proof / "grant.json"),
            "--ledger",
            str(proof / "receipts.jsonl"),
            "--gate-key",
            str(proof / "gate.key"),
            "--port",
            str(gate_port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        started = wait_port(gate_port)
        allow_status, allow_body = request(
            f"http://127.0.0.1:{gate_port}/v1/authorize",
            method="POST",
            headers={"Content-Type": "application/json"},
            body={"url": "http://93.184.216.34/", "method": "GET"},
        )
        deny_status, deny_body = request(
            f"http://127.0.0.1:{gate_port}/v1/authorize",
            method="POST",
            headers={"Content-Type": "application/json"},
            body={"url": "http://example.net/", "method": "GET"},
        )
        allow = json.loads(allow_body).get("decision") if allow_body else ""
        deny = json.loads(deny_body).get("decision") if deny_body else ""
        gate.check("gate starts", started)
        gate.check("gate allows authorized action", allow == "allow", f"decision={allow or deny_status}")
        gate.check("gate denies out-of-scope action", deny == "deny", f"decision={deny or deny_status}")
    finally:
        gate_proc.terminate()
        try:
            gate_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            gate_proc.kill()

    proof_code, proof_out = run(
        [
            PY,
            "-m",
            "ishastra",
            "proof",
            "--grant",
            str(proof / "grant.json"),
            "--ledger",
            str(proof / "receipts.jsonl"),
            "--out",
            str(proof / "proof.json"),
        ]
    )
    gate.check("proof pack built", proof_code == 0, proof_out.splitlines()[-1] if proof_out else "")
    verify_code, verify_out = run(
        [
            PY,
            "-m",
            "ishastra",
            "verify",
            str(proof / "proof.json"),
            "--issuer-key",
            str(proof / "issuer.key"),
        ]
    )
    gate.check(
        "offline proof verifies",
        verify_code == 0,
        "VERIFIED" if "VERIFIED" in verify_out else verify_out[:80],
    )

    tampered = work / "tampered.json"
    pack = json.loads((proof / "proof.json").read_text())
    pack["summary"]["denied"] = 99
    tampered.write_text(json.dumps(pack))
    tamper_code, _ = run(
        [
            PY,
            "-m",
            "ishastra",
            "verify",
            str(tampered),
            "--issuer-key",
            str(proof / "issuer.key"),
        ]
    )
    gate.check("tampered proof rejected", tamper_code != 0, f"exit {tamper_code}")
    missing_code, _ = run(
        [
            PY,
            "-m",
            "ishastra",
            "verify",
            str(work / "missing.json"),
            "--issuer-key",
            str(proof / "issuer.key"),
        ]
    )
    gate.check("missing proof rejected", missing_code != 0, f"exit {missing_code}")

    db = sqlite3.connect(work / "ishastra.db")
    try:
        integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        db.close()
    gate.check("database integrity", integrity == "ok", integrity)

    if "--keep" in sys.argv:
        print(f"artifacts kept in {work}")
    else:
        shutil.rmtree(work, ignore_errors=True)
    return gate.summary()


if __name__ == "__main__":
    raise SystemExit(main())

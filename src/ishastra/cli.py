"""Command-line entry points: ``ishastra`` (server) and ``ishastra assess`` (CLI scan)."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import logging
import os
import re
import secrets
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import uvicorn

from ishastra import __version__, proof
from ishastra.config import Settings, get_settings
from ishastra.core import jobs as jobs_module
from ishastra.core import scope as scope_module
from ishastra.core import store
from ishastra.core.findings import to_sarif
from ishastra.locale import LocaleCode, TemplateContext
from ishastra.report_pdf import render_pdf_report


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "time": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry)


def _configure_logging(settings: Settings) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(
        _JsonFormatter()
        if settings.log_format == "json"
        else logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logging.basicConfig(level=settings.log_level, handlers=[handler])


def _build_auth_config(args: argparse.Namespace) -> dict[str, Any] | None:
    """Build authentication configuration from CLI arguments."""

    if args.auth_config:
        import json

        config_path = Path(args.auth_config).expanduser().resolve()
        try:
            with open(config_path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"failed to load auth config from {config_path}: {exc}") from exc

    auth_type = args.auth_type
    if not auth_type:
        has_auth_flags = any(
            [
                args.auth_bearer,
                args.auth_api_key,
                args.auth_header,
                args.auth_cookie,
                args.auth_login_url,
                args.auth_username,
                args.auth_password,
            ]
        )
        if not has_auth_flags:
            return None

        if args.auth_bearer or args.auth_api_key:
            auth_type = "token"
        elif args.auth_cookie:
            auth_type = "session"
        elif args.auth_login_url:
            auth_type = "form_login"
        else:
            return None

    config = {"type": auth_type, "principal_id": f"cli-auth-{secrets.token_hex(4)}"}

    if auth_type == "token":
        if args.auth_bearer:
            config["bearer"] = args.auth_bearer
        if args.auth_api_key:
            config["api_key"] = args.auth_api_key
            config["api_key_header"] = args.auth_api_key_header
        custom_headers = {}
        for h in args.auth_header:
            if ":" in h:
                name, value = h.split(":", 1)
                custom_headers[name.strip()] = value.strip()
        if custom_headers:
            config["custom_headers"] = custom_headers

    elif auth_type == "session":
        cookies = {}
        for c in args.auth_cookie:
            if "=" in c:
                name, value = c.split("=", 1)
                cookies[name.strip()] = value.strip()
        if cookies:
            config["cookies"] = cookies

    elif auth_type == "form_login":
        if not args.auth_login_url:
            raise ValueError("--auth-login-url required for form_login auth")
        if not args.auth_username or not args.auth_password:
            raise ValueError("--auth-username and --auth-password required for form_login auth")
        config["login_url"] = args.auth_login_url
        config["username"] = args.auth_username
        config["password"] = args.auth_password
        config["username_field"] = args.auth_username_field
        config["password_field"] = args.auth_password_field
        if args.auth_csrf_field:
            config["csrf_field"] = args.auth_csrf_field
        extra_fields = {}
        for f in args.auth_extra_field:
            if "=" in f:
                name, value = f.split("=", 1)
                extra_fields[name.strip()] = value.strip()
        if extra_fields:
            config["extra_fields"] = extra_fields

    elif auth_type == "multi_step":
        raise ValueError("multi_step auth not yet supported via CLI; use --auth-config file")

    return config


def _run_server(args: argparse.Namespace) -> None:
    settings = get_settings()
    _configure_logging(settings)
    if args.reset_audit_chain:
        store.configure(settings.db_path)
        removed = store.reset_audit_chain_sync()
        print(f"audit chain reset: removed {removed} entries from {settings.db_path}")

    forwarded_allow_ips = os.environ.get("ISHASTRA_FORWARDED_ALLOW_IPS", "*")
    uvicorn.run(
        "ishastra.api.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        proxy_headers=True,
        forwarded_allow_ips=forwarded_allow_ips,
        timeout_graceful_shutdown=30,
    )


def _prepare_demo_environment(directory: Path) -> dict[str, str]:
    """Write a signed demo scope and fresh keys; return the env the server needs.

    Self-contained on purpose: no scope to author, no key to generate by hand,
    and nothing outside ``directory`` is touched.
    """
    import base64

    from ishastra.core import scope_signing

    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / "scope-signing-key.pem"
    jwks_path = directory / "jwks.json"
    document = {
        "version": 2,
        "program": "Ishastra demo (self-owned targets only)",
        "authorized_by": "Demo operator",
        "authorization_ref": "DEMO-001",
        "include": ["localhost", "127.0.0.1"],
        "exclude": [],
        "authorized_networks": [],
        "allowed_ports": [80, 443, 8000],
        "allow_broad_networks": False,
    }
    pem, jwk = scope_signing.generate_keypair("demo")
    key_path.write_bytes(pem)
    key_path.chmod(0o600)
    jwks_path.write_text(json.dumps({"keys": [jwk]}, indent=2) + "\n")
    key = scope_signing.load_private_key_file(key_path)
    signed = scope_signing.sign_document(document, key, jwk["kid"])
    scope_signing.verify_document(signed, {jwk["kid"]: key.public_key()})
    scope_path = directory / "scope.json"
    scope_path.write_text(json.dumps(signed, indent=2) + "\n")
    return {
        "ISHASTRA_ENV": "development",
        "ISHASTRA_DB": str(directory / "ishastra-demo.db"),
        "ISHASTRA_SCOPE_FILE": str(scope_path),
        "ISHASTRA_SCOPE_JWKS": str(jwks_path),
        "ISHASTRA_API_KEY": secrets.token_urlsafe(32),
        "ISHASTRA_AUDIT_HMAC_KEY": base64.b64encode(os.urandom(32)).decode(),
        "ISHASTRA_ENCRYPTION_KEY": base64.b64encode(os.urandom(32)).decode(),
        "ISHASTRA_WORKERS": "1",
        "ISHASTRA_LOG_LEVEL": "INFO",
    }


def _run_demo(args: argparse.Namespace) -> None:
    """Boot a self-contained instance: signed localhost scope, fresh key, SQLite."""
    directory = Path(args.data_dir).expanduser().resolve()
    env = _prepare_demo_environment(directory)
    os.environ.update(env)
    print("Ishastra demo")
    print(f"  UI:      http://{args.host}:{args.port}")
    print(f"  API key: {env['ISHASTRA_API_KEY']}")
    print("           paste it into the API-key field in the top bar")
    print(f"  scope:   {env['ISHASTRA_SCOPE_FILE']} (Ed25519-signed, localhost only)")
    print(f"  data:    {directory}")
    _run_server(argparse.Namespace(host=args.host, port=args.port, reload=False, reset_audit_chain=False))


def _run_assess(args: argparse.Namespace) -> int:
    """Run a single assessment and output SARIF. Returns exit code."""
    settings = get_settings()
    _configure_logging(settings)

    auth_config = _build_auth_config(args)

    job_policy = {}
    if auth_config is not None:
        if not settings.encryption_key:
            print("error: ISHASTRA_ENCRYPTION_KEY not configured (required for auth)", file=sys.stderr)
            return 3
        try:
            from ishastra.core.auth import EncryptedAuthConfig, create_authenticator_from_dict

            authenticator = create_authenticator_from_dict(auth_config)
            encrypted_auth = EncryptedAuthConfig.create(authenticator, settings.encryption_key)
            job_policy["encrypted_auth_config"] = {
                "principal_id": encrypted_auth.principal_id,
                "authenticator_type": encrypted_auth.authenticator_type,
                "encrypted_config": encrypted_auth.encrypted_config,
                "created_at": encrypted_auth.created_at,
            }
        except Exception as exc:
            print(f"error: invalid auth configuration: {exc}", file=sys.stderr)
            return 3

    gate: proof.Gate | None = None
    grant: proof.Grant | None = None
    loaded_scope: scope_module.Scope | None
    if args.grant:
        try:
            grant = proof.load_grant(args.grant)
            gate = proof.Gate(
                grant,
                signing_key=_gate_key(args.gate_key) if args.gate_key else "",
                actor=args.actor,
                ledger_path=args.proof_ledger,
                trusted_issuer=_public_key(args.trusted_issuer) or None,
            )
            loaded_scope = grant.to_scope()
        except (proof.ProofError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
    elif getattr(args, "scope_file", "") and isinstance(args.scope_file, str) and args.scope_file:
        scope_path = Path(args.scope_file).expanduser().resolve()
        if not scope_path.exists():
            print(f"error: scope file not found: {scope_path}", file=sys.stderr)
            return 3

        content = scope_path.read_text()
        scope_doc = None

        scope_format = getattr(args, "scope_format", "auto")
        if scope_format == "scope" or (scope_format == "auto" and "scope" in scope_path.name.lower()):
            scope_doc = _import_from_scope(content)
        elif scope_format == "har" or (scope_format == "auto" and scope_path.suffix == ".har"):
            scope_doc = _import_from_har(content)
        elif scope_format == "openapi" or (
            scope_format == "auto" and scope_path.suffix in (".json", ".yaml", ".yml")
        ):
            scope_doc = _import_from_openapi(content, scope_path.suffix)
        else:
            msg = "error: unsupported format '{scope_format}'. Use --scope-format openapi|har|scope|auto"
            print(msg.format(scope_format=scope_format), file=sys.stderr)
            return 3

        if scope_doc is None:
            print("error: failed to extract scope from input", file=sys.stderr)
            return 3

        scope_domain = getattr(args, "scope_domain", "")
        if scope_domain:
            scope_doc = _substitute_domain(scope_doc, scope_domain)

        scope_ports = getattr(args, "scope_ports", "")
        if scope_ports:
            scope_doc["allowed_ports"] = [int(p.strip()) for p in scope_ports.split(",") if p.strip()]

        try:
            from ishastra.core.scope import Scope

            loaded_scope = Scope(
                program=scope_doc.get("program", "Imported scope"),
                authorized_by=scope_doc.get("authorized_by", "REPLACE: authorizing authority"),
                authorization_ref=scope_doc.get("authorization_ref", "REPLACE: engagement reference"),
                include=tuple(scope_doc.get("include", [])),
                exclude=tuple(scope_doc.get("exclude", [])),
                authorized_networks=tuple(scope_doc.get("authorized_networks", [])),
                allowed_ports=tuple(scope_doc.get("allowed_ports", [80, 443])),
                allow_broad_networks=scope_doc.get("allow_broad_networks", False),
            )
        except ValueError as exc:
            print(f"error: invalid scope document: {exc}", file=sys.stderr)
            return 3
    else:
        scope_path = Path(args.scope).expanduser().resolve()
        loaded_scope = scope_module.load(scope_path)
        if loaded_scope is None:
            print(f"error: scope file not found: {scope_path}", file=sys.stderr)
            return 3

    try:
        job = jobs_module.prepare(
            target=args.target,
            profile=args.profile,
            actor=args.actor,
            timeout=args.timeout,
            scope_snapshot=loaded_scope,
            policy=job_policy or None,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    with gate.observe() if gate is not None else contextlib.nullcontext():
        jobs_module.execute(job)

    if gate is not None and grant is not None and args.proof_out:
        try:
            pack = proof.build_pack(grant, gate.ledger)
        except proof.ProofError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
        pack_path = Path(args.proof_out).expanduser().resolve()
        pack_path.write_text(json.dumps(pack, indent=2))
        print(
            f"proof pack written to {pack_path} ({len(pack['receipts'])} receipts)",
            file=sys.stderr,
        )

    sarif_doc = to_sarif(job.findings, tool_version=job.policy.get("tool_version", "ishastra"))
    output = json.dumps(sarif_doc, indent=2)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(output)
        print(f"SARIF written to {output_path}", file=sys.stderr)
    else:
        print(output)

    if job.state is jobs_module.JobState.COMPLETED:
        return 0 if not job.findings else 1
    if job.state is jobs_module.JobState.FAILED:
        if job.error and "out_of_scope" in job.error:
            return 2
        print(f"assessment failed: {job.error}", file=sys.stderr)
        return 3
    if job.state is jobs_module.JobState.CANCELLED:
        print("assessment cancelled", file=sys.stderr)
        return 3
    return 3


def _run_assess_submit(args: argparse.Namespace) -> int:
    """Submit an assessment to the queue (async). Returns exit code."""
    settings = get_settings()
    _configure_logging(settings)

    auth_config = _build_auth_config(args)

    job_policy = {}
    if auth_config is not None:
        if not settings.encryption_key:
            print("error: ISHASTRA_ENCRYPTION_KEY not configured (required for auth)", file=sys.stderr)
            return 3
        try:
            from ishastra.core.auth import EncryptedAuthConfig, create_authenticator_from_dict

            authenticator = create_authenticator_from_dict(auth_config)
            encrypted_auth = EncryptedAuthConfig.create(authenticator, settings.encryption_key)
            job_policy["encrypted_auth_config"] = {
                "principal_id": encrypted_auth.principal_id,
                "authenticator_type": encrypted_auth.authenticator_type,
                "encrypted_config": encrypted_auth.encrypted_config,
                "created_at": encrypted_auth.created_at,
            }
        except Exception as exc:
            print(f"error: invalid auth configuration: {exc}", file=sys.stderr)
            return 3

    gate: proof.Gate | None = None
    grant: proof.Grant | None = None
    loaded_scope: scope_module.Scope | None
    if args.grant:
        try:
            grant = proof.load_grant(args.grant)
            gate = proof.Gate(
                grant,
                signing_key=_gate_key(args.gate_key) if args.gate_key else "",
                actor=args.actor,
                ledger_path=args.proof_ledger,
                trusted_issuer=_public_key(args.trusted_issuer) or None,
            )
            loaded_scope = grant.to_scope()
        except (proof.ProofError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
    elif getattr(args, "scope_file", "") and isinstance(args.scope_file, str) and args.scope_file:
        scope_path = Path(args.scope_file).expanduser().resolve()
        if not scope_path.exists():
            print(f"error: scope file not found: {scope_path}", file=sys.stderr)
            return 3

        content = scope_path.read_text()
        scope_doc = None

        scope_format = getattr(args, "scope_format", "auto")
        if scope_format == "scope" or (scope_format == "auto" and "scope" in scope_path.name.lower()):
            scope_doc = _import_from_scope(content)
        elif scope_format == "har" or (scope_format == "auto" and scope_path.suffix == ".har"):
            scope_doc = _import_from_har(content)
        elif scope_format == "openapi" or (
            scope_format == "auto" and scope_path.suffix in (".json", ".yaml", ".yml")
        ):
            scope_doc = _import_from_openapi(content, scope_path.suffix)
        else:
            msg = "error: unsupported format '{scope_format}'. Use --scope-format openapi|har|scope|auto"
            print(msg.format(scope_format=scope_format), file=sys.stderr)
            return 3

        if scope_doc is None:
            print("error: failed to extract scope from input", file=sys.stderr)
            return 3

        scope_domain = getattr(args, "scope_domain", "")
        if scope_domain:
            scope_doc = _substitute_domain(scope_doc, scope_domain)

        scope_ports = getattr(args, "scope_ports", "")
        if scope_ports:
            scope_doc["allowed_ports"] = [int(p.strip()) for p in scope_ports.split(",") if p.strip()]

        try:
            from ishastra.core.scope import Scope

            loaded_scope = Scope(
                program=scope_doc.get("program", "Imported scope"),
                authorized_by=scope_doc.get("authorized_by", "REPLACE: authorizing authority"),
                authorization_ref=scope_doc.get("authorization_ref", "REPLACE: engagement reference"),
                include=tuple(scope_doc.get("include", [])),
                exclude=tuple(scope_doc.get("exclude", [])),
                authorized_networks=tuple(scope_doc.get("authorized_networks", [])),
                allowed_ports=tuple(scope_doc.get("allowed_ports", [80, 443])),
                allow_broad_networks=scope_doc.get("allow_broad_networks", False),
            )
        except ValueError as exc:
            print(f"error: invalid scope document: {exc}", file=sys.stderr)
            return 3
    else:
        scope_path = Path(args.scope).expanduser().resolve()
        loaded_scope = scope_module.load(scope_path)
        if loaded_scope is None:
            print(f"error: scope file not found: {scope_path}", file=sys.stderr)
            return 3

    try:
        job = jobs_module.prepare(
            target=args.target,
            profile=args.profile,
            actor=args.actor,
            timeout=args.timeout,
            scope_snapshot=loaded_scope,
            policy=job_policy or None,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    # Submit to queue
    try:
        import asyncio
        from ishastra.core.queue import get_assessment_queue

        queue = get_assessment_queue()

        async def submit_job():
            await queue.start()
            await queue.submit(job, lambda j: None)

        asyncio.run(submit_job())
    except Exception as exc:
        print(f"error: failed to submit job: {exc}", file=sys.stderr)
        return 3

    print(f"job submitted: {job.id}")
    print(f"  target: {args.target}")
    print(f"  profile: {args.profile}")
    print(f"  status: queued")
    print(f"  check status with: ishastra assess status --job-id {job.id}")
    return 0


def _run_assess_status(args: argparse.Namespace) -> int:
    """Check status of a submitted assessment job. Returns exit code."""
    settings = get_settings()
    _configure_logging(settings)

    try:
        import asyncio
        from ishastra.core import store

        store.configure(settings.db_path)

        async def get_status():
            await store.get_database()
            job = await store.get_job(args.job_id, tenant=args.tenant or None)
            return job

        job = asyncio.run(get_status())
    except Exception as exc:
        print(f"error: failed to get job status: {exc}", file=sys.stderr)
        return 3

    if job is None:
        print(f"error: job {args.job_id} not found", file=sys.stderr)
        return 3

    print(f"job: {job['id']}")
    print(f"  target: {job['target']}")
    print(f"  profile: {job['profile']}")
    print(f"  state: {job['state']}")
    print(f"  verdict: {job['verdict']}")
    if job['started_at']:
        print(f"  started: {datetime.fromtimestamp(job['started_at']).isoformat()}")
    if job['finished_at']:
        print(f"  finished: {datetime.fromtimestamp(job['finished_at']).isoformat()}")
    if job['error']:
        print(f"  error: {job['error']}")
    print(f"  coverage: {job['coverage']}")
    print(f"  findings: {len(job['findings'])}")
    return 0


def _run_assess_list(args: argparse.Namespace) -> int:
    """List assessment jobs for a tenant. Returns exit code."""
    settings = get_settings()
    _configure_logging(settings)

    try:
        import asyncio
        from ishastra.core import store

        store.configure(settings.db_path)

        async def list_jobs():
            await store.get_database()
            return await store.list_jobs(tenant=args.tenant, limit=args.limit, offset=args.offset)

        jobs = asyncio.run(list_jobs())
    except Exception as exc:
        print(f"error: failed to list jobs: {exc}", file=sys.stderr)
        return 3

    if not jobs:
        print(f"no jobs found for tenant {args.tenant}")
        return 0

    print(f"jobs for tenant {args.tenant}:")
    for job in jobs:
        print(f"  {job['id']}  {job['state']:12}  {job['target']}  {job['profile']}  {job['verdict']}")
    return 0


def _run_evidence(args: argparse.Namespace) -> int:
    """Run compliance assessment and generate evidence pack. Returns exit code."""
    settings = get_settings()
    _configure_logging(settings)

    from ishastra.locale import TemplateContext

    locale_code: LocaleCode = args.locale
    loaded_scope: scope_module.Scope | None = None

    if getattr(args, "scope_file", "") and isinstance(args.scope_file, str) and args.scope_file:
        scope_path = Path(args.scope_file).expanduser().resolve()
        if not scope_path.exists():
            print(f"error: scope file not found: {scope_path}", file=sys.stderr)
            return 3

        content = scope_path.read_text()
        scope_doc = None

        scope_format = getattr(args, "scope_format", "auto")
        if scope_format == "scope" or (scope_format == "auto" and "scope" in scope_path.name.lower()):
            scope_doc = _import_from_scope(content)
        elif scope_format == "har" or (scope_format == "auto" and scope_path.suffix == ".har"):
            scope_doc = _import_from_har(content)
        elif scope_format == "openapi" or (
            scope_format == "auto" and scope_path.suffix in (".json", ".yaml", ".yml")
        ):
            scope_doc = _import_from_openapi(content, scope_path.suffix)
        else:
            msg = "error: unsupported format '{fmt}'. Use --scope-format openapi|har|scope|auto"
            print(msg.format(fmt=scope_format), file=sys.stderr)
            return 3

        if scope_doc is None:
            print("error: failed to extract scope from input", file=sys.stderr)
            return 3

        scope_domain = getattr(args, "scope_domain", "")
        if scope_domain:
            scope_doc = _substitute_domain(scope_doc, scope_domain)

        scope_ports = getattr(args, "scope_ports", "")
        if scope_ports:
            scope_doc["allowed_ports"] = [int(p.strip()) for p in scope_ports.split(",") if p.strip()]

        try:
            from ishastra.core.scope import Scope

            loaded_scope = Scope(
                program=scope_doc.get("program", "Imported scope"),
                authorized_by=scope_doc.get("authorized_by", "REPLACE: authorizing authority"),
                authorization_ref=scope_doc.get("authorization_ref", "REPLACE: engagement reference"),
                include=tuple(scope_doc.get("include", [])),
                exclude=tuple(scope_doc.get("exclude", [])),
                authorized_networks=tuple(scope_doc.get("authorized_networks", [])),
                allowed_ports=tuple(scope_doc.get("allowed_ports", [80, 443])),
                allow_broad_networks=scope_doc.get("allow_broad_networks", False),
            )
        except ValueError as exc:
            print(f"error: invalid scope document: {exc}", file=sys.stderr)
            return 3
    else:
        scope_path = Path(args.scope).expanduser().resolve()
        loaded_scope = scope_module.load(scope_path)
        if loaded_scope is None:
            print(f"error: scope file not found: {scope_path}", file=sys.stderr)
            return 3

    try:
        job = jobs_module.prepare(
            target=args.target,
            profile=args.profile,
            actor=args.actor,
            timeout=args.timeout,
            scope_snapshot=loaded_scope,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    jobs_module.execute(job)

    from ishastra.core import evidence as evidence_module

    frameworks = ["nrb", "nta", "ncsp"] if args.framework == "all" else [args.framework]
    mappings = evidence_module.load_mappings(frameworks)

    pack = evidence_module.build_evidence_pack(
        job=job,
        mappings=mappings,
        include_passing=args.include_passing,
    )

    context = TemplateContext(
        locale_code=locale_code,
        client_name=args.client_name or (loaded_scope.program if loaded_scope else ""),
        client_name_nepali=args.client_name_nepali,
        organization_name=args.org_name or "Ishastra Security",
        organization_name_nepali=args.org_name_nepali,
        program_name=loaded_scope.program if loaded_scope else "",
        authorized_by=loaded_scope.authorized_by if loaded_scope else "",
        authorization_ref=loaded_scope.authorization_ref if loaded_scope else "",
        target=args.target,
    )

    if args.format == "sarif":
        sarif_doc = to_sarif(job.findings, tool_version="ishastra-evidence")
        output = json.dumps(sarif_doc, indent=2)
    elif args.format == "csv":
        output = evidence_module.to_csv(pack)
    elif args.format == "oscal":
        output = evidence_module.to_oscal(pack)
    elif args.format == "pdf":
        report = {
            "target": args.target,
            "job_id": job.id if hasattr(job, "id") else "unknown",
            "state": job.state.name if hasattr(job, "state") else "unknown",
            "verdict": job.verdict if hasattr(job, "verdict") else "unknown",
            "program": loaded_scope.program if loaded_scope else "unknown",
            "authorized_by": loaded_scope.authorized_by if loaded_scope else "unknown",
            "authorization_ref": loaded_scope.authorization_ref if loaded_scope else "unknown",
            "scope_include": loaded_scope.include if loaded_scope else [],
            "findings": [
                {
                    "severity": f.severity if hasattr(f, "severity") else "info",
                    "confidence": f.confidence if hasattr(f, "confidence") else "unknown",
                    "title": f.title if hasattr(f, "title") else "untitled",
                    "category": f.category if hasattr(f, "category") else "unknown",
                    "cwe": f.cwe if hasattr(f, "cwe") else "no CWE",
                    "asset": f.asset if hasattr(f, "asset") else "unknown",
                    "location": f.location if hasattr(f, "location") else "unknown",
                    "evidence": f.evidence if hasattr(f, "evidence") else "",
                    "remediation": f.remediation if hasattr(f, "remediation") else "",
                    "description": f.description if hasattr(f, "description") else "",
                    "detector": f.detector if hasattr(f, "detector") else "unknown",
                    "detector_version": f.detector_version if hasattr(f, "detector_version") else "",
                }
                for f in job.findings
            ],
            "coverage": job.coverage() if hasattr(job, "coverage") else {},
            "severity_counts": {},
            "integrity": {"chain_valid": True, "chain_hash": ""},
        }
        try:
            pdf_bytes = render_pdf_report(
                report, output_path=args.output, locale_code=locale_code, context=context
            )
            if args.output:
                print(f"PDF report written to {args.output}", file=sys.stderr)
            else:
                import sys as _sys

                _sys.stdout.buffer.write(pdf_bytes)
            return 0
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            print("falling back to printable HTML", file=sys.stderr)
            output = evidence_module.printable_html(pack, locale_code=locale_code, context=context)
    else:
        output = json.dumps(pack, indent=2, default=str)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        if args.format == "pdf" and isinstance(output, bytes):
            output_path.write_bytes(output)
        else:
            output_path.write_text(output)
        print(f"Evidence pack written to {output_path}", file=sys.stderr)
    else:
        if isinstance(output, bytes):
            import sys as _sys

            _sys.stdout.buffer.write(output)
        else:
            print(output)

    if job.state is jobs_module.JobState.FAILED:
        if job.error and "out_of_scope" in job.error:
            return 2
        print(f"assessment failed: {job.error}", file=sys.stderr)
        return 3
    if job.state is jobs_module.JobState.CANCELLED:
        print("assessment cancelled", file=sys.stderr)
        return 3

    has_gaps = any(c.get("status") in ("fail", "gap", "finding") for c in pack.get("controls", []))
    return 1 if has_gaps else 0


def _public_key(value: str) -> str:
    """A public key given inline, or read from a file path.

    A private key file is accepted too: its public key is derived, which is
    what a caller pinning an issuer or gate means by it.
    """
    if not value:
        return ""
    candidate = Path(value).expanduser()
    if not candidate.is_file():
        return value
    text = candidate.read_text().strip()
    if text.startswith(proof.PRIVATE_KEY_PREFIX):
        return proof.public_key(text[len(proof.PRIVATE_KEY_PREFIX) :])
    return proof.load_public_key(candidate)


def _gate_key(path: str) -> str:
    """Reuse the gate key at ``path``, or create it so receipts stay attributable."""
    key_path = Path(path).expanduser()
    if key_path.exists():
        return proof.load_private_key(key_path)
    private, _public = proof.new_keypair()
    proof.write_private_key(key_path, private)
    return private


def _run_grant(args: argparse.Namespace) -> int:
    """Create and sign an authorization grant."""
    try:
        private = proof.load_private_key(args.key) if args.key else proof.new_keypair()[0]
        if not args.key:
            proof.write_private_key(args.key_out, private)
        grant = proof.new_grant(
            program=args.program,
            authorized_by=args.authorized_by,
            authorization_ref=args.ref,
            include=args.include,
            exclude=args.exclude,
            authorized_networks=args.network,
            allowed_ports=args.port,
            allow_broad_networks=args.allow_broad_networks,
            days=args.days,
            grant_id=args.id,
        ).sign(private)
        output = Path(args.out).expanduser().resolve()
        output.write_text(json.dumps(grant.to_dict(), indent=2))
    except (proof.ProofError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    print(f"grant {grant.grant_id} written to {output}", file=sys.stderr)
    if not args.key:
        print(f"issuer key written to {args.key_out} (0600)", file=sys.stderr)
    print(
        f"issuer {grant.issuer} (fingerprint {proof.fingerprint(grant.issuer)})",
        file=sys.stderr,
    )
    return 0


def _run_gate(args: argparse.Namespace) -> int:
    """Serve the authorization gate for any agent, receipting every decision."""
    try:
        grant = proof.load_grant(args.grant)
        gate = proof.Gate(
            grant,
            signing_key=_gate_key(args.gate_key) if args.gate_key else "",
            actor=args.actor,
            ledger_path=args.ledger,
            trusted_issuer=_public_key(args.trusted_issuer) or None,
        )
    except (proof.ProofError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    if not args.trusted_issuer:
        print(
            "warning: issuer key is not pinned; --trusted-issuer makes this gate "
            "accept only the asset owner's signature",
            file=sys.stderr,
        )
    print(
        f"grant {grant.grant_id} ({grant.program}); gate key "
        f"{proof.fingerprint(gate.ledger.gate_public_key)}",
        file=sys.stderr,
    )
    print(f"ledger {args.ledger}", file=sys.stderr)
    print(
        f'POST http://{args.host}:{args.port}/v1/authorize {{"url": "https://...", "method": "GET"}}',
        file=sys.stderr,
    )
    try:
        proof.serve(gate, host=args.host, port=args.port, token=args.token)
    except KeyboardInterrupt:
        print("gate stopped", file=sys.stderr)
    except (proof.ProofError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    return 0


def _run_proof(args: argparse.Namespace) -> int:
    """Bundle a grant and its receipt ledger into a verifiable proof pack."""
    try:
        grant = proof.load_grant(args.grant)
        ledger = proof.Ledger.open(args.ledger)
        if args.gate_key:
            pinned = _public_key(args.gate_key)
            if pinned != ledger.gate_public_key:
                raise proof.ProofError(
                    f"ledger was written by gate "
                    f"{proof.fingerprint(ledger.gate_public_key)}, not "
                    f"{proof.fingerprint(pinned)}"
                )
        pack = proof.build_pack(grant, ledger)
        output = Path(args.out).expanduser().resolve()
        output.write_text(json.dumps(pack, indent=2))
    except (proof.ProofError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    print(
        f"proof pack written to {output} ({len(pack['receipts'])} receipts: "
        f"{pack['summary']['allowed']} allow, {pack['summary']['denied']} deny)",
        file=sys.stderr,
    )
    return 0


def _run_verify(args: argparse.Namespace) -> int:
    """Verify a proof pack offline, with the issuer (and optionally gate) pinned."""
    try:
        pack = json.loads(Path(args.proof).expanduser().read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read proof pack: {exc}", file=sys.stderr)
        return 3
    trusted_issuer = _public_key(args.issuer_key) or None
    trusted_gate = _public_key(args.gate_key) or None
    report = proof.verify_pack(pack, trusted_issuer=trusted_issuer, trusted_gate=trusted_gate)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for name, ok in report["checks"].items():
            print(f"{'ok  ' if ok else 'FAIL'} {name}")
        summary = report["summary"]
        if summary:
            print(
                f"grant {summary['grant_id']} ({summary['program']}) by "
                f"{summary['authorized_by']} ref {summary['authorization_ref']}"
            )
            print(f"{summary['allowed']} allowed, {summary['denied']} denied")
        if not trusted_issuer:
            print("note: issuer key not pinned; this proves the grant is intact, not who issued it")
        for error in report["errors"]:
            print(f"error: {error}", file=sys.stderr)
        print("VERIFIED" if report["ok"] else "NOT VERIFIED")
    return 0 if report["ok"] else 1


def _run_backup(args: argparse.Namespace) -> int:
    """Write one verified database backup, or verify an existing backup file."""
    import asyncio

    from ishastra.core.standby import StandbyError, create_backup, verify_backup

    if args.verify:
        target = Path(args.verify).expanduser().resolve()
        try:
            info = asyncio.run(verify_backup(target))
        except StandbyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3
        print(f"Backup OK ({info['backend']}): {info['path']}")
        print(f"  Size: {info['size_bytes']} bytes")
        if info["backend"] == "sqlite":
            print(f"  Schema version: {info['schema_version']}")
            print(f"  Audit chain entries: {info['audit_chain_entries']}")
        print(f"  Tables: {', '.join(info['tables'])}")
        return 0

    source = (
        args.db or os.environ.get("ISHASTRA_DATABASE_URL") or os.environ.get("ISHASTRA_DB") or "ishastra.db"
    )
    out_dir = Path(args.out).expanduser().resolve()
    try:
        result = create_backup(source, out_dir)
    except StandbyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    info = result["verified"]
    print(f"Backup written ({result['backend']}): {result['path']}")
    print(f"  Size: {result['size_bytes']} bytes")
    if result["backend"] == "sqlite":
        print(f"  Schema version: {info['schema_version']}")
        print(f"  Audit chain entries: {info['audit_chain_entries']}")
    print(f"  Tables: {', '.join(info['tables'])}")
    return 0


def _run_worker(args: argparse.Namespace) -> int:
    """Run the Redis Streams assessment queue worker."""
    import os

    os.environ["ISHASTRA_WORKERS"] = str(getattr(args, "concurrency", 1))
    os.environ["ISHASTRA_QUEUE_MAX"] = str(getattr(args, "queue_max", 1000))

    os.environ["ISHASTRA_WORKER_HEALTH_HOST"] = "0.0.0.0"
    os.environ["ISHASTRA_WORKER_HEALTH_PORT"] = "8080"

    from ishastra.core.worker_runner import main as worker_main

    return worker_main()


def _run_gateway(args: argparse.Namespace) -> int:
    """Run the egress gateway (CONNECT proxy) for worker network."""
    from ishastra.security.egress.gateway import main as gateway_main
    import asyncio
    return asyncio.run(gateway_main())




def _run_vault(args: argparse.Namespace) -> int:
    """Manage secrets in HashiCorp Vault."""
    from ishastra.vault import (
        VaultError,
        delete_secret,
        inject_vault_secrets_into_env,
        list_secrets,
        read_vault_secret,
        write_vault_secret,
    )

    try:
        if args.vault_command == "read":
            secret = read_vault_secret(args.path, args.mount)
            if args.version:
                pass
            if args.json:
                print(json.dumps(secret, indent=2))
            else:
                for k, v in secret.items():
                    print(f"{k}={v}")
            return 0

        if args.vault_command == "write":
            data = json.loads(Path(args.file).read_text()) if args.file else json.loads(args.data)
            write_vault_secret(args.path, data, args.mount)
            print(f"Secret written to {args.mount}/{args.path}")
            return 0

        if args.vault_command == "list":
            keys = list_secrets(args.path, args.mount)
            for k in keys:
                print(k)
            return 0

        if args.vault_command == "delete":
            delete_secret(args.path, args.mount)
            print(f"Secret deleted: {args.mount}/{args.path}")
            return 0

        if args.vault_command == "inject":
            count = inject_vault_secrets_into_env(args.prefix)
            print(f"Injected {count} secrets from Vault into environment")
            return 0

    except VaultError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"error: invalid JSON: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    return 0


def _run_slsa(args: argparse.Namespace) -> int:
    """Generate or verify SLSA Provenance."""
    from ishastra.slsa import generate_slsa_provenance, verify_slsa_provenance

    try:
        if args.verify:
            if verify_slsa_provenance(args.verify):
                print("Provenance verification PASSED")
                return 0
            print("Provenance verification FAILED", file=sys.stderr)
            return 1

        provenance_file = generate_slsa_provenance(
            output_dir=args.output,
            builder_id=args.builder_id,
            artifacts_dir=args.artifacts,
        )
        print(f"SLSA Provenance generated: {provenance_file}")
        return 0

    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def _run_dr(args: argparse.Namespace) -> int:
    """Manage disaster recovery and failover operations."""
    import sys

    from ishastra.dr import main as dr_main

    sys.argv = ["ishastra", "dr", args.dr_command]

    if args.dr_command == "init-config":
        sys.argv.extend(["-o", args.output])
    elif args.dr_command == "health":
        sys.argv.extend(["--config", args.config, "--state", args.state])
    elif args.dr_command == "failover":
        sys.argv.append(args.target_region)
        sys.argv.extend(["--reason", args.reason])
        if args.force:
            sys.argv.append("--force")
        sys.argv.extend(["--config", args.config, "--state", args.state])
    elif args.dr_command == "status":
        sys.argv.extend(["--state", args.state])
    elif args.dr_command == "chaos":
        sys.argv.extend(["--config", args.config, "--state", args.state])
    elif args.dr_command == "pitr":
        sys.argv.append(args.pitr_command)
        if args.pitr_command == "backup":
            sys.argv.extend(["--db-url", args.db_url, "--backup-dir", args.backup_dir])
        elif args.pitr_command == "list":
            sys.argv.extend(["--backup-dir", args.backup_dir])
        elif args.pitr_command == "restore":
            sys.argv.extend(
                [
                    "--target-time",
                    args.target_time,
                    "--target-dir",
                    args.target_dir,
                    "--db-url",
                    args.db_url,
                    "--backup-dir",
                    args.backup_dir,
                ]
            )
            if args.base_backup:
                sys.argv.extend(["--base-backup", args.base_backup])

    return dr_main()


def _run_standby_promote(args: argparse.Namespace) -> int:
    """Promote warm standby: verify backup, restore DB, take worker lease, run readiness checks."""
    import asyncio

    from ishastra.core.standby import StandbyError, promote_standby, verify_backup

    backup_dir = Path(args.backup_dir).expanduser().resolve()
    raw_db = args.db_path

    db_path: Path | str = (
        raw_db if raw_db.startswith(("postgresql://", "postgres://")) else Path(raw_db).expanduser().resolve()
    )
    scope_file = args.scope_file if args.scope_file else None

    if not backup_dir.exists() or not backup_dir.is_dir():
        print(f"error: backup directory not found: {backup_dir}", file=sys.stderr)
        return 3

    if args.dry_run:
        postgres_target = str(db_path).startswith(("postgresql://", "postgres://"))
        pattern = "ishastra-*.dump" if postgres_target else "ishastra-*.db"
        backup_files = sorted(backup_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
        if not backup_files:
            print(f"error: no backup files found in {backup_dir} (expected {pattern})", file=sys.stderr)
            return 3
        latest = backup_files[0]
        try:
            result = asyncio.run(verify_backup(latest))
            print("Backup verification OK:")
            print(f"  File: {result['path']}")
            print(f"  Backend: {result['backend']}")
            print(f"  Size: {result['size_bytes']} bytes")
            if result["backend"] == "sqlite":
                print(f"  Schema version: {result['schema_version']}")
                print(f"  Audit chain entries: {result['audit_chain_entries']}")
            print(f"  Tables: {', '.join(result['tables'])}")
            return 0
        except StandbyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 3

    try:
        result = asyncio.run(
            promote_standby(
                backup_dir=backup_dir,
                db_path=db_path,
                scope_file=scope_file,
                timeout=args.timeout,
            )
        )
    except StandbyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return 3

    print("Standby promotion successful")
    print(f"  Backup used: {result['backup_used']}")
    print(f"  Database restored to: {result['db_restored_to']}")
    print(f"  Worker lease: {result['lease_path']}")
    print(f"  RTO: {result['rto_ms']} ms")
    print("  Readiness checks:")
    for check, data in result["readiness"].items():
        status = "OK" if data.get("ok") else "FAIL"
        detail = ""
        if check == "scope":
            detail = f" (mode={data.get('mode')}, program={data.get('program')})"
        elif check == "api_keys":
            detail = f" (admin_keys={data.get('admin_count')})"
        elif check == "audit_chain":
            detail = f" (entries={data.get('audit_chain_entries', 0)})"
        print(f"    {check}: {status}{detail}")
    print("  Timings (ms):")
    for step, ms in result["timings_ms"].items():
        print(f"    {step}: {ms}")
    return 0


def _run_scope_keygen(args: argparse.Namespace) -> int:
    """Create an Ed25519 signing key and publish its public JWK."""
    from ishastra.core import scope_signing

    private_path = Path(args.key).expanduser().resolve()
    jwks_path = Path(args.jwks).expanduser().resolve()
    if private_path.exists() and not args.force:
        print(f"error: {private_path} already exists; pass --force to replace it", file=sys.stderr)
        return 1
    keys: list[dict] = []
    try:
        pem, jwk = scope_signing.generate_keypair(args.kid)
        if jwks_path.is_file() and not args.new_set:
            existing = json.loads(jwks_path.read_text())
            previous = existing.get("keys", []) if isinstance(existing, dict) else None
            if not isinstance(previous, list):
                raise ValueError(f"{jwks_path} is not a JWKS key set")
            keys = [entry for entry in previous if entry.get("kid") != jwk["kid"]]
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    keys.append(jwk)
    private_path.write_bytes(pem)
    private_path.chmod(0o600)
    jwks_path.write_text(json.dumps({"keys": keys}, indent=2) + "\n")
    print(f"private key: {private_path} (0600; it never belongs on the verifier host)")
    print(f"public key set: {jwks_path} ({len(keys)} key(s), kid={jwk['kid']})")
    print(f"  next: ishastra scope-sign --scope scope.json --key {private_path} --kid {jwk['kid']}")
    return 0


def _run_scope_key_rotate(args: argparse.Namespace) -> int:
    """Create a new signing key while keeping the published overlap set."""
    from ishastra.core import scope_signing

    try:
        jwk = scope_signing.rotate_keypair(
            args.kid,
            Path(args.key).expanduser().resolve(),
            Path(args.jwks).expanduser().resolve(),
        )
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"private key: {Path(args.key).expanduser()} (0600; retain in the signing system)")
    print(f"public key set: {Path(args.jwks).expanduser()} (new kid={jwk['kid']}; previous keys retained)")
    return 0


BREAK_GLASS_MAX = timedelta(hours=4)


def _parse_duration(text: str) -> timedelta:
    """'90m', '24h', '7d', '3600s' -> timedelta; a bare number means seconds."""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    raw = str(text).strip().lower()
    unit = units.get(raw[-1]) if raw else None
    if unit is None:
        if not raw.isdigit():
            raise ValueError(f"duration {text!r} must look like 90m, 24h or 7d")
        return timedelta(seconds=int(raw))
    number = raw[:-1]
    if not number.isdigit() or int(number) <= 0:
        raise ValueError(f"duration {text!r} must be a positive number followed by s/m/h/d")
    return timedelta(seconds=int(number) * unit)


def _stamp_expiry(document: dict[str, Any], ttl: str | None) -> dict[str, Any]:
    """Give a minted scope an expiry; an existing one is never replaced."""
    if ttl is None or document.get("expires_at"):
        return document
    stamp = (datetime.now(UTC) + _parse_duration(ttl)).isoformat(timespec="seconds")
    return {**document, "expires_at": stamp}


def _run_scope_sign(args: argparse.Namespace) -> int:
    """Sign a scope document so a verifier can prove who authorized it."""
    from ishastra.core import scope_signing

    path = Path(args.scope).expanduser().resolve()
    if not path.is_file():
        print(f"error: scope file not found: {path}", file=sys.stderr)
        return 1
    try:
        document = json.loads(path.read_text())
        if not isinstance(document, dict):
            raise ValueError("scope document must be a JSON object")
        ttl = None if getattr(args, "no_expiry", False) else args.expires_in
        if getattr(args, "break_glass", False):
            if ttl is None:
                print("error: --break-glass requires --expires-in", file=sys.stderr)
                return 2
            if _parse_duration(ttl) > BREAK_GLASS_MAX:
                print(
                    f"error: --break-glass is capped at {BREAK_GLASS_MAX}; "
                    "a longer window needs a normal authorization",
                    file=sys.stderr,
                )
                return 2
        document = _stamp_expiry(document, ttl)
        if getattr(args, "break_glass", False):
            metadata = dict(document.get("metadata") or {})
            document = {**document, "metadata": {**metadata, "break_glass": "true"}}
        key = scope_signing.load_private_key_file(Path(args.key).expanduser())
        signed = scope_signing.sign_document(document, key, args.kid)

        scope_signing.verify_document(signed, {args.kid: key.public_key()})
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    output = Path(args.output).expanduser().resolve() if args.output else path
    output.write_text(json.dumps(signed, indent=2) + "\n")
    print(f"signed {path.name} with kid={args.kid}: {output}")
    print(f"  expires_at: {document.get('expires_at') or 'never'}")
    print("  the document now loads only where ISHASTRA_SCOPE_JWKS publishes that key")
    return 0


def _run_scope_breakglass(args: argparse.Namespace) -> int:
    """Create a dual-approval emergency scope authorization (break-glass)."""
    from ishastra.core import scope_breakglass

    try:
        base_scope_path = Path(args.scope).expanduser().resolve()
        base_document = json.loads(base_scope_path.read_text()) if base_scope_path.is_file() else {}

        include_hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
        if not include_hosts:
            print("error: --hosts must contain at least one host", file=sys.stderr)
            return 2

        exclude_hosts = [h.strip() for h in args.exclude.split(",") if h.strip()] if args.exclude else []
        authorized_networks = (
            [n.strip() for n in args.networks.split(",") if n.strip()] if args.networks else []
        )
        allowed_ports = (
            [int(p.strip()) for p in args.ports.split(",") if p.strip()] if args.ports else [80, 443]
        )

        program = str(args.program or base_document.get("program") or "break-glass")
        authorized_by = str(args.authorized_by or base_document.get("authorized_by") or "break-glass")
        authorization_ref = str(args.ref or base_document.get("authorization_ref") or "break-glass")

        scope_document = {
            "program": program,
            "authorized_by": authorized_by,
            "authorization_ref": authorization_ref,
            "include": include_hosts,
            "exclude": exclude_hosts,
            "authorized_networks": authorized_networks,
            "allowed_ports": allowed_ports,
            "allow_broad_networks": False,
            "version": 2,
        }

        from ishastra.core.scope import Scope

        Scope(
            program=program,
            authorized_by=authorized_by,
            authorization_ref=authorization_ref,
            include=tuple(include_hosts),
            exclude=tuple(exclude_hosts),
            authorized_networks=tuple(authorized_networks),
            allowed_ports=tuple(allowed_ports),
            allow_broad_networks=False,
        )

        signed = scope_breakglass.create_break_glass_scope(
            scope_document=scope_document,
            approver1_key_path=args.approver1_key,
            approver1_kid=args.approver1_kid,
            approver2_key_path=args.approver2_key,
            approver2_kid=args.approver2_kid,
            jwks_path=args.jwks,
            tenant_id=args.tenant,
            reason=args.reason,
            duration=args.duration,
        )

        output_path = (
            Path(args.output).expanduser().resolve()
            if args.output
            else Path("scope-breakglass.json").resolve()
        )
        output_path.write_text(json.dumps(signed, indent=2) + "\n")

        print(f"break-glass scope written to {output_path}", file=sys.stderr)
        print(f"  tenant: {args.tenant}", file=sys.stderr)
        print(f"  approvers: {args.approver1_kid}, {args.approver2_kid}", file=sys.stderr)
        print(f"  expires_at: {signed.get('expires_at')}", file=sys.stderr)
        print(f"  reason: {args.reason}", file=sys.stderr)
        print(f"  scope_hash: {scope_breakglass._compute_scope_hash(signed)}", file=sys.stderr)

    except scope_breakglass.BreakGlassError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


def _run_create_api_key(args: argparse.Namespace) -> int:
    """Create a new API key for a tenant (bootstrap)."""
    import asyncio
    import secrets
    import time

    from ishastra.config import get_settings, reset_settings
    from ishastra.core import store
    from ishastra.core.store import close_database

    reset_settings()
    settings = get_settings()
    if not settings.db_path:
        print("error: ISHASTRA_DATABASE_URL or ISHASTRA_DB not configured", file=sys.stderr)
        return 2

    store.configure(settings.db_path)

    async def create_key():
        tenant_id = args.tenant
        raw_key = f"ishastra_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        now = time.time()
        expires_at = now + args.ttl_days * 86400.0 if args.ttl_days else None

        await store.save_api_key(
            tenant_id=tenant_id,
            key_hash=key_hash,
            tier=args.tier,
            admin=args.admin,
            active=True,
            created_at=now,
            expires_at=expires_at,
            last_used=None,
            rotated_at=now,
            ai_enabled=False,
            scope=args.scope,
            scope_type="tenant",
            project_id=None,
            allowed_projects=None,
            resource_filters=None,
            include_hosts=None,
        )
        await close_database()
        return raw_key

    try:
        raw_key = asyncio.run(create_key())
        print(f"API key created for tenant '{args.tenant}':")
        print(raw_key)
        print("\nSave this key — it will not be shown again.")
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _run_evidence_verify(args: argparse.Namespace) -> int:
    """Verify a signed evidence manifest offline. Returns exit code."""
    from ishastra.security.signing.service import verify_evidence_file

    try:
        ok, reason = verify_evidence_file(
            args.manifest,
            args.key,
            artifacts_dir=args.artifacts_dir or None,
        )
    except (OSError, ValueError) as exc:
        ok, reason = False, str(exc)

    if args.json:
        print(json.dumps({"valid": ok, "reason": reason}))
    elif ok:
        print(f"valid evidence: {args.manifest}")
    else:
        print(f"invalid evidence: {reason}", file=sys.stderr)
    return 0 if ok else 1


def _run_bundle(args: argparse.Namespace) -> int:
    """Create or verify a signed evidence bundle. Returns exit code."""
    import asyncio

    from ishastra.core import bundle as bundle_module
    from ishastra.core import scope_signing

    if args.verify:
        try:
            keys = scope_signing.load_jwks(args.jwks)
            manifest = bundle_module.verify_bundle(Path(args.verify).read_bytes(), keys)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        job_id = manifest.get("job_id") or "(none)"
        files = len(manifest["files"])
        print(f"valid bundle: job={job_id} files={files} signed_at={manifest.get('created_at')}")
        return 0

    if not args.job:
        print("error: --job is required unless --verify is used", file=sys.stderr)
        return 2

    scope_path = Path(args.scope).expanduser().resolve()
    try:
        scope_document = json.loads(scope_path.read_text())
    except OSError as exc:
        print(f"error: scope file cannot be read: {exc}", file=sys.stderr)
        return 3
    except json.JSONDecodeError as exc:
        print(f"error: scope file is not valid JSON: {exc.msg}", file=sys.stderr)
        return 3
    try:
        private_key = scope_signing.load_private_key_file(args.key)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    settings = get_settings()
    store.configure(settings.db_path)

    async def _collect() -> tuple[dict[str, Any] | None, list[Any], list[dict[str, Any]]]:
        await store.get_database()
        job = await store.get_job(args.job, tenant=args.tenant)
        findings = await store.get_findings(args.job, tenant=args.tenant)
        return job, findings, [row async for row in store.chain_rows()]

    try:
        job, findings, audit = asyncio.run(_collect())
    except Exception as exc:  # noqa: BLE001 - surfaced as a CLI error, not swallowed
        print(f"error: cannot read job {args.job}: {exc}", file=sys.stderr)
        return 4
    if job is None:
        print(f"error: job {args.job} not found", file=sys.stderr)
        return 4

    from collections import Counter

    from ishastra.core.findings import to_sarif
    from ishastra.report_html import render_html_report

    report = {
        "target": job.get("target", ""),
        "job_id": job.get("id", ""),
        "state": job.get("state", ""),
        "verdict": job.get("verdict", ""),
        "coverage": job.get("coverage") or {},
        "severity_counts": dict(Counter(f.severity for f in findings)),
        "findings": [f.to_dict() for f in findings],
        "program": scope_document.get("program", ""),
        "authorized_by": scope_document.get("authorized_by", ""),
        "authorization_ref": scope_document.get("authorization_ref", ""),
        "scope_include": scope_document.get("include", []),
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    data = bundle_module.build_bundle(
        job=job,
        audit=audit,
        scope_document=scope_document,
        private_key=private_key,
        kid=args.kid,
        sarif=to_sarif(findings),
        report_html=render_html_report(report),
    )
    out = Path(args.out or f"evidence-{args.job}.zip")
    out.write_bytes(data)
    print(f"wrote {out} ({len(data)} bytes, {len(audit)} audit entries)")
    return 0


def _run_scope_template(args: argparse.Namespace) -> int:
    """Generate scope.json template for Nepal sector."""
    from ishastra.core.evidence import get_scope_template, list_scope_templates

    if args.sector == "list":
        templates = list_scope_templates()
        print("Available Nepal sector templates:")
        for t in templates:
            print(f"  {t}")
        return 0

    template = get_scope_template(args.sector)
    if template is None:
        print(f"error: unknown sector '{args.sector}'", file=sys.stderr)
        return 3

    if args.domain:
        domain = args.domain.strip().lower().strip(".")
        base = next(
            (p[2:] for p in template["include"] if p.startswith("*.")),
            template["include"][0],
        )
        for key in ("include", "exclude"):
            template[key] = list(dict.fromkeys(p.replace(base, domain) for p in template[key]))

    output = json.dumps(template, indent=2)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(output)
        print(f"Scope template written to {output_path}", file=sys.stderr)
    else:
        print(output)

    return 0


def _run_scope_wizard(args: argparse.Namespace) -> int:
    """Interactive wizard to create a scope.json authorization document."""
    import ipaddress
    import re

    _MAX_HOST = 253
    _LABEL = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?")

    def _is_ip_literal(host: str) -> bool:
        try:
            ipaddress.ip_address(host.split("%")[0])
        except ValueError:
            return False
        return True

    def _validate_host(pattern: str) -> str:
        """Validate a host pattern, return error message or empty string if valid."""
        if not isinstance(pattern, str) or not pattern.strip():
            return "host entries must be non-empty strings"
        host = pattern.strip().lower().strip(".")
        if host.startswith("*."):
            host = host[2:]
        if not host:
            return f"host entry {pattern!r} has no name after the wildcard"
        if _is_ip_literal(host.split("%")[0]):
            return ""
        labels = host[:-1].split(".") if host.endswith(".") else host.split(".")
        if len(host) > _MAX_HOST or not all(_LABEL.fullmatch(label) for label in labels):
            return f"host entry {pattern!r} is not a valid DNS name (IDNs must be given as punycode)"
        return ""

    def _validate_cidr(cidr: str) -> str:
        """Validate a CIDR network, return error message or empty string if valid."""
        try:
            network = ipaddress.ip_network(cidr.strip(), strict=False)
        except (ValueError, TypeError) as exc:
            return f"'{cidr}' is not a valid CIDR network: {exc}"
        if network.version == 6 and network.network_address.ipv4_mapped is not None:
            return (
                f"'{cidr}' is an IPv4-mapped IPv6 network; authorize the IPv4 CIDR directly (e.g. 10.0.0.0/8)"
            )
        floor = 8
        if network.prefixlen < floor:
            return (
                f"'{cidr}' covers more than a /{floor} (it is /{network.prefixlen}); "
                "split the range or use --allow-broad-networks (not supported in wizard)"
            )
        return ""

    def _validate_port(port_str: str) -> str:
        """Validate a port number, return error message or empty string if valid."""
        try:
            port = int(port_str.strip())
        except ValueError:
            return f"'{port_str}' is not a valid integer"
        if not 1 <= port <= 65535:
            return f"port {port} must be between 1 and 65535"
        return ""

    def _validate_days(days_str: str) -> str:
        """Validate days, return error message or empty string if valid."""
        try:
            days = float(days_str.strip())
        except ValueError:
            return f"'{days_str}' is not a valid number"
        if days <= 0:
            return "days must be greater than 0"
        return ""

    def prompt_with_validation(prompt_text: str, validator, default: str = "") -> str:
        """Prompt user with validation, re-prompt on error."""
        while True:
            if default:
                user_input = input(f"{prompt_text} [{default}]: ").strip()
                if not user_input:
                    user_input = default
            else:
                user_input = input(f"{prompt_text}: ").strip()
            error = validator(user_input)
            if error:
                print(f"  ✗ {error}")
                continue
            return user_input

    def prompt_comma_separated(prompt_text: str, validator, default: str = "") -> list[str]:
        """Prompt for comma-separated values, validate each."""
        while True:
            if default:
                user_input = input(f"{prompt_text} [{default}]: ").strip()
                if not user_input:
                    user_input = default
            else:
                user_input = input(f"{prompt_text}: ").strip()
            if not user_input:
                return []
            items = [item.strip() for item in user_input.split(",") if item.strip()]
            errors = []
            for item in items:
                error = validator(item)
                if error:
                    errors.append(f"  ✗ {item}: {error}")
            if errors:
                print("\n".join(errors))
                continue
            return items

    print("\n=== Ishastra Scope Wizard ===")
    print("Create an authorization scope document (scope.json)\n")

    program = prompt_with_validation(
        "Program name", lambda x: "" if x.strip() else "program name is required"
    )
    authorized_by = prompt_with_validation(
        "Authorized by", lambda x: "" if x.strip() else "authorized_by is required"
    )
    authorization_ref = prompt_with_validation(
        "Authorization reference (contract, ticket, email)",
        lambda x: "" if x.strip() else "authorization_ref is required",
    )

    print("\n--- In-Scope Hosts ---")
    print("Enter hosts one per line or comma-separated (e.g., *.example.com, api.example.com)")
    print("Wildcards (*.domain.com) cover subdomains only, not the apex.")
    include_hosts = prompt_comma_separated("Include hosts", _validate_host)

    print("\n--- Out-of-Scope Hosts (optional) ---")
    exclude_hosts = prompt_comma_separated(
        "Exclude hosts (comma-separated, or press Enter to skip)", _validate_host
    )

    print("\n--- Authorized Networks (CIDR) ---")
    print("Enter internal networks that should be allowed (e.g., 10.0.0.0/8, 172.16.0.0/12)")
    print("Networks broader than /8 are rejected unless explicitly allowed.")
    authorized_networks = prompt_comma_separated("Authorized networks (CIDR)", _validate_cidr)

    print("\n--- Allowed Ports ---")
    print("Enter TCP/UDP ports to allow (e.g., 80, 443, 8443)")
    print("Leave empty to allow all ports on in-scope hosts.")
    allowed_ports_input = prompt_comma_separated("Allowed ports", _validate_port)
    allowed_ports = [int(p) for p in allowed_ports_input]

    print("\n--- Grant Validity ---")
    days_valid = float(prompt_with_validation("Days valid", _validate_days, "30"))

    output_path = prompt_with_validation(
        "Output file path",
        lambda x: "" if x.strip() else "output path is required",
        "scope.json",
    )

    scope_doc = {
        "program": program,
        "authorized_by": authorized_by,
        "authorization_ref": authorization_ref,
        "include": include_hosts,
        "exclude": exclude_hosts,
        "authorized_networks": authorized_networks,
        "allowed_ports": allowed_ports,
        "allow_broad_networks": False,
    }

    print("\n=== Summary ===")
    print(f"Program: {program}")
    print(f"Authorized by: {authorized_by}")
    print(f"Authorization ref: {authorization_ref}")
    print(f"Include hosts: {', '.join(include_hosts) if include_hosts else '(none)'}")
    print(f"Exclude hosts: {', '.join(exclude_hosts) if exclude_hosts else '(none)'}")
    print(f"Authorized networks: {', '.join(authorized_networks) if authorized_networks else '(none)'}")
    print(f"Allowed ports: {', '.join(str(p) for p in allowed_ports) if allowed_ports else '(all ports)'}")
    print(f"Days valid: {days_valid}")
    print(f"Output: {output_path}")

    confirm = input("\nWrite scope.json? [y/N]: ").strip().lower()
    if confirm not in ("y", "yes"):
        print("Cancelled.")
        return 0

    try:
        from ishastra.core.scope import Scope

        Scope(
            program=program,
            authorized_by=authorized_by,
            authorization_ref=authorization_ref,
            include=tuple(include_hosts),
            exclude=tuple(exclude_hosts),
            authorized_networks=tuple(authorized_networks),
            allowed_ports=tuple(allowed_ports),
            allow_broad_networks=False,
        )
    except ValueError as exc:
        print(f"error: validation failed: {exc}", file=sys.stderr)
        return 3

    try:
        output_file = Path(output_path).expanduser().resolve()
        output_file.write_text(json.dumps(scope_doc, indent=2))
        print(f"\n✓ Scope document written to {output_file}")
        print("\nYou can now run assessments with:")
        print(f"  ishastra assess --target https://example.com --scope {output_file}")
    except OSError as exc:
        print(f"error: cannot write {output_path}: {exc}", file=sys.stderr)
        return 3

    return 0


def _run_scope_import(args: argparse.Namespace) -> int:
    """Import scope from various formats (OpenAPI, HAR, etc.)."""
    import sys
    from pathlib import Path

    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        print(f"error: input file not found: {input_path}", file=sys.stderr)
        return 3

    content = input_path.read_text()
    scope_doc = None

    if args.format == "scope" or (args.format == "auto" and "scope" in input_path.name.lower()):
        scope_doc = _import_from_scope(content)
    elif args.format == "har" or (args.format == "auto" and input_path.suffix == ".har"):
        scope_doc = _import_from_har(content)
    elif args.format == "openapi" or (
        args.format == "auto" and input_path.suffix in (".json", ".yaml", ".yml")
    ):
        scope_doc = _import_from_openapi(content, input_path.suffix)
    else:
        msg = "error: unsupported format '{fmt}'. Use --format openapi|har|scope|auto"
        print(msg.format(fmt=args.format), file=sys.stderr)
        return 3

    if scope_doc is None:
        print("error: failed to extract scope from input", file=sys.stderr)
        return 3

    if args.domain:
        scope_doc = _substitute_domain(scope_doc, args.domain)

    if args.ports:
        scope_doc["allowed_ports"] = [int(p.strip()) for p in args.ports.split(",") if p.strip()]

    output = json.dumps(scope_doc, indent=2)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(output)
        print(f"Scope document written to {output_path}", file=sys.stderr)
    else:
        print(output)

    return 0


def _run_import(args: argparse.Namespace) -> int:
    """Import findings from ``import-<format>`` and output normalized SARIF."""
    from ishastra.core.findings import to_sarif
    from ishastra.core.imports import import_findings

    fmt = args.command.removeprefix("import-")
    try:
        findings = import_findings(args.file, fmt, args.engagement or "", args.job or "")
    except Exception as exc:
        print(f"error: failed to import {fmt}: {exc}", file=sys.stderr)
        return 3

    sarif_doc = to_sarif(findings, tool_version="ishastra-import")
    output = json.dumps(sarif_doc, indent=2)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(output)
        print(f"SARIF written to {output_path}", file=sys.stderr)
    else:
        print(output)

    return 0


def _import_from_openapi(content: str, suffix: str) -> dict | None:
    """Extract scope from OpenAPI spec."""
    try:
        import yaml

        spec = yaml.safe_load(content) if suffix in (".yaml", ".yml") else json.loads(content)

        servers = spec.get("servers", [{"url": ""}])
        hosts = set()
        for server in servers:
            url = server.get("url", "")
            if url:
                from urllib.parse import urlparse

                parsed = urlparse(url)
                if parsed.hostname:
                    hosts.add(parsed.hostname)

        paths = spec.get("paths", {})
        for _path, methods in paths.items():
            for _method, details in methods.items():
                if isinstance(details, dict) and details.get("servers"):
                    for server in details["servers"]:
                        url = server.get("url", "")
                        if url:
                            from urllib.parse import urlparse

                            parsed = urlparse(url)
                            if parsed.hostname:
                                hosts.add(parsed.hostname)

        if not hosts:
            return None

        return {
            "program": "Imported from OpenAPI",
            "authorized_by": "REPLACE: authorizing authority",
            "authorization_ref": "REPLACE: engagement reference",
            "include": sorted(hosts),
            "exclude": [],
            "authorized_networks": [],
            "allowed_ports": [443, 80],
            "allow_broad_networks": False,
        }
    except Exception:
        return None


def _import_from_har(content: str) -> dict | None:
    """Extract scope from HAR file."""
    try:
        har = json.loads(content)
        entries = har.get("log", {}).get("entries", [])
        hosts = set()
        for entry in entries:
            request = entry.get("request", {})
            url = request.get("url", "")
            if url:
                from urllib.parse import urlparse

                parsed = urlparse(url)
                if parsed.hostname:
                    hosts.add(parsed.hostname)

        if not hosts:
            return None

        return {
            "program": "Imported from HAR",
            "authorized_by": "REPLACE: authorizing authority",
            "authorization_ref": "REPLACE: engagement reference",
            "include": sorted(hosts),
            "exclude": [],
            "authorized_networks": [],
            "allowed_ports": [443, 80],
            "allow_broad_networks": False,
        }
    except Exception:
        return None


def _import_from_scope(content: str) -> dict | None:
    """Validate and return existing scope document."""
    try:
        doc = json.loads(content)
        required = ["program", "authorized_by", "authorization_ref", "include"]
        if not all(k in doc for k in required):
            return None
        return doc
    except Exception:
        return None


def _substitute_domain(scope_doc: dict, domain: str) -> dict:
    """Substitute domain in scope document."""
    import copy

    doc = copy.deepcopy(scope_doc)
    base = None
    for host in doc.get("include", []):
        if host.startswith("*."):
            base = host[2:]
            break
    if base:
        for key in ("include", "exclude"):
            doc[key] = [h.replace(base, domain) for h in doc.get(key, [])]
    return doc


def _run_report(args: argparse.Namespace) -> int:
    """Generate assessment report (HTML or PDF). Competitors charge for this; ishastra gives it free."""
    settings = get_settings()
    _configure_logging(settings)

    scope_path = Path(args.scope).expanduser().resolve()
    loaded_scope = scope_module.load(scope_path)
    if loaded_scope is None:
        print(f"error: scope file not found: {scope_path}", file=sys.stderr)
        return 3

    try:
        job = jobs_module.prepare(
            target=args.target,
            profile=args.profile,
            actor=args.actor,
            timeout=args.timeout,
            scope_snapshot=loaded_scope,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    jobs_module.execute(job)

    locale_code: LocaleCode = args.locale

    report = {
        "target": args.target,
        "job_id": job.id if hasattr(job, "id") else "unknown",
        "state": job.state.name if hasattr(job, "state") else "unknown",
        "verdict": job.verdict if hasattr(job, "verdict") else "unknown",
        "program": loaded_scope.program if loaded_scope else "unknown",
        "authorized_by": loaded_scope.authorized_by if loaded_scope else "unknown",
        "authorization_ref": loaded_scope.authorization_ref if loaded_scope else "unknown",
        "scope_include": loaded_scope.include if loaded_scope else [],
        "findings": [
            {
                "severity": f.severity if hasattr(f, "severity") else "info",
                "confidence": f.confidence if hasattr(f, "confidence") else "unknown",
                "title": f.title if hasattr(f, "title") else "untitled",
                "category": f.category if hasattr(f, "category") else "unknown",
                "cwe": f.cwe if hasattr(f, "cwe") else "no CWE",
                "asset": f.asset if hasattr(f, "asset") else "unknown",
                "location": f.location if hasattr(f, "location") else "unknown",
                "evidence": f.evidence if hasattr(f, "evidence") else "",
                "remediation": f.remediation if hasattr(f, "remediation") else "",
                "description": f.description if hasattr(f, "description") else "",
                "detector": f.detector if hasattr(f, "detector") else "unknown",
                "detector_version": f.detector_version if hasattr(f, "detector_version") else "",
            }
            for f in job.findings
        ],
        "coverage": job.coverage() if hasattr(job, "coverage") else {},
        "severity_counts": {},
        "integrity": {"chain_valid": True, "chain_hash": ""},
    }

    context = TemplateContext(
        locale_code=locale_code,
        client_name=args.client_name or (loaded_scope.program if loaded_scope else ""),
        client_name_nepali=args.client_name_nepali,
        organization_name=args.org_name or "Ishastra Security",
        organization_name_nepali=args.org_name_nepali,
        program_name=loaded_scope.program if loaded_scope else "",
        authorized_by=loaded_scope.authorized_by if loaded_scope else "",
        authorization_ref=loaded_scope.authorization_ref if loaded_scope else "",
        target=args.target,
    )

    if args.format == "pdf":
        try:
            pdf_bytes = render_pdf_report(
                report, output_path=args.output, locale_code=locale_code, context=context
            )
            if args.output:
                print(f"PDF report written to {args.output}", file=sys.stderr)
            else:
                import sys as _sys

                _sys.stdout.buffer.write(pdf_bytes)
            return 0
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            print("falling back to HTML", file=sys.stderr)

    from ishastra.report_html import render_html_report

    html_output = render_html_report(report, locale_code=locale_code, context=context)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(html_output)
        print(f"HTML report written to {output_path}", file=sys.stderr)
    else:
        print(html_output)

    return 0


def _run_init(args: argparse.Namespace) -> int:
    """Generate scope.json and GitHub Action workflow from repo analysis."""
    import json
    from pathlib import Path

    repo_path = Path(args.repository).expanduser().resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        print(f"error: repository not found: {repo_path}", file=sys.stderr)
        return 3

    print(f"Analyzing {repo_path}...")

    framework_hints = _detect_framework(repo_path)
    print(f"Detected: {framework_hints['framework']} ({framework_hints['language']})")

    routes = _extract_routes(repo_path, framework_hints["framework"])
    print(f"Found {len(routes)} candidate routes/endpoints")

    auth_info = _detect_auth_patterns(repo_path, framework_hints["framework"])
    print(f"Auth patterns: {auth_info['type'] or 'none detected'}")

    base_domain = _infer_base_domain(routes, args.domain)
    if base_domain:
        print(f"Inferred base domain: {base_domain}")
    elif args.domain:
        base_domain = args.domain
        print(f"Using provided domain: {base_domain}")
    else:
        print("warning: could not infer base domain; scope will use placeholder")

    if not args.authorized_by or not args.ref:
        print(
            "error: ishastra init requires --authorized-by and --ref; a scope document "
            "without an authorizer and a ticket reference authorizes nothing",
            file=sys.stderr,
        )
        return 2

    scope_doc = _build_scope_from_analysis(
        repo_path=repo_path,
        framework=framework_hints["framework"],
        language=framework_hints["language"],
        routes=routes,
        auth_info=auth_info,
        base_domain=base_domain,
        program=args.program or repo_path.name,
        authorized_by=args.authorized_by,
        authorization_ref=args.ref,
        allow_broad_networks=args.allow_broad_networks,
    )

    scope_output = Path(args.output).expanduser().resolve()
    scope_output.parent.mkdir(parents=True, exist_ok=True)
    scope_output.write_text(json.dumps(scope_doc, indent=2))
    print(f"\n✓ Scope document written to {scope_output}")

    if args.github_action:
        workflow_path = repo_path / ".github" / "workflows" / "ishastra-scan.yml"
        workflow_path.parent.mkdir(parents=True, exist_ok=True)
        workflow_content = _generate_github_action_workflow(
            scope_file=scope_output.name,
            profile=args.profile,
            target=args.target or f"https://{base_domain}" if base_domain else "https://example.com",
            upload_sarif=True,
        )
        workflow_path.write_text(workflow_content)
        print(f"✓ GitHub Action workflow written to {workflow_path}")

    print("\nNext steps:")
    print(f"  1. Review {scope_output} before using it")
    print(f"  2. Run an assessment: ishastra assess --target <URL> --scope {scope_output}")
    if args.github_action:
        print("  3. Push to GitHub — the workflow will run SARIF scans on PRs")
    return 0


def _detect_framework(repo_path: Path) -> dict[str, str]:
    """Detect primary framework and language from repository files."""
    framework = "unknown"
    language = "unknown"

    files = {f.name for f in repo_path.rglob("*") if f.is_file()}

    if "requirements.txt" in files or "pyproject.toml" in files or "setup.py" in files:
        language = "python"

        if any(f in files for f in ["manage.py", "celery.py", "asgi.py", "wsgi.py"]):
            framework = "django"
        elif "fastapi" in files or any(
            "fastapi" in f.read_text()[:2000] for f in repo_path.rglob("*.py") if f.stat().st_size < 50000
        ):
            framework = "fastapi"
        elif "flask" in files or any(
            "flask" in f.read_text()[:2000] for f in repo_path.rglob("*.py") if f.stat().st_size < 50000
        ):
            framework = "flask"
        else:
            framework = "python"

    elif "package.json" in files:
        language = "javascript"
        pkg = {}
        with contextlib.suppress(Exception):
            pkg = json.loads((repo_path / "package.json").read_text())
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        if "next" in deps:
            framework = "nextjs"
        elif "express" in deps:
            framework = "express"
        elif "nestjs" in deps or "@nestjs/core" in deps:
            framework = "nestjs"
        elif "fastify" in deps:
            framework = "fastify"
        elif "react" in deps and ("vite" in deps or "react-scripts" in deps):
            framework = "react"
        elif "vue" in deps:
            framework = "vue"
        else:
            framework = "node"

    elif "go.mod" in files:
        language = "go"
        framework = "go"

    elif "pom.xml" in files or "build.gradle" in files or "build.gradle.kts" in files:
        language = "java"
        framework = "spring" if "pom.xml" in files else "gradle"

    elif "Cargo.toml" in files:
        language = "rust"
        framework = "rust"

    elif "composer.json" in files:
        language = "php"
        composer_text = (repo_path / "composer.json").read_text()[:2000]
        framework = "laravel" if "laravel/framework" in composer_text else "php"

    return {"framework": framework, "language": language}


def _extract_routes(repo_path: Path, framework: str) -> list[dict[str, Any]]:
    """Extract routes/endpoints from source code based on framework."""
    routes: list[dict[str, Any]] = []

    if framework == "fastapi":
        routes.extend(_extract_fastapi_routes(repo_path))
    elif framework == "django":
        routes.extend(_extract_django_routes(repo_path))
    elif framework == "flask":
        routes.extend(_extract_flask_routes(repo_path))
    elif framework == "express":
        routes.extend(_extract_express_routes(repo_path))
    elif framework == "nestjs":
        routes.extend(_extract_nestjs_routes(repo_path))
    elif framework == "nextjs":
        routes.extend(_extract_nextjs_routes(repo_path))
    elif framework == "spring":
        routes.extend(_extract_spring_routes(repo_path))
    else:
        routes.extend(_extract_generic_routes(repo_path))

    return routes


def _extract_fastapi_routes(repo_path: Path) -> list[dict[str, Any]]:
    routes = []
    pattern = re.compile(
        r"@(?:app|router)\.(get|post|put|patch|delete|head|options)" r'\s*\(\s*["\']([^"\']+)["\']'
    )
    for py_file in repo_path.rglob("*.py"):
        try:
            content = py_file.read_text()
            for match in pattern.finditer(content):
                method, path = match.groups()
                routes.append(
                    {"method": method.upper(), "path": path, "file": str(py_file.relative_to(repo_path))}
                )
        except Exception:
            pass
    return routes


def _extract_django_routes(repo_path: Path) -> list[dict[str, Any]]:
    routes = []

    pattern = re.compile(r'path\s*\(\s*["\']([^"\']+)["\']')
    for py_file in repo_path.rglob("urls.py"):
        try:
            content = py_file.read_text()
            for match in pattern.finditer(content):
                path = match.group(1)
                routes.append(
                    {
                        "method": "*",
                        "path": "/" + path.lstrip("/"),
                        "file": str(py_file.relative_to(repo_path)),
                    }
                )
        except Exception:
            pass
    return routes


def _extract_flask_routes(repo_path: Path) -> list[dict[str, Any]]:
    routes = []
    pattern = re.compile(
        r'@(?:app|bp|blueprint)\.route\s*\(\s*["\']([^"\']+)["\']' r"(?:,\s*methods\s*=\s*\[([^\]]+)\])?"
    )
    for py_file in repo_path.rglob("*.py"):
        try:
            content = py_file.read_text()
            for match in pattern.finditer(content):
                path = match.group(1)
                methods = match.group(2) if match.group(2) else "GET"
                methods = [m.strip().strip("\"'") for m in methods.split(",")]
                for method in methods:
                    routes.append(
                        {"method": method.upper(), "path": path, "file": str(py_file.relative_to(repo_path))}
                    )
        except Exception:
            pass
    return routes


def _extract_express_routes(repo_path: Path) -> list[dict[str, Any]]:
    routes = []
    pattern = re.compile(r'\.(get|post|put|patch|delete|head|options|all)\s*\(\s*["\']([^"\']+)["\']')
    for js_file in repo_path.rglob("*.js"):
        if "node_modules" in str(js_file):
            continue
        try:
            content = js_file.read_text()
            for match in pattern.finditer(content):
                method, path = match.groups()
                routes.append(
                    {"method": method.upper(), "path": path, "file": str(js_file.relative_to(repo_path))}
                )
        except Exception:
            pass
    for ts_file in repo_path.rglob("*.ts"):
        if "node_modules" in str(ts_file):
            continue
        try:
            content = ts_file.read_text()
            for match in pattern.finditer(content):
                method, path = match.groups()
                routes.append(
                    {"method": method.upper(), "path": path, "file": str(ts_file.relative_to(repo_path))}
                )
        except Exception:
            pass
    return routes


def _extract_nestjs_routes(repo_path: Path) -> list[dict[str, Any]]:
    routes = []

    ctrl_pattern = re.compile(r'@Controller\s*\(\s*["\']([^"\']*)["\']')
    method_pattern = re.compile(r'@(Get|Post|Put|Patch|Delete|Head|Options|All)\s*\(\s*["\']([^"\']*)["\']')
    for ts_file in repo_path.rglob("*.ts"):
        if "node_modules" in str(ts_file):
            continue
        try:
            content = ts_file.read_text()
            ctrl_match = ctrl_pattern.search(content)
            base_path = ctrl_match.group(1) if ctrl_match else ""
            for match in method_pattern.finditer(content):
                method, path = match.groups()
                full_path = "/" + (base_path + "/" + path).strip("/")
                routes.append(
                    {"method": method.upper(), "path": full_path, "file": str(ts_file.relative_to(repo_path))}
                )
        except Exception:
            pass
    return routes


def _extract_nextjs_routes(repo_path: Path) -> list[dict[str, Any]]:
    routes = []

    for route_file in repo_path.rglob("app/**/route.ts"):
        if "node_modules" in str(route_file):
            continue
        try:
            rel = route_file.relative_to(repo_path)

            path_parts = list(rel.parts)
            if "app" in path_parts:
                idx = path_parts.index("app")
                api_parts = path_parts[idx + 1 : -1]
                route_path = "/" + "/".join(api_parts).replace("[", "{").replace("]", "}")

                content = route_file.read_text()
                methods = []
                for m in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]:
                    if f"export async function {m}" in content or f"export const {m}" in content:
                        methods.append(m)
                if not methods:
                    methods = ["*"]
                for method in methods:
                    routes.append({"method": method, "path": route_path, "file": str(rel)})
        except Exception:
            pass
    return routes


def _extract_spring_routes(repo_path: Path) -> list[dict[str, Any]]:
    routes = []

    ctrl_pattern = re.compile(r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']')
    method_pattern = re.compile(
        r'@(Get|Post|Put|Patch|Delete|Head|Options)Mapping\s*\(\s*["\']([^"\']*)["\']'
    )
    for java_file in repo_path.rglob("*.java"):
        try:
            content = java_file.read_text()
            ctrl_match = ctrl_pattern.search(content)
            base_path = ctrl_match.group(1) if ctrl_match else ""
            for match in method_pattern.finditer(content):
                method, path = match.groups()
                full_path = "/" + (base_path + "/" + path).strip("/")
                routes.append(
                    {
                        "method": method.upper(),
                        "path": full_path,
                        "file": str(java_file.relative_to(repo_path)),
                    }
                )
        except Exception:
            pass
    return routes


def _extract_generic_routes(repo_path: Path) -> list[dict[str, Any]]:
    """Fallback: look for common URL patterns in source files."""
    routes = []

    patterns = [
        (re.compile(r'["\'](/api/[^"\']+)["\']'), "*"),
        (re.compile(r'["\'](/v\d+/[^"\']+)["\']'), "*"),
        (re.compile(r'["\'](/auth/[^"\']+)["\']'), "*"),
    ]
    allowed_suffixes = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs"}
    excluded_dirs = {"node_modules", ".venv", "venv", "__pycache__", "target", "build", "dist"}
    for source_file in repo_path.rglob("*"):
        if source_file.is_file() and source_file.suffix in allowed_suffixes:
            if any(ex in str(source_file) for ex in excluded_dirs):
                continue
            try:
                content = source_file.read_text()
                for pattern, method in patterns:
                    for match in pattern.finditer(content):
                        routes.append(
                            {
                                "method": method,
                                "path": match.group(1),
                                "file": str(source_file.relative_to(repo_path)),
                            }
                        )
            except Exception:
                pass
    return routes


def _detect_auth_patterns(repo_path: Path, framework: str) -> dict[str, Any]:
    """Detect authentication patterns in the codebase."""
    auth_info: dict[str, Any] = {"type": None, "details": {}}

    jwt_patterns = [
        r"jwt",
        r"JSONWebToken",
        r"Bearer\s+token",
        r"Authorization\s*:\s*Bearer",
    ]

    session_patterns = [
        r"session",
        r"cookie",
        r"express-session",
        r"django\.contrib\.sessions",
        r"flask\.session",
    ]

    api_key_patterns = [
        r"api[_-]?key",
        r"X-API-Key",
        r"api_key",
    ]

    oauth_patterns = [
        r"oauth",
        r"oidc",
        r"openid",
        r"Keycloak",
        r"Auth0",
        r"Okta",
    ]

    text_content = ""
    allowed_suffixes = {
        ".py",
        ".js",
        ".ts",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".cs",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
    }
    excluded_dirs = {"node_modules", ".venv", "venv", "__pycache__", "target", "build", "dist", ".git"}
    for source_file in repo_path.rglob("*"):
        if source_file.is_file() and source_file.suffix in allowed_suffixes:
            if any(ex in str(source_file) for ex in excluded_dirs):
                continue
            try:
                if source_file.stat().st_size < 100000:
                    text_content += source_file.read_text() + "\n"
            except Exception:
                pass

    text_lower = text_content.lower()

    if any(re.search(p, text_lower) for p in jwt_patterns):
        auth_info["type"] = "token"
        auth_info["details"]["jwt"] = True
    elif any(re.search(p, text_lower) for p in session_patterns):
        auth_info["type"] = "session"
        auth_info["details"]["session"] = True
    elif any(re.search(p, text_lower) for p in api_key_patterns):
        auth_info["type"] = "token"
        auth_info["details"]["api_key"] = True
    elif any(re.search(p, text_lower) for p in oauth_patterns):
        auth_info["type"] = "oauth"
        auth_info["details"]["oauth"] = True

    return auth_info


def _infer_base_domain(routes: list[dict[str, Any]], provided_domain: str | None) -> str | None:
    """Infer base domain from route paths."""
    if provided_domain:
        return provided_domain

    hosts = set()
    for route in routes:
        path = route.get("path", "")

        if path.startswith(("http://", "https://")):
            try:
                from urllib.parse import urlparse

                parsed = urlparse(path)
                if parsed.netloc:
                    hosts.add(parsed.netloc)
            except Exception:
                pass

    if hosts:
        return list(hosts)[0]

    return None


def _build_scope_from_analysis(
    *,
    repo_path: Path,
    framework: str,
    language: str,
    routes: list[dict[str, Any]],
    auth_info: dict[str, Any],
    base_domain: str | None,
    program: str,
    authorized_by: str,
    authorization_ref: str,
    allow_broad_networks: bool,
) -> dict[str, Any]:
    """Build a scope.json document from repository analysis."""
    include_hosts: list[str] = []
    exclude_hosts: list[str] = []

    if base_domain:
        include_hosts.append(f"*.{base_domain}")
        include_hosts.append(base_domain)

    if base_domain:
        common_subs = ["api", "app", "admin", "staging", "dev", "test"]
        for sub in common_subs:
            include_hosts.append(f"{sub}.{base_domain}")

    unique_paths = sorted({r["path"] for r in routes if r["path"].startswith("/")})

    return {
        "program": program,
        "authorized_by": authorized_by,
        "authorization_ref": authorization_ref,
        "include": include_hosts,
        "exclude": exclude_hosts,
        "authorized_networks": [],
        "allowed_ports": [80, 443],
        "allow_broad_networks": allow_broad_networks,
        "_meta": {
            "generated_by": "ishastra init",
            "framework": framework,
            "language": language,
            "detected_routes": len(routes),
            "unique_paths": unique_paths[:50],
            "auth_type": auth_info.get("type"),
            "note": "Review and customize before use. Fill in authorized_by and authorization_ref.",
        },
    }


def _generate_github_action_workflow(
    *,
    scope_file: str,
    profile: str,
    target: str,
    upload_sarif: bool,
) -> str:
    """Generate GitHub Action workflow YAML for Ishastra SARIF scans."""
    return f"""# Ishastra Security Assessment — GitHub Action
name: Ishastra Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday 2 AM UTC

permissions:
  contents: read
  security-events: write  # Required for SARIF upload

jobs:
  ishastra-scan:
    name: Ishastra Assessment
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Ishastra
        run: |
          pip install -U pip
          pip install "ishastra @ git+https://github.com/hacker-194/IshAstra"

      - name: Install optional scanners
        run: |
          pip install semgrep || true
          pip install bandit || true
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
            | sh -s -- -b /usr/local/bin || true

      - name: Run Ishastra assessment
        id: ishastra
        run: |
          ishastra assess \\
            --target "{target}" \\
            --scope "{scope_file}" \\
            --profile "{profile}" \\
            --output ishastra-results.sarif \\
            --actor "github-actions"
        env:

      - name: Upload SARIF to GitHub Code Scanning
        if: {str(upload_sarif).lower()}
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ishastra-results.sarif
          category: ishastra

      - name: Run local code scan (SAST/SCA)
        run: |
          ishastra-code-scan . --sarif --output ishastra-code-scan.sarif || true
        continue-on-error: true

      - name: Upload code scan SARIF
        if: {str(upload_sarif).lower()}
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ishastra-code-scan.sarif
          category: ishastra-code-scan
"""


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="ishastra", description="Ishastra security assessment platform")
    parser.add_argument("--version", action="version", version=f"ishastra {__version__}")

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    parser.add_argument(
        "--reset-audit-chain",
        action="store_true",
        help="Clear the sealed audit chain before starting. Use only for a deliberate recovery.",
    )
    subparsers = parser.add_subparsers(dest="command")

    server_parser = subparsers.add_parser("serve", help="Run the API server")
    server_parser.add_argument("--host", default="127.0.0.1")
    server_parser.add_argument("--port", type=int, default=8000)
    server_parser.add_argument("--reload", action="store_true")
    server_parser.add_argument(
        "--reset-audit-chain",
        action="store_true",
        help="Clear the sealed audit chain before starting. Use only for a deliberate recovery.",
    )

    demo_parser = subparsers.add_parser(
        "demo", help="Run a self-contained instance with a generated key and signed localhost scope"
    )
    demo_parser.add_argument("--host", default="127.0.0.1")
    demo_parser.add_argument("--port", type=int, default=8000)
    demo_parser.add_argument(
        "--data-dir",
        default=".ishastra-demo",
        help="Where the demo database, scope and keys are written (default: ./.ishastra-demo)",
    )

    bundle_parser = subparsers.add_parser(
        "bundle", help="Create or verify a signed, hash-pinned evidence bundle"
    )
    bundle_parser.add_argument("--job", default="", help="Assessment job id to bundle")
    bundle_parser.add_argument("--tenant", default=None, help="Tenant that owns the job")
    bundle_parser.add_argument("--scope", default="scope.json", help="Scope document as loaded")
    bundle_parser.add_argument("--key", default="scope-signing-key.pem", help="Ed25519 private key (PEM)")
    bundle_parser.add_argument("--kid", default="default", help="Key id recorded in the bundle")
    bundle_parser.add_argument("-o", "--out", help="Output zip (default: evidence-<job>.zip)")
    bundle_parser.add_argument("--verify", default="", help="Verify this bundle instead of creating one")
    bundle_parser.add_argument("--jwks", default="jwks.json", help="JWKS used with --verify")

    evidence_verify_parser = subparsers.add_parser(
        "evidence-verify", help="Verify a signed evidence manifest offline"
    )
    evidence_verify_parser.add_argument("manifest", help="Path to the signed evidence JSON")
    evidence_verify_parser.add_argument(
        "--key", required=True, help="Trusted Ed25519 public key file"
    )
    evidence_verify_parser.add_argument(
        "--artifacts-dir", default="", help="Re-hash artifacts from this directory"
    )
    evidence_verify_parser.add_argument("--json", action="store_true")

    assess_parser = subparsers.add_parser("assess", help="Assessment commands")
    assess_subparsers = assess_parser.add_subparsers(dest="assess_command", required=True)

    # assess run (existing synchronous behavior)
    run_parser = assess_subparsers.add_parser("run", help="Run a single assessment and output SARIF")
    run_parser.add_argument("--target", required=True, help="Target URL (e.g. https://app.example.com/)")
    run_parser.add_argument(
        "--profile",
        default="web",
        choices=["web", "web-deep", "api", "api-deep", "network"],
        help="Assessment profile (default: web)",
    )
    run_parser.add_argument(
        "--scope",
        default="scope.json",
        help="Path to scope.json authorization document (default: scope.json)",
    )
    run_parser.add_argument(
        "--output",
        "-o",
        help="Output SARIF file (default: stdout)",
    )
    run_parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="Overall job deadline in seconds (default: 300)",
    )
    run_parser.add_argument(
        "--actor",
        default="analyst",
        help="Actor name for audit trail (default: analyst)",
    )

    run_parser.add_argument(
        "--auth-type",
        choices=["token", "session", "form_login", "multi_step"],
        help="Authentication type for authenticated scanning",
    )
    run_parser.add_argument(
        "--auth-config",
        help="Path to JSON file with authentication configuration (alternative to individual flags)",
    )

    run_parser.add_argument(
        "--auth-bearer",
        help="Bearer token for Authorization header",
    )
    run_parser.add_argument(
        "--auth-api-key",
        help="API key value",
    )
    run_parser.add_argument(
        "--auth-api-key-header",
        default="X-API-Key",
        help="Header name for API key (default: X-API-Key)",
    )
    run_parser.add_argument(
        "--auth-header",
        action="append",
        default=[],
        help="Custom header as 'Name:Value' (repeatable)",
    )

    run_parser.add_argument(
        "--auth-cookie",
        action="append",
        default=[],
        help="Session cookie as 'name=value' (repeatable)",
    )

    run_parser.add_argument(
        "--auth-login-url",
        help="Login form URL",
    )
    run_parser.add_argument(
        "--auth-username",
        help="Username for form login",
    )
    run_parser.add_argument(
        "--auth-password",
        help="Password for form login",
    )
    run_parser.add_argument(
        "--auth-username-field",
        default="username",
        help="Username field name (default: username)",
    )
    run_parser.add_argument(
        "--auth-password-field",
        default="password",
        help="Password field name (default: password)",
    )
    run_parser.add_argument(
        "--auth-csrf-field",
        help="CSRF token field name",
    )
    run_parser.add_argument(
        "--auth-extra-field",
        action="append",
        default=[],
        help="Extra form field as 'name=value' (repeatable)",
    )
    run_parser.add_argument(
        "--grant",
        default="",
        help="Signed grant (Ishastra Proof) authorizing and receipting this run",
    )
    run_parser.add_argument(
        "--scope-file",
        default="",
        help="Import scope from OpenAPI spec, HAR file, or scope.json (auto-detected)",
    )
    run_parser.add_argument(
        "--scope-format",
        choices=["auto", "openapi", "har", "scope"],
        default="auto",
        help="Scope import format (default: auto-detect from file extension)",
    )
    run_parser.add_argument(
        "--scope-domain",
        default="",
        help="Substitute domain in imported scope (e.g., example.com)",
    )
    run_parser.add_argument(
        "--scope-ports",
        default="",
        help="Override allowed ports in imported scope (comma-separated, e.g., 80,443,8443)",
    )
    run_parser.add_argument("--proof-out", default="", help="Write a proof pack for this run")
    run_parser.add_argument(
        "--proof-ledger",
        default="",
        help="Append receipts to this JSONL ledger (default: in memory)",
    )
    run_parser.add_argument(
        "--gate-key",
        default="",
        help="Gate signing key file for receipts (created if absent)",
    )
    run_parser.add_argument(
        "--trusted-issuer",
        default="",
        help="Require the grant to be signed by this public key (or key file)",
    )

    # assess submit - queue an assessment asynchronously
    submit_parser = assess_subparsers.add_parser("submit", help="Submit an assessment to the queue (async)")
    submit_parser.add_argument("--target", required=True, help="Target URL (e.g. https://app.example.com/)")
    submit_parser.add_argument(
        "--profile",
        default="web",
        choices=["web", "web-deep", "api", "api-deep", "network"],
        help="Assessment profile (default: web)",
    )
    submit_parser.add_argument(
        "--scope-file",
        default="",
        help="Import scope from OpenAPI spec, HAR file, or scope.json (auto-detected)",
    )
    submit_parser.add_argument(
        "--scope-format",
        choices=["auto", "openapi", "har", "scope"],
        default="auto",
        help="Scope import format (default: auto-detect from file extension)",
    )
    submit_parser.add_argument(
        "--scope-domain",
        default="",
        help="Substitute domain in imported scope (e.g., example.com)",
    )
    submit_parser.add_argument(
        "--scope-ports",
        default="",
        help="Override allowed ports in imported scope (comma-separated, e.g., 80,443,8443)",
    )
    submit_parser.add_argument(
        "--actor",
        default="analyst",
        help="Actor name for audit trail (default: analyst)",
    )
    submit_parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="Overall job deadline in seconds (default: 300)",
    )
    submit_parser.add_argument(
        "--auth-type",
        choices=["token", "session", "form_login", "multi_step"],
        help="Authentication type for authenticated scanning",
    )
    submit_parser.add_argument(
        "--auth-config",
        help="Path to JSON file with authentication configuration",
    )
    submit_parser.add_argument(
        "--auth-bearer",
        help="Bearer token for Authorization header",
    )
    submit_parser.add_argument(
        "--auth-api-key",
        help="API key value",
    )
    submit_parser.add_argument(
        "--auth-api-key-header",
        default="X-API-Key",
        help="Header name for API key (default: X-API-Key)",
    )
    submit_parser.add_argument(
        "--auth-header",
        action="append",
        default=[],
        help="Custom header as 'Name:Value' (repeatable)",
    )
    submit_parser.add_argument(
        "--auth-cookie",
        action="append",
        default=[],
        help="Session cookie as 'name=value' (repeatable)",
    )
    submit_parser.add_argument(
        "--auth-login-url",
        help="Login form URL",
    )
    submit_parser.add_argument(
        "--auth-username",
        help="Username for form login",
    )
    submit_parser.add_argument(
        "--auth-password",
        help="Password for form login",
    )
    submit_parser.add_argument(
        "--auth-username-field",
        default="username",
        help="Username field name (default: username)",
    )
    submit_parser.add_argument(
        "--auth-password-field",
        default="password",
        help="Password field name (default: password)",
    )
    submit_parser.add_argument(
        "--auth-csrf-field",
        help="CSRF token field name",
    )
    submit_parser.add_argument(
        "--auth-extra-field",
        action="append",
        default=[],
        help="Extra form field as 'name=value' (repeatable)",
    )
    submit_parser.add_argument(
        "--grant",
        default="",
        help="Signed grant (Ishastra Proof) authorizing and receipting this run",
    )
    submit_parser.add_argument(
        "--proof-out",
        default="",
        help="Write a proof pack for this run when complete",
    )
    submit_parser.add_argument(
        "--proof-ledger",
        default="",
        help="Append receipts to this JSONL ledger (default: in memory)",
    )
    submit_parser.add_argument(
        "--gate-key",
        default="",
        help="Gate signing key file for receipts (created if absent)",
    )
    submit_parser.add_argument(
        "--trusted-issuer",
        default="",
        help="Require the grant to be signed by this public key (or key file)",
    )

    # assess status - check job status
    status_parser = assess_subparsers.add_parser("status", help="Check status of a submitted assessment job")
    status_parser.add_argument("--job-id", required=True, help="Job ID to check")
    status_parser.add_argument("--tenant", default="", help="Tenant ID (optional, for admin)")

    # assess list - list assessment jobs
    list_parser = assess_subparsers.add_parser("list", help="List assessment jobs for a tenant")
    list_parser.add_argument("--tenant", required=True, help="Tenant ID to list jobs for")
    list_parser.add_argument("--limit", type=int, default=20, help="Maximum number of jobs to return (default: 20)")
    list_parser.add_argument("--offset", type=int, default=0, help="Offset for pagination (default: 0)")

    evidence_parser = subparsers.add_parser(
        "evidence", help="Generate compliance evidence pack (NRB, NTA, NCSP)"
    )
    evidence_parser.add_argument("--target", required=True, help="Target URL (e.g. https://app.example.com/)")
    evidence_parser.add_argument(
        "--scope",
        default="scope.json",
        help="Path to scope.json authorization document (default: scope.json)",
    )
    evidence_parser.add_argument(
        "--scope-file",
        default="",
        help="Import scope from OpenAPI spec, HAR file, or scope.json (auto-detected)",
    )
    evidence_parser.add_argument(
        "--scope-format",
        choices=["auto", "openapi", "har", "scope"],
        default="auto",
        help="Scope import format (default: auto-detect from file extension)",
    )
    evidence_parser.add_argument(
        "--scope-domain",
        default="",
        help="Substitute domain in imported scope (e.g., example.com)",
    )
    evidence_parser.add_argument(
        "--scope-ports",
        default="",
        help="Override allowed ports in imported scope (comma-separated, e.g., 80,443,8443)",
    )
    evidence_parser.add_argument(
        "--framework",
        choices=["nrb", "nta", "ncsp", "all"],
        default="all",
        help="Regulatory framework (default: all)",
    )
    evidence_parser.add_argument(
        "--format",
        choices=["pdf", "oscal", "sarif", "csv", "json"],
        default="json",
        help="Output format (default: json; pdf generates real PDF via WeasyPrint)",
    )
    evidence_parser.add_argument(
        "--output",
        "-o",
        help="Output file (default: stdout)",
    )
    evidence_parser.add_argument(
        "--profile",
        default="web-deep",
        choices=["web", "web-deep", "api", "api-deep", "network"],
        help="Assessment profile (default: web-deep for compliance)",
    )
    evidence_parser.add_argument(
        "--timeout",
        type=float,
        default=600.0,
        help="Overall job deadline in seconds (default: 600 for deep scans)",
    )
    evidence_parser.add_argument(
        "--actor",
        default="compliance-analyst",
        help="Actor name for audit trail (default: compliance-analyst)",
    )
    evidence_parser.add_argument(
        "--include-passing",
        action="store_true",
        help="Include passing controls in output (default: only gaps/findings)",
    )
    evidence_parser.add_argument(
        "--locale",
        choices=["en_US", "ne_NP"],
        default="en_US",
        help="Report locale/language (default: en_US)",
    )
    evidence_parser.add_argument(
        "--client-name",
        default="",
        help="Client name (used in report header)",
    )
    evidence_parser.add_argument(
        "--client-name-nepali",
        default="",
        help="Client name in Nepali (Devanagari)",
    )
    evidence_parser.add_argument(
        "--org-name",
        default="",
        help="Organization name (used in report header)",
    )
    evidence_parser.add_argument(
        "--org-name-nepali",
        default="",
        help="Organization name in Nepali (Devanagari)",
    )

    worker_parser = subparsers.add_parser(
        "worker", help="Run a dedicated Redis Streams queue worker (for horizontal scaling)"
    )
    worker_parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Number of concurrent assessments per worker (default: 1)",
    )
    worker_parser.add_argument(
        "--queue-max",
        type=int,
        default=1000,
        help="Maximum queued jobs (default: 1000)",
    )
    worker_subparsers = worker_parser.add_subparsers(dest="worker_command", required=False)

    gateway_parser = worker_subparsers.add_parser("gateway", help="Run the egress gateway (CONNECT proxy) for worker network")
    gateway_parser.add_argument("--listen-host", default="0.0.0.0", help="Listen address (default: 0.0.0.0)")
    gateway_parser.add_argument("--listen-port", type=int, default=8080, help="Listen port (default: 8080)")
    gateway_parser.set_defaults(func=_run_gateway)

    scope_tpl_parser = subparsers.add_parser(
        "scope-template", help="Generate scope.json template for Nepal sector"
    )
    scope_tpl_parser.add_argument(
        "sector",
        choices=["bank", "telco", "gov", "global", "list"],
        help="Sector template (bank=NRB, telco=NTA, gov=NCSP, list=show all)",
    )
    scope_tpl_parser.add_argument(
        "--output",
        "-o",
        help="Output file (default: stdout)",
    )
    scope_tpl_parser.add_argument(
        "--domain",
        help="Base domain to substitute (e.g. mybank.com)",
    )

    scope_wizard_parser = subparsers.add_parser(
        "scope-wizard", help="Interactively create a scope.json authorization document"
    )
    scope_wizard_parser.add_argument(
        "--output",
        "-o",
        default="scope.json",
        help="Output file path (default: scope.json)",
    )

    scope_import_parser = subparsers.add_parser(
        "scope-import", help="Import scope from OpenAPI spec, HAR file, or scope.json"
    )
    scope_import_parser.add_argument(
        "input",
        help="Input file path (OpenAPI .json/.yaml, HAR .har, or scope.json)",
    )
    scope_import_parser.add_argument(
        "--format",
        choices=["auto", "openapi", "har", "scope"],
        default="auto",
        help="Input format (default: auto-detect from file extension)",
    )
    scope_import_parser.add_argument(
        "--output",
        "-o",
        help="Output file path (default: stdout)",
    )
    scope_import_parser.add_argument(
        "--domain",
        help="Substitute base domain in imported scope (e.g., example.com)",
    )
    scope_import_parser.add_argument(
        "--ports",
        help="Override allowed ports (comma-separated, e.g., 80,443,8443)",
    )

    import_sarif_parser = subparsers.add_parser(
        "import-sarif", help="Import findings from SARIF file and output as SARIF"
    )
    import_sarif_parser.add_argument("file", help="Path to SARIF file")
    import_sarif_parser.add_argument("--engagement", help="Engagement reference")
    import_sarif_parser.add_argument("--job", help="Job ID")
    import_sarif_parser.add_argument("--output", "-o", help="Output SARIF file (default: stdout)")

    import_nuclei_parser = subparsers.add_parser(
        "import-nuclei", help="Import findings from Nuclei JSONL output and output as SARIF"
    )
    import_nuclei_parser.add_argument("file", help="Path to Nuclei JSONL file")
    import_nuclei_parser.add_argument("--engagement", help="Engagement reference")
    import_nuclei_parser.add_argument("--job", help="Job ID")
    import_nuclei_parser.add_argument("--output", "-o", help="Output SARIF file (default: stdout)")

    import_zap_parser = subparsers.add_parser(
        "import-zap", help="Import findings from ZAP JSON report and output as SARIF"
    )
    import_zap_parser.add_argument("file", help="Path to ZAP JSON file")
    import_zap_parser.add_argument("--engagement", help="Engagement reference")
    import_zap_parser.add_argument("--job", help="Job ID")
    import_zap_parser.add_argument("--output", "-o", help="Output SARIF file (default: stdout)")

    scope_keygen_parser = subparsers.add_parser(
        "scope-keygen", help="Create an Ed25519 scope signing key and publish its public JWK"
    )
    scope_keygen_parser.add_argument("--kid", required=True, help="Key id published in the JWKS")
    scope_keygen_parser.add_argument(
        "--key", default="scope-signing-key.pem", help="Private key output path (written 0600)"
    )
    scope_keygen_parser.add_argument("--jwks", default="scope-jwks.json", help="Public key set output path")
    scope_keygen_parser.add_argument(
        "--force", action="store_true", help="Replace an existing private key file"
    )
    scope_keygen_parser.add_argument(
        "--new-set", action="store_true", help="Replace the key set instead of adding this key to it"
    )

    scope_key_rotate_parser = subparsers.add_parser(
        "scope-key-rotate", help="Create a new signing key and retain existing JWKS keys"
    )
    scope_key_rotate_parser.add_argument("--kid", required=True, help="Unique key id for the new key")
    scope_key_rotate_parser.add_argument(
        "--key", required=True, help="New private key output path (written 0600)"
    )
    scope_key_rotate_parser.add_argument(
        "--jwks", default="scope-jwks.json", help="Existing public key set to extend"
    )

    scope_sign_parser = subparsers.add_parser("scope-sign", help="Sign a scope document with an Ed25519 key")
    scope_sign_parser.add_argument(
        "--scope", default="scope.json", help="Scope document to sign (default: scope.json)"
    )
    scope_sign_parser.add_argument("--key", required=True, help="Private key PEM path")
    scope_sign_parser.add_argument("--kid", required=True, help="Key id matching the JWKS entry")
    scope_sign_parser.add_argument("--output", "-o", help="Output path (default: sign in place)")
    scope_sign_parser.add_argument(
        "--expires-in",
        default="24h",
        help="Lifetime bound for a minted scope (90m, 24h, 7d); an existing expires_at is kept",
    )
    scope_sign_parser.add_argument("--no-expiry", action="store_true", help="Mint without an expiry bound")
    scope_sign_parser.add_argument(
        "--break-glass",
        action="store_true",
        help="Emergency issuance: requires --expires-in and caps it at 4h",
    )

    breakglass_parser = subparsers.add_parser(
        "scope-breakglass", help="Create a dual-approval emergency scope authorization (break-glass)"
    )
    breakglass_parser.add_argument(
        "--scope", default="scope.json", help="Base scope document to authorize (default: scope.json)"
    )
    breakglass_parser.add_argument("--tenant", required=True, help="Tenant identifier for audit trail")
    breakglass_parser.add_argument(
        "--hosts",
        required=True,
        help="Comma-separated list of in-scope hosts (e.g., '*.example.com,api.example.com')",
    )
    breakglass_parser.add_argument(
        "--duration",
        default="4h",
        help="Duration (max 4h): 90m, 2h, 4h (default: 4h)",
    )
    breakglass_parser.add_argument(
        "--approver1-key", required=True, help="First approver private key PEM path"
    )
    breakglass_parser.add_argument(
        "--approver1-kid", required=True, help="First approver key ID (must exist in JWKS)"
    )
    breakglass_parser.add_argument(
        "--approver2-key", required=True, help="Second approver private key PEM path"
    )
    breakglass_parser.add_argument(
        "--approver2-kid", required=True, help="Second approver key ID (must exist in JWKS)"
    )
    breakglass_parser.add_argument(
        "--jwks", required=True, help="JWKS file containing both approver public keys"
    )
    breakglass_parser.add_argument("--reason", required=True, help="Reason for break-glass activation")
    breakglass_parser.add_argument("--output", "-o", help="Output path (default: scope-breakglass.json)")
    breakglass_parser.add_argument(
        "--program", help="Program name (default: from base scope or 'break-glass')"
    )
    breakglass_parser.add_argument(
        "--authorized-by", help="Authorized by (default: from base scope or 'break-glass')"
    )
    breakglass_parser.add_argument(
        "--ref", help="Authorization reference (default: from base scope or 'break-glass')"
    )
    breakglass_parser.add_argument("--exclude", default="", help="Comma-separated out-of-scope hosts")
    breakglass_parser.add_argument("--networks", default="", help="Comma-separated authorized CIDR networks")
    breakglass_parser.add_argument(
        "--ports", default="80,443", help="Comma-separated allowed ports (default: 80,443)"
    )

    create_api_key_parser = subparsers.add_parser(
        "create-api-key", help="Create a new API key for a tenant (bootstrap)"
    )
    create_api_key_parser.add_argument("--tenant", default="default", help="Tenant ID (default: default)")
    create_api_key_parser.add_argument(
        "--tier",
        default="enterprise",
        choices=["free", "pro", "enterprise"],
        help="Key tier (default: enterprise)",
    )
    create_api_key_parser.add_argument("--admin", action="store_true", help="Grant admin privileges")
    create_api_key_parser.add_argument("--ttl-days", type=int, help="Key TTL in days (default: no expiry)")
    create_api_key_parser.add_argument(
        "--scope", default="write", choices=["read", "write"], help="Key scope (default: write)"
    )

    init_parser = subparsers.add_parser(
        "init", help="Generate scope.json and GitHub Action workflow from repository analysis"
    )
    init_parser.add_argument(
        "repository",
        nargs="?",
        default=".",
        help="Repository path to analyze (default: current directory)",
    )
    init_parser.add_argument(
        "--output",
        "-o",
        default="scope.json",
        help="Output scope.json path (default: scope.json)",
    )
    init_parser.add_argument(
        "--domain",
        help="Base domain for scope (e.g., example.com). Inferred from routes if not provided.",
    )
    init_parser.add_argument(
        "--program",
        help="Program name for scope (default: repository name)",
    )
    init_parser.add_argument(
        "--authorized-by",
        help="Authorized by (required in scope.json)",
    )
    init_parser.add_argument(
        "--ref",
        help="Authorization reference (contract, ticket, email)",
    )
    init_parser.add_argument(
        "--profile",
        default="web",
        choices=["web", "web-deep", "web-full", "api", "api-deep", "api-full", "network", "ports"],
        help="Assessment profile for generated workflow (default: web)",
    )
    init_parser.add_argument(
        "--target",
        help="Target URL for generated workflow (default: inferred from domain)",
    )
    init_parser.add_argument(
        "--github-action",
        action="store_true",
        help="Generate .github/workflows/ishastra-scan.yml workflow file",
    )
    init_parser.add_argument(
        "--allow-broad-networks",
        action="store_true",
        help="Allow broad networks (e.g., /8) in scope",
    )

    report_parser = subparsers.add_parser("report", help="Generate assessment report (HTML or PDF)")
    report_parser.add_argument("--target", required=True, help="Target URL (e.g. https://app.example.com/)")
    report_parser.add_argument(
        "--scope",
        default="scope.json",
        help="Path to scope.json authorization document (default: scope.json)",
    )
    report_parser.add_argument(
        "--profile",
        default="web",
        choices=["web", "web-deep", "api", "api-deep", "network"],
        help="Assessment profile (default: web)",
    )
    report_parser.add_argument(
        "--format",
        choices=["html", "pdf"],
        default="html",
        help="Output format (default: html)",
    )
    report_parser.add_argument(
        "--output",
        "-o",
        help="Output file (default: stdout)",
    )
    report_parser.add_argument(
        "--title",
        default="Ishastra assessment report",
        help="Report title (default: 'Ishastra assessment report')",
    )
    report_parser.add_argument(
        "--logo",
        default="",
        help="Logo filename in static/ (default: none)",
    )
    report_parser.add_argument(
        "--locale",
        choices=["en_US", "ne_NP"],
        default="en_US",
        help="Report locale/language (default: en_US)",
    )
    report_parser.add_argument(
        "--client-name",
        default="",
        help="Client name (used in report header)",
    )
    report_parser.add_argument(
        "--client-name-nepali",
        default="",
        help="Client name in Nepali (Devanagari)",
    )
    report_parser.add_argument(
        "--org-name",
        default="",
        help="Organization name (used in report header)",
    )
    report_parser.add_argument(
        "--org-name-nepali",
        default="",
        help="Organization name in Nepali (Devanagari)",
    )
    report_parser.add_argument(
        "--actor",
        default="analyst",
        help="Actor name for audit trail",
    )
    report_parser.add_argument(
        "--timeout",
        default=300,
        type=int,
        help="Overall job deadline in seconds (default: 300)",
    )

    grant_parser = subparsers.add_parser(
        "grant", help="Create and sign an authorization grant (Ishastra Proof)"
    )
    grant_parser.add_argument("--program", required=True, help="Program name")
    grant_parser.add_argument("--authorized-by", required=True, help="Who authorizes the testing")
    grant_parser.add_argument(
        "--ref", required=True, help="Authorization reference (contract, ticket, email)"
    )
    grant_parser.add_argument(
        "--include",
        action="append",
        required=True,
        help="In-scope host or *.domain (repeatable)",
    )
    grant_parser.add_argument("--exclude", action="append", default=[])
    grant_parser.add_argument("--network", action="append", default=[], help="Authorized CIDR (repeatable)")
    grant_parser.add_argument("--port", action="append", type=int, default=[])
    grant_parser.add_argument("--days", type=float, default=30.0, help="Validity in days (default: 30)")
    grant_parser.add_argument("--id", default="", help="Explicit grant id")
    grant_parser.add_argument("--key", help="Existing issuer private key (default: generate one)")
    grant_parser.add_argument("--key-out", default="issuer.key")
    grant_parser.add_argument("--allow-broad-networks", action="store_true")
    grant_parser.add_argument("--out", "-o", default="grant.json")

    gate_parser = subparsers.add_parser(
        "gate", help="Serve the authorization gate that receipts every decision"
    )
    gate_parser.add_argument("--grant", default="grant.json")
    gate_parser.add_argument("--host", default="127.0.0.1")
    gate_parser.add_argument("--port", type=int, default=8787)
    gate_parser.add_argument("--actor", default="agent")
    gate_parser.add_argument("--ledger", default="proof-ledger.jsonl")
    gate_parser.add_argument("--gate-key", default="gate.key", help="Gate signing key (created if absent)")
    gate_parser.add_argument("--trusted-issuer", default="", help="Pinned issuer public key or key file")
    gate_parser.add_argument(
        "--token",
        default=os.environ.get("ISHASTRA_PROOF_TOKEN", ""),
        help="Bearer token required on every request (env: ISHASTRA_PROOF_TOKEN)",
    )

    proof_parser = subparsers.add_parser(
        "proof", help="Bundle a grant and its receipt ledger into a proof pack"
    )
    proof_parser.add_argument("--grant", default="grant.json")
    proof_parser.add_argument("--ledger", default="proof-ledger.jsonl")
    proof_parser.add_argument("--gate-key", default="", help="Require this gate public key (or key file)")
    proof_parser.add_argument("--out", "-o", default="proof.json")

    verify_parser = subparsers.add_parser("verify", help="Verify a proof pack offline")
    verify_parser.add_argument("proof", help="Path to the proof pack JSON")
    verify_parser.add_argument("--issuer-key", default="", help="Pin the issuer public key or key file")
    verify_parser.add_argument("--gate-key", default="", help="Pin the gate public key or key file")
    verify_parser.add_argument("--json", action="store_true")

    vault_parser = subparsers.add_parser("vault", help="Manage secrets in HashiCorp Vault")
    vault_subparsers = vault_parser.add_subparsers(dest="vault_command", required=True)

    vault_read_parser = vault_subparsers.add_parser("read", help="Read a secret from Vault")
    vault_read_parser.add_argument("path", help="Secret path (e.g., ishastra)")
    vault_read_parser.add_argument("--mount", default="secret", help="Mount point (default: secret)")
    vault_read_parser.add_argument("--version", type=int, help="Secret version")
    vault_read_parser.add_argument("--json", action="store_true", help="Output as JSON")

    vault_write_parser = vault_subparsers.add_parser("write", help="Write a secret to Vault")
    vault_write_parser.add_argument("path", help="Secret path (e.g., ishastra)")
    vault_write_parser.add_argument("--mount", default="secret", help="Mount point (default: secret)")
    vault_write_parser.add_argument("--data", required=True, help="JSON data to write")
    vault_write_parser.add_argument("--file", help="Read JSON data from file")

    vault_list_parser = vault_subparsers.add_parser("list", help="List secrets at a path")
    vault_list_parser.add_argument("path", help="Secret path (e.g., ishastra)")
    vault_list_parser.add_argument("--mount", default="secret", help="Mount point (default: secret)")

    vault_delete_parser = vault_subparsers.add_parser("delete", help="Delete a secret")
    vault_delete_parser.add_argument("path", help="Secret path (e.g., ishastra)")
    vault_delete_parser.add_argument("--mount", default="secret", help="Mount point (default: secret)")

    vault_inject_parser = vault_subparsers.add_parser(
        "inject", help="Load secrets from Vault into environment variables"
    )
    vault_inject_parser.add_argument(
        "--prefix", default="ishastra", help="Secret path prefix (default: ishastra)"
    )

    slsa_parser = subparsers.add_parser(
        "slsa", help="Generate SLSA Provenance attestation for supply chain security"
    )
    slsa_parser.add_argument(
        "-o",
        "--output",
        default="./provenance",
        help="Output directory for provenance file (default: ./provenance)",
    )
    slsa_parser.add_argument(
        "-b",
        "--builder-id",
        help="Builder identity URI (default: from ISHASTRA_SLSA_BUILDER_ID env)",
    )
    slsa_parser.add_argument(
        "-a",
        "--artifacts",
        help="Directory containing build artifacts to include",
    )
    slsa_parser.add_argument(
        "--verify",
        help="Verify a provenance file instead of generating",
    )

    dr_parser = subparsers.add_parser("dr", help="Disaster Recovery and failover management")
    dr_subparsers = dr_parser.add_subparsers(dest="dr_command", required=True)

    dr_init_parser = dr_subparsers.add_parser("init-config", help="Create example DR config")
    dr_init_parser.add_argument("-o", "--output", default="/etc/ishastra/dr_config.json")

    dr_health_parser = dr_subparsers.add_parser("health", help="Check all regions health")
    dr_health_parser.add_argument("--config", default="/etc/ishastra/dr_config.json")
    dr_health_parser.add_argument("--state", default="/var/lib/ishastra/dr_state.json")

    dr_failover_parser = dr_subparsers.add_parser("failover", help="Initiate manual failover")
    dr_failover_parser.add_argument("target_region", help="Target region name")
    dr_failover_parser.add_argument("--reason", default="manual")
    dr_failover_parser.add_argument("--force", action="store_true")
    dr_failover_parser.add_argument("--config", default="/etc/ishastra/dr_config.json")
    dr_failover_parser.add_argument("--state", default="/var/lib/ishastra/dr_state.json")

    dr_status_parser = dr_subparsers.add_parser("status", help="Show DR status")
    dr_status_parser.add_argument("--state", default="/var/lib/ishastra/dr_state.json")

    dr_chaos_parser = dr_subparsers.add_parser("chaos", help="Run chaos engineering tests")
    dr_chaos_parser.add_argument("--config", default="/etc/ishastra/dr_config.json")
    dr_chaos_parser.add_argument("--state", default="/var/lib/ishastra/dr_state.json")

    dr_pitr_parser = dr_subparsers.add_parser("pitr", help="Point-in-Time Recovery operations")
    dr_pitr_subparsers = dr_pitr_parser.add_subparsers(dest="pitr_command", required=True)

    dr_pitr_backup = dr_pitr_subparsers.add_parser("backup", help="Create base backup")
    dr_pitr_backup.add_argument("--db-url", required=True)
    dr_pitr_backup.add_argument("--backup-dir", default="/var/lib/ishastra/pitr")

    dr_pitr_list = dr_pitr_subparsers.add_parser("list", help="List backups")
    dr_pitr_list.add_argument("--backup-dir", default="/var/lib/ishastra/pitr")

    dr_pitr_restore = dr_pitr_subparsers.add_parser("restore", help="Restore to point in time")
    dr_pitr_restore.add_argument("--target-time", required=True, help="ISO format timestamp")
    dr_pitr_restore.add_argument("--target-dir", required=True)
    dr_pitr_restore.add_argument("--base-backup", help="Specific base backup to use")
    dr_pitr_restore.add_argument("--db-url", required=True)
    dr_pitr_restore.add_argument("--backup-dir", default="/var/lib/ishastra/pitr")

    standby_parser = subparsers.add_parser(
        "standby-promote", help="Promote warm standby: verify backup, restore DB, take lease, run readiness"
    )
    standby_parser.add_argument(
        "--backup-dir", required=True, help="Directory containing ishastra-*.db backup files"
    )
    standby_parser.add_argument(
        "--db-path",
        required=True,
        help="Target database path to restore to (e.g., /var/lib/ishastra/ishastra.db)",
    )
    standby_parser.add_argument(
        "--scope-file", default="", help="Scope file path (overrides ISHASTRA_SCOPE_FILE)"
    )
    standby_parser.add_argument(
        "--timeout", type=float, default=30.0, help="Readiness check timeout in seconds (default: 30)"
    )
    standby_parser.add_argument(
        "--dry-run", action="store_true", help="Verify backup only, do not restore or promote"
    )

    backup_parser = subparsers.add_parser(
        "backup", help="Write one verified database backup (SQLite snapshot or pg_dump archive)"
    )
    backup_parser.add_argument(
        "--out", "-o", default="backups", help="Directory to write the backup into (default: ./backups)"
    )
    backup_parser.add_argument(
        "--db",
        default="",
        help=(
            "Database file or PostgreSQL DSN "
            "(default: ISHASTRA_DATABASE_URL, ISHASTRA_DB, then ./ishastra.db)"
        ),
    )
    backup_parser.add_argument("--verify", default="", help="Verify this backup file instead of creating one")

    args = parser.parse_args(argv)

    if args.command is None:
        args.command = "serve"

    if args.command == "serve":
        _run_server(args)
    elif args.command == "demo":
        _run_demo(args)
    elif args.command == "backup":
        sys.exit(_run_backup(args))
    elif args.command == "assess":
        assess_cmd = getattr(args, "assess_command", "run")
        if assess_cmd == "run":
            sys.exit(_run_assess(args))
        elif assess_cmd == "submit":
            sys.exit(_run_assess_submit(args))
        elif assess_cmd == "status":
            sys.exit(_run_assess_status(args))
        elif assess_cmd == "list":
            sys.exit(_run_assess_list(args))
        else:
            parser.error(f"unknown assess command: {assess_cmd}")
    elif args.command == "evidence":
        sys.exit(_run_evidence(args))
    elif args.command == "evidence-verify":
        sys.exit(_run_evidence_verify(args))
    elif args.command == "bundle":
        sys.exit(_run_bundle(args))
    elif args.command == "scope-template":
        sys.exit(_run_scope_template(args))
    elif args.command == "scope-wizard":
        sys.exit(_run_scope_wizard(args))
    elif args.command == "scope-import":
        sys.exit(_run_scope_import(args))
    elif args.command in ("import-sarif", "import-nuclei", "import-zap"):
        sys.exit(_run_import(args))
    elif args.command == "scope-keygen":
        sys.exit(_run_scope_keygen(args))
    elif args.command == "scope-key-rotate":
        sys.exit(_run_scope_key_rotate(args))
    elif args.command == "scope-sign":
        sys.exit(_run_scope_sign(args))
    elif args.command == "scope-breakglass":
        sys.exit(_run_scope_breakglass(args))
    elif args.command == "create-api-key":
        sys.exit(_run_create_api_key(args))
    elif args.command == "init":
        sys.exit(_run_init(args))
    elif args.command == "report":
        sys.exit(_run_report(args))
    elif args.command == "grant":
        sys.exit(_run_grant(args))
    elif args.command == "gate":
        sys.exit(_run_gate(args))
    elif args.command == "proof":
        sys.exit(_run_proof(args))
    elif args.command == "verify":
        sys.exit(_run_verify(args))
    elif args.command == "standby-promote":
        sys.exit(_run_standby_promote(args))
    elif args.command == "worker":
        if getattr(args, "worker_command", None) == "gateway":
            sys.exit(_run_gateway(args))
        sys.exit(_run_worker(args))
    elif args.command == "vault":
        sys.exit(_run_vault(args))
    elif args.command == "slsa":
        sys.exit(_run_slsa(args))
    elif args.command == "dr":
        sys.exit(_run_dr(args))
    else:
        parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()

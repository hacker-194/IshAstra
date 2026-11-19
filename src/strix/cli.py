"""Command-line entry points: ``strix`` (server) and ``strix assess`` (CLI scan)."""

from __future__ import annotations

import argparse
import contextlib
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

from strix import __version__, proof
from strix.config import Settings, get_settings
from strix.core import jobs as jobs_module
from strix.core import scope as scope_module
from strix.core import store
from strix.core.findings import to_sarif
from strix.locale import LocaleCode, TemplateContext
from strix.report_pdf import render_pdf_report


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
    # If --auth-config file is provided, load it
    if args.auth_config:
        import json

        config_path = Path(args.auth_config).expanduser().resolve()
        try:
            with open(config_path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"failed to load auth config from {config_path}: {exc}") from exc

    # Otherwise build from individual flags
    auth_type = args.auth_type
    if not auth_type:
        # Check if any auth-related flags were provided
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
        # Default to token if bearer/api_key, session if cookies, form_login if login_url
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
    # API versioning: all routes prefixed with /api/v1
    # FastAPI app in strix.api.app already supports this via route prefix
    uvicorn.run(
        "strix.api.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        proxy_headers=False,
        timeout_graceful_shutdown=30,
    )


def _run_assess(args: argparse.Namespace) -> int:
    """Run a single assessment and output SARIF. Returns exit code."""
    settings = get_settings()
    _configure_logging(settings)

    # Build auth config from CLI args
    auth_config = _build_auth_config(args)

    # Prepare job policy with encrypted auth config if provided
    job_policy = {}
    if auth_config is not None:
        if not settings.encryption_key:
            print("error: STRIX_ENCRYPTION_KEY not configured (required for auth)", file=sys.stderr)
            return 3
        try:
            from strix.core.auth import EncryptedAuthConfig, create_authenticator_from_dict

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

    # A signed grant replaces the scope document (and receipts every decision).
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
    else:
        scope_path = Path(args.scope).expanduser().resolve()
        loaded_scope = scope_module.load(scope_path)
        if loaded_scope is None:
            print(f"error: scope file not found: {scope_path}", file=sys.stderr)
            return 3

    # Prepare job
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

    # Execute job synchronously, recording each gate decision when a grant
    # authorizes the run.
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

    # Output SARIF
    sarif_doc = to_sarif(job.findings, tool_version=job.policy.get("tool_version", "strix"))
    output = json.dumps(sarif_doc, indent=2)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(output)
        print(f"SARIF written to {output_path}", file=sys.stderr)
    else:
        print(output)

    # Exit codes: 0=clean, 1=findings, 2=scope violation, 3=error
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


def _run_evidence(args: argparse.Namespace) -> int:
    """Run compliance assessment and generate evidence pack. Returns exit code."""
    settings = get_settings()
    _configure_logging(settings)

    # Resolve locale
    from strix.locale import TemplateContext

    locale_code: LocaleCode = args.locale

    # Load scope
    scope_path = Path(args.scope).expanduser().resolve()
    loaded_scope = scope_module.load(scope_path)
    if loaded_scope is None:
        print(f"error: scope file not found: {scope_path}", file=sys.stderr)
        return 3

    # Prepare and execute job
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

    # Load policy mappings for selected framework(s)
    from strix.core import evidence as evidence_module

    frameworks = ["nrb", "nta", "ncsp"] if args.framework == "all" else [args.framework]
    mappings = evidence_module.load_mappings(frameworks)

    # Generate evidence pack
    pack = evidence_module.build_evidence_pack(
        job=job,
        mappings=mappings,
        include_passing=args.include_passing,
    )

    # Create template context with localized names
    context = TemplateContext(
        locale_code=locale_code,
        client_name=args.client_name or (loaded_scope.program if loaded_scope else ""),
        client_name_nepali=args.client_name_nepali,
        organization_name=args.org_name or "Strix Security",
        organization_name_nepali=args.org_name_nepali,
        program_name=loaded_scope.program if loaded_scope else "",
        authorized_by=loaded_scope.authorized_by if loaded_scope else "",
        authorization_ref=loaded_scope.authorization_ref if loaded_scope else "",
        target=args.target,
    )

    # Format output
    if args.format == "sarif":
        sarif_doc = to_sarif(job.findings, tool_version="strix-evidence")
        output = json.dumps(sarif_doc, indent=2)
    elif args.format == "csv":
        output = evidence_module.to_csv(pack)
    elif args.format == "oscal":
        output = evidence_module.to_oscal(pack)
    elif args.format == "pdf":
        # Build report dict compatible with report_html
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
            "coverage": job.coverage if hasattr(job, "coverage") else {},
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

    # Exit: 0=clean (no gaps), 1=gaps found, 2=scope violation, 3=error
    if job.state is jobs_module.JobState.FAILED:
        if job.error and "out_of_scope" in job.error:
            return 2
        print(f"assessment failed: {job.error}", file=sys.stderr)
        return 3
    if job.state is jobs_module.JobState.CANCELLED:
        print("assessment cancelled", file=sys.stderr)
        return 3

    # Check if any controls have gaps (failures)
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


def _run_standby_promote(args: argparse.Namespace) -> int:
    """Promote warm standby: verify backup, restore DB, take worker lease, run readiness checks."""
    import asyncio

    from strix.core.standby import StandbyError, promote_standby, verify_backup

    backup_dir = Path(args.backup_dir).expanduser().resolve()
    db_path = Path(args.db_path).expanduser().resolve()
    scope_file = args.scope_file if args.scope_file else None

    if not backup_dir.exists() or not backup_dir.is_dir():
        print(f"error: backup directory not found: {backup_dir}", file=sys.stderr)
        return 3

    if args.dry_run:
        # Just verify the latest backup
        backup_files = sorted(backup_dir.glob("strix-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not backup_files:
            print(f"error: no backup files found in {backup_dir} (expected strix-*.db)", file=sys.stderr)
            return 3
        latest = backup_files[0]
        try:
            result = asyncio.run(verify_backup(latest))
            print("Backup verification OK:")
            print(f"  File: {result['path']}")
            print(f"  Size: {result['size_bytes']} bytes")
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

    # Output results
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
    from strix.core import scope_signing

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
    print(f"  next: strix scope-sign --scope scope.json --key {private_path} --kid {jwk['kid']}")
    return 0


def _run_scope_key_rotate(args: argparse.Namespace) -> int:
    """Create a new signing key while keeping the published overlap set."""
    from strix.core import scope_signing

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


# Emergency issuance is bounded by the tool, not by the operator's judgement.
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
    from strix.core import scope_signing

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
        # Round-trip immediately: a signature nobody can verify is worse than none.
        scope_signing.verify_document(signed, {args.kid: key.public_key()})
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    output = Path(args.output).expanduser().resolve() if args.output else path
    output.write_text(json.dumps(signed, indent=2) + "\n")
    print(f"signed {path.name} with kid={args.kid}: {output}")
    print(f"  expires_at: {document.get('expires_at') or 'never'}")
    print("  the document now loads only where STRIX_SCOPE_JWKS publishes that key")
    return 0


def _run_scope_breakglass(args: argparse.Namespace) -> int:
    """Create a dual-approval emergency scope authorization (break-glass)."""
    from strix.core import scope_breakglass

    try:
        # Load base scope document if it exists
        base_scope_path = Path(args.scope).expanduser().resolve()
        base_document = json.loads(base_scope_path.read_text()) if base_scope_path.is_file() else {}

        # Parse hosts
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

        # Coerce the argparse strings once: the base document is untrusted
        # JSON, so a non-string field must not reach Scope as-is.
        program = str(args.program or base_document.get("program") or "break-glass")
        authorized_by = str(args.authorized_by or base_document.get("authorized_by") or "break-glass")
        authorization_ref = str(args.ref or base_document.get("authorization_ref") or "break-glass")

        # Build scope document
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

        # Validate the scope document structure
        from strix.core.scope import Scope

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

        # Create break-glass scope
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

        # Write output
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


def _run_scope_template(args: argparse.Namespace) -> int:
    """Generate scope.json template for Nepal sector."""
    from strix.core.evidence import get_scope_template, list_scope_templates

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

    # Substitute the placeholder base domain, preserving subdomains and
    # de-duplicating patterns (the old code mapped every wildcard to the new
    # domain, which could emit the same entry several times).
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
        floor = 8  # /8 minimum prefix length
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

    print("\n=== Strix Scope Wizard ===")
    print("Create an authorization scope document (scope.json)\n")

    # Required fields
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

    # Include hosts
    print("\n--- In-Scope Hosts ---")
    print("Enter hosts one per line or comma-separated (e.g., *.example.com, api.example.com)")
    print("Wildcards (*.domain.com) cover subdomains only, not the apex.")
    include_hosts = prompt_comma_separated("Include hosts", _validate_host)

    # Exclude hosts
    print("\n--- Out-of-Scope Hosts (optional) ---")
    exclude_hosts = prompt_comma_separated(
        "Exclude hosts (comma-separated, or press Enter to skip)", _validate_host
    )

    # Authorized networks
    print("\n--- Authorized Networks (CIDR) ---")
    print("Enter internal networks that should be allowed (e.g., 10.0.0.0/8, 172.16.0.0/12)")
    print("Networks broader than /8 are rejected unless explicitly allowed.")
    authorized_networks = prompt_comma_separated("Authorized networks (CIDR)", _validate_cidr)

    # Allowed ports
    print("\n--- Allowed Ports ---")
    print("Enter TCP/UDP ports to allow (e.g., 80, 443, 8443)")
    print("Leave empty to allow all ports on in-scope hosts.")
    allowed_ports_input = prompt_comma_separated("Allowed ports", _validate_port)
    allowed_ports = [int(p) for p in allowed_ports_input]

    # Days valid
    print("\n--- Grant Validity ---")
    days_valid = float(prompt_with_validation("Days valid", _validate_days, "30"))

    # Output path
    output_path = prompt_with_validation(
        "Output file path",
        lambda x: "" if x.strip() else "output path is required",
        "scope.json",
    )

    # Build scope document
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

    # Show summary
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

    # Validate by creating a Scope object (uses the same validation as scope.py)
    try:
        from strix.core.scope import Scope

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

    # Write file
    try:
        output_file = Path(output_path).expanduser().resolve()
        output_file.write_text(json.dumps(scope_doc, indent=2))
        print(f"\n✓ Scope document written to {output_file}")
        print("\nYou can now run assessments with:")
        print(f"  strix assess --target https://example.com --scope {output_file}")
    except OSError as exc:
        print(f"error: cannot write {output_path}: {exc}", file=sys.stderr)
        return 3

    return 0


def _run_report(args: argparse.Namespace) -> int:
    """Generate assessment report (HTML or PDF). Competitors charge for this; strix gives it free."""
    settings = get_settings()
    _configure_logging(settings)

    # Load scope
    scope_path = Path(args.scope).expanduser().resolve()
    loaded_scope = scope_module.load(scope_path)
    if loaded_scope is None:
        print(f"error: scope file not found: {scope_path}", file=sys.stderr)
        return 3

    # Prepare and execute job
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

    # Resolve locale
    locale_code: LocaleCode = args.locale

    # Build the report dict compatible with report_html
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
        "coverage": job.coverage if hasattr(job, "coverage") else {},
        "severity_counts": {},
        "integrity": {"chain_valid": True, "chain_hash": ""},
    }

    # Create template context with localized names
    context = TemplateContext(
        locale_code=locale_code,
        client_name=args.client_name or (loaded_scope.program if loaded_scope else ""),
        client_name_nepali=args.client_name_nepali,
        organization_name=args.org_name or "Strix Security",
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
            # fall through to HTML output

    # Render HTML using the existing report_html module
    from strix.report_html import render_html_report

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

    # --- Framework / language detection ---
    framework_hints = _detect_framework(repo_path)
    print(f"Detected: {framework_hints['framework']} ({framework_hints['language']})")

    # --- Route / endpoint extraction ---
    routes = _extract_routes(repo_path, framework_hints["framework"])
    print(f"Found {len(routes)} candidate routes/endpoints")

    # --- Auth pattern detection ---
    auth_info = _detect_auth_patterns(repo_path, framework_hints["framework"])
    print(f"Auth patterns: {auth_info['type'] or 'none detected'}")

    # --- Base domain inference ---
    base_domain = _infer_base_domain(routes, args.domain)
    if base_domain:
        print(f"Inferred base domain: {base_domain}")
    elif args.domain:
        base_domain = args.domain
        print(f"Using provided domain: {base_domain}")
    else:
        print("warning: could not infer base domain; scope will use placeholder")

    # --- Build scope.json ---
    if not args.authorized_by or not args.ref:
        print(
            "error: strix init requires --authorized-by and --ref; a scope document "
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

    # Write scope.json
    scope_output = Path(args.output).expanduser().resolve()
    scope_output.parent.mkdir(parents=True, exist_ok=True)
    scope_output.write_text(json.dumps(scope_doc, indent=2))
    print(f"\n✓ Scope document written to {scope_output}")

    # --- Generate GitHub Action workflow ---
    if args.github_action:
        workflow_path = repo_path / ".github" / "workflows" / "strix-scan.yml"
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
    print(f"  2. Run an assessment: strix assess --target <URL> --scope {scope_output}")
    if args.github_action:
        print("  3. Push to GitHub — the workflow will run SARIF scans on PRs")
    return 0


def _detect_framework(repo_path: Path) -> dict[str, str]:
    """Detect primary framework and language from repository files."""
    framework = "unknown"
    language = "unknown"

    # Check for key files
    files = {f.name for f in repo_path.rglob("*") if f.is_file()}

    # Python frameworks
    if "requirements.txt" in files or "pyproject.toml" in files or "setup.py" in files:
        language = "python"
        # Check for framework-specific files
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
    # Node.js frameworks
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
    # Go
    elif "go.mod" in files:
        language = "go"
        framework = "go"
    # Java
    elif "pom.xml" in files or "build.gradle" in files or "build.gradle.kts" in files:
        language = "java"
        framework = "spring" if "pom.xml" in files else "gradle"
    # Rust
    elif "Cargo.toml" in files:
        language = "rust"
        framework = "rust"
    # PHP
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
        # Generic pattern matching for other frameworks
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
    # urls.py patterns
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
    # Controller decorators
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
    # App router: route.ts files in app/**/route.ts
    for route_file in repo_path.rglob("app/**/route.ts"):
        if "node_modules" in str(route_file):
            continue
        try:
            rel = route_file.relative_to(repo_path)
            # Convert app/api/users/route.ts -> /api/users
            path_parts = list(rel.parts)
            if "app" in path_parts:
                idx = path_parts.index("app")
                api_parts = path_parts[idx + 1 : -1]  # exclude app and route.ts
                route_path = "/" + "/".join(api_parts).replace("[", "{").replace("]", "}")
                # Check for HTTP methods in the file
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
    # @RequestMapping, @GetMapping, etc.
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
    # Very basic patterns for common frameworks
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

    # Check for JWT
    jwt_patterns = [
        r"jwt",
        r"JSONWebToken",
        r"Bearer\s+token",
        r"Authorization\s*:\s*Bearer",
    ]
    # Check for session/cookie
    session_patterns = [
        r"session",
        r"cookie",
        r"express-session",
        r"django\.contrib\.sessions",
        r"flask\.session",
    ]
    # Check for API key
    api_key_patterns = [
        r"api[_-]?key",
        r"X-API-Key",
        r"api_key",
    ]
    # Check for OAuth/OIDC
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

    # Look for common host patterns in routes
    hosts = set()
    for route in routes:
        path = route.get("path", "")
        # Extract potential host from full URLs
        if path.startswith(("http://", "https://")):
            try:
                from urllib.parse import urlparse

                parsed = urlparse(path)
                if parsed.netloc:
                    hosts.add(parsed.netloc)
            except Exception:
                pass

    if hosts:
        # Return the most common host
        return list(hosts)[0]

    # Fallback: try to find in config files
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

    # Add common subdomains
    if base_domain:
        common_subs = ["api", "app", "admin", "staging", "dev", "test"]
        for sub in common_subs:
            include_hosts.append(f"{sub}.{base_domain}")

    # Extract unique paths from routes for reference
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
            "generated_by": "strix init",
            "framework": framework,
            "language": language,
            "detected_routes": len(routes),
            "unique_paths": unique_paths[:50],  # cap for readability
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
    """Generate GitHub Action workflow YAML for Strix SARIF scans."""
    return f"""# Strix Security Assessment — GitHub Action
# Generated by `strix init` — review before committing.
# This workflow runs on push/PR and uploads SARIF to GitHub Code Scanning.
name: Strix Security Scan

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
  strix-scan:
    name: Strix Assessment
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Strix
        run: |
          pip install -U pip
          pip install strix

      - name: Install optional scanners
        run: |
          # Semgrep for SAST (used by strix-code-scan)
          pip install semgrep || true
          # Bandit for Python SAST
          pip install bandit || true
          # Trivy for SCA/secrets/misconfig
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
            | sh -s -- -b /usr/local/bin || true

      - name: Run Strix assessment
        id: strix
        run: |
          strix assess \\
            --target "{target}" \\
            --scope "{scope_file}" \\
            --profile "{profile}" \\
            --output strix-results.sarif \\
            --actor "github-actions"
        env:
          # Required for authenticated scans (if configured in scope)
          # STRIX_ENCRYPTION_KEY: ${{ secrets.STRIX_ENCRYPTION_KEY }}
          # STRIX_AUDIT_HMAC_KEY: ${{ secrets.STRIX_AUDIT_HMAC_KEY }}

      - name: Upload SARIF to GitHub Code Scanning
        if: {str(upload_sarif).lower()}
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: strix-results.sarif
          category: strix

      - name: Run local code scan (SAST/SCA)
        run: |
          strix-code-scan . --sarif --output strix-code-scan.sarif || true
        continue-on-error: true

      - name: Upload code scan SARIF
        if: {str(upload_sarif).lower()}
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: strix-code-scan.sarif
          category: strix-code-scan
"""


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="strix", description="Strix assessment platform")
    parser.add_argument("--version", action="version", version=f"strix {__version__}")
    # Loopback by default: exposing the API is an explicit deployment choice
    # (the container image passes 0.0.0.0 and sits behind nginx).
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    parser.add_argument(
        "--reset-audit-chain",
        action="store_true",
        help="Clear the sealed audit chain before starting. Use only for a deliberate recovery.",
    )
    subparsers = parser.add_subparsers(dest="command")

    # Server subcommand
    server_parser = subparsers.add_parser("serve", help="Run the API server")
    server_parser.add_argument("--host", default="127.0.0.1")
    server_parser.add_argument("--port", type=int, default=8000)
    server_parser.add_argument("--reload", action="store_true")
    server_parser.add_argument(
        "--reset-audit-chain",
        action="store_true",
        help="Clear the sealed audit chain before starting. Use only for a deliberate recovery.",
    )

    # Assess subcommand (MVP CLI)
    assess_parser = subparsers.add_parser("assess", help="Run a single assessment and output SARIF")
    assess_parser.add_argument("--target", required=True, help="Target URL (e.g. https://app.example.com/)")
    assess_parser.add_argument(
        "--profile",
        default="web",
        choices=["web", "web-deep", "api", "api-deep", "network"],
        help="Assessment profile (default: web)",
    )
    assess_parser.add_argument(
        "--scope",
        default="scope.json",
        help="Path to scope.json authorization document (default: scope.json)",
    )
    assess_parser.add_argument(
        "--output",
        "-o",
        help="Output SARIF file (default: stdout)",
    )
    assess_parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="Overall job deadline in seconds (default: 300)",
    )
    assess_parser.add_argument(
        "--actor",
        default="analyst",
        help="Actor name for audit trail (default: analyst)",
    )
    # Authentication options
    assess_parser.add_argument(
        "--auth-type",
        choices=["token", "session", "form_login", "multi_step"],
        help="Authentication type for authenticated scanning",
    )
    assess_parser.add_argument(
        "--auth-config",
        help="Path to JSON file with authentication configuration (alternative to individual flags)",
    )
    # Token auth options
    assess_parser.add_argument(
        "--auth-bearer",
        help="Bearer token for Authorization header",
    )
    assess_parser.add_argument(
        "--auth-api-key",
        help="API key value",
    )
    assess_parser.add_argument(
        "--auth-api-key-header",
        default="X-API-Key",
        help="Header name for API key (default: X-API-Key)",
    )
    assess_parser.add_argument(
        "--auth-header",
        action="append",
        default=[],
        help="Custom header as 'Name:Value' (repeatable)",
    )
    # Session auth options
    assess_parser.add_argument(
        "--auth-cookie",
        action="append",
        default=[],
        help="Session cookie as 'name=value' (repeatable)",
    )
    # Form login options
    assess_parser.add_argument(
        "--auth-login-url",
        help="Login form URL",
    )
    assess_parser.add_argument(
        "--auth-username",
        help="Username for form login",
    )
    assess_parser.add_argument(
        "--auth-password",
        help="Password for form login",
    )
    assess_parser.add_argument(
        "--auth-username-field",
        default="username",
        help="Username field name (default: username)",
    )
    assess_parser.add_argument(
        "--auth-password-field",
        default="password",
        help="Password field name (default: password)",
    )
    assess_parser.add_argument(
        "--auth-csrf-field",
        help="CSRF token field name",
    )
    assess_parser.add_argument(
        "--auth-extra-field",
        action="append",
        default=[],
        help="Extra form field as 'name=value' (repeatable)",
    )
    assess_parser.add_argument(
        "--grant",
        default="",
        help="Signed grant (Strix Proof) authorizing and receipting this run",
    )
    assess_parser.add_argument("--proof-out", default="", help="Write a proof pack for this run")
    assess_parser.add_argument(
        "--proof-ledger",
        default="",
        help="Append receipts to this JSONL ledger (default: in memory)",
    )
    assess_parser.add_argument(
        "--gate-key",
        default="",
        help="Gate signing key file for receipts (created if absent)",
    )
    assess_parser.add_argument(
        "--trusted-issuer",
        default="",
        help="Require the grant to be signed by this public key (or key file)",
    )

    # Evidence subcommand (Nepal compliance packs)
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

    # Scope template subcommand (Nepal sector starters)
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

    # Scope wizard subcommand (interactive scope.json creation)
    scope_wizard_parser = subparsers.add_parser(
        "scope-wizard", help="Interactively create a scope.json authorization document"
    )
    scope_wizard_parser.add_argument(
        "--output",
        "-o",
        default="scope.json",
        help="Output file path (default: scope.json)",
    )

    # Scope signing subcommands (Ed25519, JWKS rotation)
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

    # Break-glass subcommand (dual-approval emergency scope authorization)
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

    # Init subcommand (generate scope.json + GitHub Action from repo analysis)
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
        help="Generate .github/workflows/strix-scan.yml workflow file",
    )
    init_parser.add_argument(
        "--allow-broad-networks",
        action="store_true",
        help="Allow broad networks (e.g., /8) in scope",
    )

    # Report subcommand (free HTML report — competitors charge for this)
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
        default="Strix assessment report",
        help="Report title (default: 'Strix assessment report')",
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

    # Strix Proof: signed authorization, enforcement receipts, offline proof.
    grant_parser = subparsers.add_parser("grant", help="Create and sign an authorization grant (Strix Proof)")
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
        default=os.environ.get("STRIX_PROOF_TOKEN", ""),
        help="Bearer token required on every request (env: STRIX_PROOF_TOKEN)",
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

    # Warm standby promotion (HA via single-host failover)
    standby_parser = subparsers.add_parser(
        "standby-promote", help="Promote warm standby: verify backup, restore DB, take lease, run readiness"
    )
    standby_parser.add_argument(
        "--backup-dir", required=True, help="Directory containing strix-*.db backup files"
    )
    standby_parser.add_argument(
        "--db-path", required=True, help="Target database path to restore to (e.g., /var/lib/strix/strix.db)"
    )
    standby_parser.add_argument(
        "--scope-file", default="", help="Scope file path (overrides STRIX_SCOPE_FILE)"
    )
    standby_parser.add_argument(
        "--timeout", type=float, default=30.0, help="Readiness check timeout in seconds (default: 30)"
    )
    standby_parser.add_argument(
        "--dry-run", action="store_true", help="Verify backup only, do not restore or promote"
    )

    args = parser.parse_args(argv)

    if args.command is None:
        args.command = "serve"

    if args.command == "serve":
        _run_server(args)
    elif args.command == "assess":
        sys.exit(_run_assess(args))
    elif args.command == "evidence":
        sys.exit(_run_evidence(args))
    elif args.command == "scope-template":
        sys.exit(_run_scope_template(args))
    elif args.command == "scope-wizard":
        sys.exit(_run_scope_wizard(args))
    elif args.command == "scope-keygen":
        sys.exit(_run_scope_keygen(args))
    elif args.command == "scope-key-rotate":
        sys.exit(_run_scope_key_rotate(args))
    elif args.command == "scope-sign":
        sys.exit(_run_scope_sign(args))
    elif args.command == "scope-breakglass":
        sys.exit(_run_scope_breakglass(args))
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
    else:
        parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()

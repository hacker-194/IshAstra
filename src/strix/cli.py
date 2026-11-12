"""Command-line entry points: ``strix`` (server) and ``strix assess`` (CLI scan)."""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import sys
from pathlib import Path

import uvicorn

from strix import __version__, proof
from strix.config import Settings
from strix.core import jobs as jobs_module
from strix.core import scope as scope_module
from strix.core import store
from strix.core.findings import to_sarif


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


def _run_server(args: argparse.Namespace) -> None:
    settings = Settings.from_env()
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
    settings = Settings.from_env()
    _configure_logging(settings)

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
            f"proof pack written to {pack_path} "
            f"({len(pack['receipts'])} receipts)",
            file=sys.stderr,
        )

    # Output SARIF
    sarif_doc = to_sarif(
        job.findings, tool_version=job.policy.get("tool_version", "strix")
    )
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
    settings = Settings.from_env()
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

    # Load policy mappings for selected framework(s)
    from strix.core import evidence as evidence_module

    frameworks = (
        ["nrb", "nta", "ncsp"] if args.framework == "all" else [args.framework]
    )
    mappings = evidence_module.load_mappings(frameworks)

    # Generate evidence pack
    pack = evidence_module.build_evidence_pack(
        job=job,
        mappings=mappings,
        include_passing=args.include_passing,
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
        output = evidence_module.printable_html(pack)
        print(
            "note: PDF rendering is not bundled; wrote printable HTML instead "
            "(open it and use Print to PDF).",
            file=sys.stderr,
        )
    else:
        output = json.dumps(pack, indent=2, default=str)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(output)
        print(f"Evidence pack written to {output_path}", file=sys.stderr)
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
    has_gaps = any(
        c.get("status") in ("fail", "gap", "finding") for c in pack.get("controls", [])
    )
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
        private = (
            proof.load_private_key(args.key)
            if args.key
            else proof.new_keypair()[0]
        )
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
        f"POST http://{args.host}:{args.port}/v1/authorize "
        '{"url": "https://...", "method": "GET"}',
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
    report = proof.verify_pack(
        pack, trusted_issuer=trusted_issuer, trusted_gate=trusted_gate
    )
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
            print(
                "note: issuer key not pinned; this proves the grant is intact, "
                "not who issued it"
            )
        for error in report["errors"]:
            print(f"error: {error}", file=sys.stderr)
        print("VERIFIED" if report["ok"] else "NOT VERIFIED")
    return 0 if report["ok"] else 1


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
            template[key] = list(
                dict.fromkeys(p.replace(base, domain) for p in template[key])
            )

    output = json.dumps(template, indent=2)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(output)
        print(f"Scope template written to {output_path}", file=sys.stderr)
    else:
        print(output)

    return 0


def _run_report(args: argparse.Namespace) -> int:
    """Generate HTML assessment report and output. Competitors charge for this; strix gives it free."""
    settings = Settings.from_env()
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

    # Build the report dict compatible with report_html
    report = {
        "target": args.target,
        "job_id": job.id if hasattr(job, 'id') else 'unknown',
        "state": job.state.name if hasattr(job, 'state') else 'unknown',
        "verdict": job.verdict if hasattr(job, 'verdict') else 'unknown',
        "program": loaded_scope.program if loaded_scope else 'unknown',
        "authorized_by": loaded_scope.authorized_by if loaded_scope else 'unknown',
        "authorization_ref": loaded_scope.authorization_ref if loaded_scope else 'unknown',
        "scope_include": loaded_scope.include if loaded_scope else [],
        "findings": [
            {
                "severity": f.severity if hasattr(f, 'severity') else 'info',
                "confidence": f.confidence if hasattr(f, 'confidence') else 'unknown',
                "title": f.title if hasattr(f, 'title') else 'untitled',
                "category": f.category if hasattr(f, 'category') else 'unknown',
                "cwe": f.cwe if hasattr(f, 'cwe') else 'no CWE',
                "asset": f.asset if hasattr(f, 'asset') else 'unknown',
                "location": f.location if hasattr(f, 'location') else 'unknown',
                "evidence": f.evidence if hasattr(f, 'evidence') else '',
                "remediation": f.remediation if hasattr(f, 'remediation') else '',
                "description": f.description if hasattr(f, 'description') else '',
                "detector": f.detector if hasattr(f, 'detector') else 'unknown',
                "detector_version": f.detector_version if hasattr(f, 'detector_version') else '',
            }
            for f in job.findings
        ],
    }

    # Render HTML using the existing report_html module
    from strix.report_html import render_html_report

    html_output = render_html_report(report)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(html_output)
        print(f"HTML report written to {output_path}", file=sys.stderr)
    else:
        print(html_output)

    return 0


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="strix", description="Strix assessment platform"
    )
    parser.add_argument(
        "--version", action="version", version=f"strix {__version__}"
    )
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
    assess_parser = subparsers.add_parser(
        "assess", help="Run a single assessment and output SARIF"
    )
    assess_parser.add_argument(
        "--target", required=True, help="Target URL (e.g. https://app.example.com/)"
    )
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
    assess_parser.add_argument(
        "--grant",
        default="",
        help="Signed grant (Strix Proof) authorizing and receipting this run",
    )
    assess_parser.add_argument(
        "--proof-out", default="", help="Write a proof pack for this run"
    )
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
    evidence_parser.add_argument(
        "--target", required=True, help="Target URL (e.g. https://app.example.com/)"
    )
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
        help="Output format (default: json; pdf writes printable HTML)",
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

    # Report subcommand (free HTML report — competitors charge for this)
    report_parser = subparsers.add_parser(
        "report", help="Generate HTML assessment report"
    )
    report_parser.add_argument(
        "--target", required=True, help="Target URL (e.g. https://app.example.com/)"
    )
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
        "--output",
        "-o",
        help="Output HTML file (default: stdout)",
    )
    report_parser.add_argument(
        "--title", default="Strix assessment report",
        help="Report title (default: 'Strix assessment report')",
    )
    report_parser.add_argument(
        "--logo", default="",
        help="Logo filename in static/ (default: none)",
    )

    # Strix Proof: signed authorization, enforcement receipts, offline proof.
    grant_parser = subparsers.add_parser(
        "grant", help="Create and sign an authorization grant (Strix Proof)"
    )
    grant_parser.add_argument("--program", required=True, help="Program name")
    grant_parser.add_argument(
        "--authorized-by", required=True, help="Who authorizes the testing"
    )
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
    grant_parser.add_argument(
        "--network", action="append", default=[], help="Authorized CIDR (repeatable)"
    )
    grant_parser.add_argument("--port", action="append", type=int, default=[])
    grant_parser.add_argument(
        "--days", type=float, default=30.0, help="Validity in days (default: 30)"
    )
    grant_parser.add_argument("--id", default="", help="Explicit grant id")
    grant_parser.add_argument(
        "--key", help="Existing issuer private key (default: generate one)"
    )
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
    gate_parser.add_argument(
        "--gate-key", default="gate.key", help="Gate signing key (created if absent)"
    )
    gate_parser.add_argument(
        "--trusted-issuer", default="", help="Pinned issuer public key or key file"
    )
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
    proof_parser.add_argument(
        "--gate-key", default="", help="Require this gate public key (or key file)"
    )
    proof_parser.add_argument("--out", "-o", default="proof.json")

    verify_parser = subparsers.add_parser(
        "verify", help="Verify a proof pack offline"
    )
    verify_parser.add_argument("proof", help="Path to the proof pack JSON")
    verify_parser.add_argument(
        "--issuer-key", default="", help="Pin the issuer public key or key file"
    )
    verify_parser.add_argument(
        "--gate-key", default="", help="Pin the gate public key or key file"
    )
    verify_parser.add_argument("--json", action="store_true")

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
    else:
        parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()

"""Scanner adapter framework: one capability, one tool, availability as it ran.

Every adapter re-checks the scope gate itself, and external tools run as
argument arrays with a minimal environment, a hard deadline and a kill switch.
Nmap receives the validated destination IP; Nuclei receives it too, with the
original Host header and TLS SNI preserved and redirects disabled. Keep
host-level egress filtering on as a second layer if you customize templates.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring as safe_fromstring

from ishastra import __version__
from ishastra.core import scope
from ishastra.core.adapter_base import (
    Adapter,
    AdapterCancelled,
    AdapterError,
    AdapterNotApplicable,
    AdapterResult,
    AdapterTimeout,
    checked_destination,
)
from ishastra.core.authz import (
    AuthConfig,
    DifferentialResult,
    Principal,
    body_digest,
    candidate_endpoints,
    classify,
)
from ishastra.core.collab import (
    CollabClient,
    CollabConfig,
    CollabServer,
    new_token,
    shared_inprocess_server,
)
from ishastra.core.crawler import MAX_PAGES as CRAWL_MAX_PAGES
from ishastra.core.crawler import WebCrawler
from ishastra.core.exposure import GitExposureAdapter
from ishastra.core.findings import SEVERITIES, Finding
from ishastra.core.ports import RISKY_PORTS, TCPPortAdapter
from ishastra.core.probe import EndpointProbe
from ishastra.core.sandbox import (
    SandboxCancelled,
    SandboxError,
    SandboxOutputLimitExceeded,
    SandboxResult,
    SandboxTimeout,
    SandboxUnavailable,
    run_in_sandbox,
)
from ishastra.core.signatures import match_url_signatures
from ishastra.core.urls import parse_url

log = logging.getLogger(__name__)


WEB_CHECKS: dict[str, tuple[str, str, str, str]] = {
    "sqli": (
        "info",
        "Potential SQL injection indicator in request target",
        "CWE-89",
        "Review server-side query construction; use parameterized queries.",
    ),
    "xss": (
        "info",
        "Potential XSS indicator; execution context unverified",
        "CWE-79",
        "Inspect the response context and apply context-aware output encoding.",
    ),
    "open_redirect": (
        "info",
        "Potential redirect-parameter indicator",
        "CWE-601",
        "Verify whether user-controlled input can select an external destination.",
    ),
    "path_traversal": (
        "info",
        "Potential path-traversal indicator in request target",
        "CWE-22",
        "Verify server-side path handling and confine paths to an authorized root.",
    ),
    "ssrf": (
        "info",
        "Potential SSRF indicator in request target",
        "CWE-918",
        "Verify server-side destination handling and enforce outbound destination allowlists.",
    ),
    "secret": (
        "info",
        "Credential-shaped text in request target",
        "CWE-798",
        "Do not put credentials in URLs; rotate any credential confirmed to be exposed.",
    ),
    "missing_csp": (
        "low",
        "Missing Content-Security-Policy header",
        "CWE-693",
        "Send a restrictive Content-Security-Policy header where appropriate.",
    ),
    "missing_hsts": (
        "low",
        "Missing Strict-Transport-Security header",
        "CWE-319",
        "Send HSTS on HTTPS responses once HTTPS is enforced.",
    ),
}

_URL_INDICATORS = frozenset({"sqli", "xss", "open_redirect", "path_traversal", "ssrf", "secret"})


class HTTPAdapter(Adapter):
    """Existing Ishastra DAST + probe engine, normalized into findings."""

    id = "ishastra-http"
    version = __version__
    asset_types = ("web",)

    MAX_DISCOVERED_PROBES = 10

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        checked_destination(target)

        auth_principal = None
        if context and "auth_principal" in context:
            auth_principal = context["auth_principal"]

        started = time.monotonic()
        deadline = started + max(0.05, timeout)
        result = AdapterResult()

        probe = EndpointProbe(
            timeout=min(timeout * 0.8, 8.0),
            rate_limit_rps=float((context or {}).get("rate_limit_rps") or 0),
        )

        response = probe.probe(target, deadline=deadline, auth=auth_principal)
        if cancel.is_set():
            raise AdapterCancelled("cancelled during HTTP probe")
        if time.monotonic() >= deadline:
            raise AdapterTimeout("HTTP assessment deadline exhausted during initial probe")

        reflected = probe.reflections(target, cancel=cancel, deadline=deadline, auth=auth_principal)
        if cancel.is_set():
            raise AdapterCancelled("cancelled during reflection checks")
        if time.monotonic() > deadline:
            raise AdapterTimeout("HTTP assessment deadline exhausted during reflection checks")
        self._observe(target, response, result, reflected=reflected, notes=result.notes)

        discovered = list((context or {}).get("discovered_urls") or [])
        for url in discovered[: self.MAX_DISCOVERED_PROBES]:
            if cancel.is_set():
                raise AdapterCancelled("cancelled during discovered-page probes")
            if time.monotonic() >= deadline:
                result.notes.append("deadline reached before every discovered page was probed")
                break
            if url == target:
                continue
            page_denial, _page_reason = scope.check(url)
            if page_denial:
                continue
            page_response = probe.probe(url, deadline=deadline, auth=auth_principal)
            self._observe(url, page_response, result, reflected=(), notes=result.notes)
        if len(discovered) > self.MAX_DISCOVERED_PROBES:
            result.notes.append(
                f"{len(discovered) - self.MAX_DISCOVERED_PROBES} discovered page(s) "
                "beyond the probe budget were not fetched"
            )
        return result

    def _observe(
        self,
        url: str,
        response: dict[str, Any],
        result: AdapterResult,
        *,
        reflected: tuple[dict[str, Any], ...] | list[dict[str, Any]],
        notes: list[str],
    ) -> None:
        """Turn one HTTP response into observations (never into verdicts)."""
        observed: dict[str, str] = {}
        for name in match_url_signatures(url):
            observed[name] = (
                "request-target signature matched; this is an indicator only and "
                "does not establish that the server is vulnerable"
            )
        headers = response.get("headers", {})
        parsed_url = parse_url(url)
        if isinstance(response.get("status"), int):
            if not headers.get("content-security-policy"):
                observed["missing_csp"] = (
                    f"HTTP {response['status']} response carries no Content-Security-Policy header"
                )

            if parsed_url and parsed_url.scheme == "https" and not headers.get("strict-transport-security"):
                observed["missing_hsts"] = (
                    f"HTTPS response {response['status']} carries no Strict-Transport-Security header"
                )
            notes.append(f"HTTP {response['status']} from {url}")
        else:
            notes.append(
                f"no HTTP response ({response.get('status')}: "
                f"{response.get('reason') or response.get('error') or 'unknown'})"
            )

        if response.get("redirect_to"):
            scope_note = "in-scope" if response.get("redirect_in_scope") else "out-of-scope"
            notes.append(
                f"HTTP redirect observed to {response['redirect_to']} ({scope_note}); "
                "redirects are not followed and are not classified as vulnerabilities by themselves"
            )

        if reflected:
            parameters = ", ".join(sorted({str(hit["parameter"]) for hit in reflected}))
            observed["xss"] = (
                f"benign marker reflected for parameter(s): {parameters}; "
                "HTML/JavaScript execution context was not tested"
            )

        for category, evidence in observed.items():
            severity, title, cwe, remediation = WEB_CHECKS[category]
            is_indicator = category in _URL_INDICATORS or category == "xss" and bool(reflected)
            if is_indicator:
                severity = "info"
                confidence = "low"
                verification = "unverified"
            else:
                confidence = "medium"
                verification = "observed"
            result.findings.append(
                Finding(
                    asset=url,
                    category=category,
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    detector=self.id,
                    detector_version=self.version,
                    evidence=evidence,
                    location=url,
                    remediation=remediation,
                    cwe=cwe,
                    verification=verification,
                )
            )


class DynamicValidationAdapter(Adapter):
    """Low-impact validation of redirect and database-error indicators.

    This adapter sends only bounded GET requests using existing query
    parameters. Redirect canaries use the reserved .invalid TLD and redirects
    are never followed. It does not extract data or send state-changing payloads.
    """

    id = "ishastra-dynamic-validation"
    version = __version__
    asset_types = ("web",)
    MAX_TIMEOUT = 20.0

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        destination = checked_destination(target)
        parsed_target = parse_url(target)
        if parsed_target is None or not parsed_target.query:
            raise AdapterNotApplicable(
                "no query parameters available; dynamic input validation is inconclusive"
            )
        deadline = time.monotonic() + min(max(0.05, timeout), self.MAX_TIMEOUT)
        rate_limit_rps = float((context or {}).get("rate_limit_rps") or 0)
        probe = EndpointProbe(timeout=min(5.0, timeout), rate_limit_rps=rate_limit_rps)

        auth_principal = None
        if context and "auth_principal" in context:
            auth_principal = context["auth_principal"]

        result = AdapterResult()
        redirects = probe.redirect_tests(target, cancel=cancel, deadline=deadline, auth=auth_principal)
        if cancel.is_set():
            raise AdapterCancelled("cancelled during redirect validation")
        for item in redirects:
            result.findings.append(
                Finding(
                    asset=target,
                    category="open_redirect",
                    title="Query parameter controls an external redirect destination",
                    severity="medium",
                    confidence="high",
                    detector=self.id,
                    detector_version=self.version,
                    evidence=str(item.get("evidence") or "External redirect canary observed"),
                    location=str(item.get("request_url") or target),
                    description=(
                        "The server returned a Location destination matching a unique "
                        "reserved .invalid canary supplied through a query parameter. "
                        "The redirect was not followed."
                    ),
                    remediation=(
                        "Validate redirect destinations against an exact allowlist of "
                        "approved URLs or hostnames; reject arbitrary external destinations."
                    ),
                    cwe="CWE-601",
                    verification="observed",
                )
            )
        if time.monotonic() < deadline and not cancel.is_set():
            sql_indicators = probe.database_error_tests(
                target, cancel=cancel, deadline=deadline, auth=auth_principal
            )
            for item in sql_indicators:
                result.findings.append(
                    Finding(
                        asset=target,
                        category="sqli_error_indicator",
                        title="Database error signature exposed after query input variation",
                        severity="medium",
                        confidence="medium",
                        detector=self.id,
                        detector_version=self.version,
                        evidence=str(item.get("evidence") or "Database error signature observed"),
                        location=str(item.get("request_url") or target),
                        description=(
                            "A database error signature appeared after a low-impact quote "
                            "mutation. This is evidence of a possible injection path, not "
                            "proof that a query can be exploited."
                        ),
                        remediation=(
                            "Use parameterized queries and avoid returning database exceptions "
                            "to clients. Validate the suspected path with a controlled test."
                        ),
                        cwe="CWE-89",
                        verification="inferred",
                    )
                )
        if cancel.is_set():
            raise AdapterCancelled("cancelled during dynamic validation")
        if time.monotonic() >= deadline:
            result.notes.append("dynamic validation reached its bounded deadline")
        else:
            result.notes.append(
                f"dynamic validation completed: {len(redirects)} redirect behavior(s), "
                f"{len(sql_indicators) if 'sql_indicators' in locals() else 0} database error indicator(s)"
            )
        return result


class OpenAPIAdapter(Adapter):
    """Discover OpenAPI/Swagger descriptions and check declared protected GETs.

    Only same-origin, in-scope endpoints documented as security-protected are
    probed, with credentials if available, and only with GET. A success is
    reported as an authorization mismatch indicator (unverified) because OpenAPI
    documents can be stale or endpoint access may be intentionally public.
    """

    id = "ishastra-openapi"
    version = __version__
    asset_types = ("web",)
    SPEC_CANDIDATES = ("openapi.json", "swagger.json", "api-docs", "v3/api-docs")
    MAX_SPEC_BYTES = 262144
    MAX_ENDPOINTS = 30

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        checked_destination(target)
        result = AdapterResult()
        parsed_target = parse_url(target)
        if parsed_target is None or not parsed_target.hostname:
            raise AdapterError("invalid target URL")
        origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
        path_base = parsed_target.path.rstrip("/")
        candidates = []
        if parsed_target.path.lower().endswith(("openapi.json", "swagger.json", "api-docs")):
            candidates.append(target)
        candidates.extend(
            [
                f"{origin}{path_base}/openapi.json",
                f"{origin}{path_base}/swagger.json",
                f"{origin}/openapi.json",
                f"{origin}/swagger.json",
                f"{origin}/api-docs",
                f"{origin}/v3/api-docs",
            ]
        )
        candidates = list(dict.fromkeys(candidates))[:7]
        started = time.monotonic()
        deadline = started + max(0.05, timeout)
        rate_limit_rps = float((context or {}).get("rate_limit_rps") or 0)
        probe = EndpointProbe(
            timeout=min(5.0, timeout),
            max_body=self.MAX_SPEC_BYTES,
            rate_limit_rps=rate_limit_rps,
        )

        auth_principal = None
        if context and "auth_principal" in context:
            auth_principal = context["auth_principal"]

        spec: dict[str, Any] | None = None
        spec_url = ""
        for candidate in candidates:
            if cancel.is_set():
                raise AdapterCancelled("cancelled while discovering OpenAPI spec")
            if time.monotonic() >= deadline:
                raise AdapterTimeout("OpenAPI discovery deadline exhausted")
            candidate_denial, _ = scope.check(candidate)
            if candidate_denial:
                continue
            response = probe._fetch(candidate, deadline=deadline, auth=auth_principal)
            body = response.get("body", "")
            if not isinstance(body, str) or not body or not isinstance(response.get("status"), int):
                continue
            if not 200 <= int(response["status"]) < 300:
                continue
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and (
                isinstance(payload.get("paths"), dict) and (payload.get("openapi") or payload.get("swagger"))
            ):
                spec = payload
                spec_url = candidate
                break
        if spec is None:
            raise AdapterNotApplicable(
                "no supported OpenAPI/Swagger JSON document found at common same-scope "
                "paths; API coverage is inconclusive"
            )
        result.notes.append(f"OpenAPI document discovered at {spec_url}")

        servers = spec.get("servers")
        server_base = origin
        if isinstance(servers, list) and servers:
            chosen = None
            for server in servers[:10]:
                if not isinstance(server, dict) or not isinstance(server.get("url"), str):
                    continue
                raw_server = server["url"].strip()
                if "{" in raw_server or "}" in raw_server:
                    continue
                absolute = urljoin(spec_url, raw_server)
                server_parsed = urlparse(absolute)
                target_parsed = urlparse(origin)
                server_port = server_parsed.port or (443 if server_parsed.scheme == "https" else 80)
                target_port = target_parsed.port or (443 if target_parsed.scheme == "https" else 80)
                if (
                    server_parsed.scheme in {"http", "https"}
                    and (server_parsed.hostname or "").lower() == (target_parsed.hostname or "").lower()
                    and server_port == target_port
                ):
                    server_denial, _ = scope.check(absolute)
                    if not server_denial:
                        chosen = absolute.rstrip("/")
                        break
            if chosen:
                server_base = chosen
            else:
                raise AdapterError(
                    "OpenAPI server URL is not same-origin/in-scope; refusing to probe external endpoints"
                )

        paths = spec.get("paths")
        global_security = spec.get("security", [])
        if not isinstance(paths, dict):
            raise AdapterError(
                "OpenAPI document contains no usable paths object; API coverage is inconclusive"
            )
        endpoints_checked = 0
        for path, path_item in paths.items():
            if cancel.is_set():
                raise AdapterCancelled("cancelled during OpenAPI endpoint checks")
            if time.monotonic() >= deadline:
                result.notes.append("OpenAPI endpoint checks stopped at deadline")
                break
            if not isinstance(path, str) or not path.startswith("/") or "{" in path or "}" in path:
                continue
            if "\\" in path or ".." in path or "?" in path or "#" in path:
                continue
            if not isinstance(path_item, dict):
                continue
            operation = path_item.get("get")
            if not isinstance(operation, dict):
                continue
            security = operation.get("security", global_security)
            requires_auth = isinstance(security, list) and any(
                isinstance(item, dict) and bool(item) for item in security
            )
            if not requires_auth:
                continue
            endpoint = server_base + "/" + path.lstrip("/")
            endpoint_denial, _ = scope.check(endpoint)
            if endpoint_denial:
                continue
            endpoints_checked += 1
            response = probe._fetch(endpoint, deadline=deadline, auth=auth_principal)
            status_code = response.get("status")
            if isinstance(status_code, int) and 200 <= status_code < 300:
                auth_note = "with credentials" if auth_principal else "without credentials"
                result.findings.append(
                    Finding(
                        asset=target,
                        category="api_documented_auth_mismatch",
                        title="Endpoint documented as protected responded successfully",
                        severity="medium",
                        confidence="medium",
                        detector=self.id,
                        detector_version=self.version,
                        evidence=(
                            f"OpenAPI declares security for GET {path}; request {auth_note} "
                            f"returned HTTP {status_code}. Response content was not retained."
                        ),
                        location=endpoint,
                        description=(
                            "This is an authorization mismatch indicator, not definitive proof: "
                            "the specification may be stale or this route may intentionally be public."
                        ),
                        remediation=(
                            "Verify the endpoint's intended access policy. Enforce authorization "
                            "server-side and keep the OpenAPI security declaration synchronized."
                        ),
                        cwe="CWE-862",
                        verification="unverified",
                    )
                )
            if endpoints_checked >= self.MAX_ENDPOINTS:
                result.notes.append(f"OpenAPI endpoint limit ({self.MAX_ENDPOINTS}) reached")
                break
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        auth_note = "with credentials" if auth_principal else "without credentials"
        result.notes.append(
            f"OpenAPI checked {endpoints_checked} documented protected GET endpoint(s) {auth_note}"
        )
        return result


class CrawlerAdapter(Adapter):
    """Bounded, same-origin crawl that publishes in-scope URLs to later adapters.

    This adapter produces no findings by itself: discovery is not a verdict.
    Discovered URLs are written to ``context["discovered_urls"]`` where the HTTP
    assessment adapter picks them up; both halves stay scope-gated so crawler
    output can never widen the engagement.
    """

    id = "ishastra-crawl"
    version = __version__
    asset_types = ("web",)
    MAX_DISCOVERED = 50

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        checked_destination(target)
        deadline = time.monotonic() + max(0.05, timeout)

        auth_principal = None
        if context and "auth_principal" in context:
            auth_principal = context["auth_principal"]

        rate_limit_rps = float((context or {}).get("rate_limit_rps") or 0)
        crawler = WebCrawler(max_pages=CRAWL_MAX_PAGES, timeout=min(10.0, timeout / 2))
        crawl = crawler.crawl(target, deadline=deadline, cancel=cancel, auth=auth_principal)
        if rate_limit_rps:
            crawl.notes.append(f"rate limit applied: {rate_limit_rps} rps")
        result = AdapterResult()
        result.notes.extend(crawl.notes or [f"crawl completed: {len(crawl.pages)} page(s)"])
        result.notes.append(
            f"discovered {len(crawl.discovered)} in-scope link(s) across {len(crawl.pages)} page(s)"
        )
        if context is not None:
            context["discovered_urls"] = crawl.discovered[: self.MAX_DISCOVERED]
            context["crawl_pages"] = [page.to_dict() for page in crawl.pages]
        return result


class AuthorizationDiffAdapter(Adapter):
    """Cross-principal authorization differences on object-shaped endpoints.

    Requires test principals in the scope document (``auth.users``). For a
    bounded set of candidate endpoints the adapter requests the same URL as
    each principal and as an anonymous caller, then compares statuses and body
    digests. Findings are behavioral facts labeled inferred: identical data
    across principals is an unscoped-object indicator, not proof of IDOR.
    Credentials never appear in evidence — principals are named by id only.
    """

    id = "ishastra-authz"
    version = __version__
    asset_types = ("web", "api")
    MAX_ENDPOINTS = 8
    MAX_BODY_FOR_DIGEST = 32768

    def __init__(self) -> None:
        self._probe = EndpointProbe(timeout=6.0)

    def available(self) -> tuple[bool, str]:
        authorized = scope.active()
        auth = authorized.auth if authorized else None
        if not isinstance(auth, AuthConfig) or not auth.users:
            return False, ("no test principals configured (add auth.users to the scope document)")
        return True, f"{len(auth.users)} principal(s): {', '.join(auth.ids)}"

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        checked_destination(target)
        authorized = scope.active()
        auth = authorized.auth if authorized else None
        if not isinstance(auth, AuthConfig) or len(auth.users) < 1:
            raise AdapterError("no principals available for authorization testing")

        deadline = time.monotonic() + max(0.05, timeout)
        pool = [target]
        if context:
            pool.extend(url for url in context.get("discovered_urls", []) if url != target)
        endpoints = candidate_endpoints(pool, max_endpoints=self.MAX_ENDPOINTS)
        result = AdapterResult()
        if not endpoints:
            result.notes.append(
                "no object-shaped endpoints found (numeric path segment or id parameter); "
                "authorization differences cannot be exercised"
            )
            return result

        first, *rest = auth.users
        checked = 0
        for endpoint in endpoints:
            if cancel.is_set():
                raise AdapterCancelled("cancelled during authorization checks")
            if time.monotonic() >= deadline:
                result.notes.append("authorization checks stopped at deadline")
                break
            responses: list[tuple[str, int | str, str]] = []
            responses.append(self._fetch_as(endpoint, first))
            if rest:
                responses.append(self._fetch_as(endpoint, rest[0]))
            responses.append(self._fetch_as(endpoint, None))
            checked += 1

            status_first = responses[0][1]
            anonymous = responses[-1]
            anonymous_matches = (
                isinstance(status_first, int)
                and isinstance(anonymous[1], int)
                and 200 <= status_first < 300
                and anonymous[1] == status_first
                and anonymous[2] == responses[0][2]
            )
            principals_identical = (
                len(responses) >= 2
                and isinstance(responses[0][1], int)
                and 200 <= responses[0][1] < 300
                and isinstance(responses[1][1], int)
                and responses[1][1] == responses[0][1]
                and responses[1][2] == responses[0][2]
            )
            differential = DifferentialResult(
                endpoint=endpoint,
                responses=tuple(responses),
                anonymous_matches_first=anonymous_matches,
                principals_identical=principals_identical,
            )
            for category in classify(differential):
                result.findings.append(self._finding(category, endpoint, differential))
            enforced = (
                isinstance(responses[0][1], int)
                and isinstance(responses[-1][1], int)
                and 200 <= responses[0][1] < 300
                and responses[-1][1] >= 400
            )
            if enforced and not result.findings:
                result.notes.append(
                    f"{endpoint}: anonymous caller refused (HTTP {responses[-1][1]}) — "
                    "authorization enforced on this endpoint"
                )
        result.notes.append(
            f"authorization differences checked on {checked} endpoint(s) with {len(auth.users)} principal(s)"
        )
        return result

    def _fetch_as(self, url: str, principal: Principal | None) -> tuple[str, int | str, str]:
        response = self._probe._fetch(url, auth=principal)
        status = response.get("status")
        status = status if isinstance(status, int | str) else "error"
        body = response.get("body", "") if isinstance(response.get("body"), str) else ""
        return (
            principal.id if principal else "anonymous",
            status,
            body_digest(body[: self.MAX_BODY_FOR_DIGEST]),
        )

    def _finding(self, category: str, endpoint: str, differential: DifferentialResult) -> Finding:
        if category == "authorization_missing":
            return Finding(
                asset=endpoint,
                category="authorization_missing",
                title="Object endpoint returns identical data to anonymous callers",
                severity="high",
                confidence="medium",
                detector=self.id,
                detector_version=self.version,
                evidence=(
                    f"{differential.evidence_line()} — the anonymous response is "
                    "byte-identical to the authenticated response"
                ),
                location=endpoint,
                description=(
                    "The endpoint returned the same response body to an unauthenticated "
                    "request and to an authenticated principal. Authentication either is "
                    "not enforced or does not change the response. Confirm whether the "
                    "data is intentionally public."
                ),
                remediation=(
                    "Require authentication for this endpoint and return 401/403 for "
                    "anonymous callers; keep authorization checks server-side."
                ),
                cwe="CWE-306",
                verification="observed",
            )
        return Finding(
            asset=endpoint,
            category="object_access_unscoped",
            title="Two distinct principals received identical object data",
            severity="medium",
            confidence="medium",
            detector=self.id,
            detector_version=self.version,
            evidence=(
                f"{differential.evidence_line()} — both principals received "
                "byte-identical responses for the same object reference"
            ),
            location=endpoint,
            description=(
                "Two different test principals requested the same object reference and "
                "received identical responses. This is a BOLA/IDOR indicator: object "
                "access may not be scoped to the owning principal. Public-by-design data "
                "or principal-independent responses can also explain this, so treat it "
                "as inferred until object ownership is confirmed."
            ),
            remediation=(
                "Enforce object-level authorization on every request (check that the "
                "authenticated principal owns or may access the requested object); "
                "return 403 for cross-tenant object access."
            ),
            cwe="CWE-639",
            verification="inferred",
        )


class SSRFOOBAdapter(Adapter):
    """Blind SSRF confirmation through out-of-band canary callbacks.

    SSRF-shaped parameters receive a unique canary URL pointing at the
    engagement's collab listener. A callback for that exact token is direct
    evidence the application fetched the injected destination — confirmed,
    not inferred. When the fetched content is reflected in the response, the
    finding is stronger still (in-band reflection recorded alongside).

    Listener configuration comes from the scope document (``collab.host`` /
    ``collab.port``); port 0 starts the in-process listener for local
    engagements. Without configuration the adapter reports unavailable.
    """

    id = "ishastra-ssrf-oob"
    version = __version__
    asset_types = ("web", "api")
    MAX_PARAMS = 6
    POLL_ATTEMPTS = 6
    POLL_INTERVAL = 0.4

    SSRF_PARAM = re.compile(
        r"^(?:url|uri|fetch|source|src|dest|destination|redirect|next|target|host|"
        r"domain|proxy|callback|feed|img|image|file|path|resource|load|read|include|"
        r"data|site|html)$",
        re.IGNORECASE,
    )
    CANARY_MARKER = "ishastra-canary"

    def __init__(self, rate_limit_rps: float = 0) -> None:
        self._probe = EndpointProbe(timeout=6.0, rate_limit_rps=rate_limit_rps)

    def _listener(self) -> tuple[CollabServer | CollabClient, str]:
        """(listener, canary base) from the active scope configuration."""
        authorized = scope.active()
        collab = authorized.collab if authorized else None
        if not isinstance(collab, CollabConfig):
            raise AdapterError("no collab listener configured for SSRF confirmation")
        if collab.port == 0:
            server = shared_inprocess_server(collab.host)
            return server, server.base_url
        return (
            CollabClient(collab.host, collab.port),
            f"http://{collab.host}:{collab.port}",
        )

    def available(self) -> tuple[bool, str]:
        authorized = scope.active()
        collab = authorized.collab if authorized else None
        if not isinstance(collab, CollabConfig):
            return False, (
                "no out-of-band listener configured (add collab.host/collab.port to the scope document)"
            )
        if collab.port == 0:
            return True, "in-process collab listener (ephemeral port)"
        return True, f"collab listener at {collab.host}:{collab.port}"

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        checked_destination(target)
        listener, canary_base = self._listener()
        deadline = time.monotonic() + max(0.05, timeout)
        pool = [target]
        if context:
            pool.extend(url for url in context.get("discovered_urls", []) if url != target)

        auth_principal = None
        if context and "auth_principal" in context:
            auth_principal = context["auth_principal"]

        candidates = self._candidate_params(pool)
        result = AdapterResult()
        if not candidates:
            result.notes.append(
                "no SSRF-shaped parameter found on the assessed URLs; "
                "out-of-band probing had nothing to inject into"
            )
            return result

        confirmed = 0
        for url, param in candidates:
            if cancel.is_set():
                raise AdapterCancelled("cancelled during SSRF probing")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result.notes.append("SSRF probing stopped at deadline")
                break
            # Apply rate limiting between probes
            self._probe._pace()
            token = new_token()
            canary = f"{canary_base}/{token}"
            finding = self._probe_param(
                url, param, canary, token, listener, cancel=cancel, deadline=deadline, auth=auth_principal
            )
            if finding is not None:
                confirmed += 1
                result.findings.append(finding)
        result.notes.append(
            f"SSRF canaries injected into {len(candidates)} parameter(s); "
            f"{confirmed} confirmed by out-of-band callback"
        )
        return result

    def _candidate_params(self, pool: list[str]) -> list[tuple[str, str]]:
        """(url, parameter) pairs worth injecting a canary into, bounded."""
        from urllib.parse import parse_qsl

        pairs: list[tuple[str, str]] = []
        for url in pool:
            parsed = parse_url(url)
            if parsed is None or not parsed.query:
                continue
            for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
                if self.SSRF_PARAM.fullmatch(name):
                    pairs.append((url, name))
                    break
            if len(pairs) >= self.MAX_PARAMS:
                break
        return pairs[: self.MAX_PARAMS]

    def _inject(self, url: str, param: str, canary: str) -> str:
        from urllib.parse import parse_qsl, urlencode

        parsed = parse_url(url)
        if parsed is None:
            return url
        params = [
            (name, canary if name == param else value)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return parsed._replace(query=urlencode(params)).geturl()

    def _probe_param(
        self,
        url: str,
        param: str,
        canary: str,
        token: str,
        listener: CollabServer | CollabClient,
        *,
        cancel: threading.Event,
        deadline: float,
        auth: Any | None = None,
    ) -> Finding | None:
        marked = self._inject(url, param, canary)
        response = self._probe._fetch(marked, deadline=deadline, auth=auth)
        body = response.get("body", "") if isinstance(response.get("body"), str) else ""
        in_band = canary in body or canary in str(response.get("redirect_to") or "")

        callbacks: list[dict[str, Any]] = []
        poll = listener.poll
        for _attempt in range(self.POLL_ATTEMPTS):
            if cancel.is_set():
                raise AdapterCancelled("cancelled while polling the collab listener")
            try:
                callbacks = poll(token)
            except AdapterError:
                raise
            except Exception:
                callbacks = []
            if callbacks:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(self.POLL_INTERVAL, remaining))
        if not callbacks:
            if in_band:
                return self._finding(url, param, canary, token, [], in_band=True)
            return None
        return self._finding(url, param, canary, token, callbacks, in_band=in_band)

    def _finding(
        self,
        url: str,
        param: str,
        canary: str,
        token: str,
        callbacks: list[dict[str, Any]],
        *,
        in_band: bool,
    ) -> Finding:
        callback = callbacks[0] if callbacks else None
        if callback is not None:
            peer = str(callback.get("peer") or "unknown peer")
            method = str(callback.get("method") or "GET")
            evidence = (
                f"unique canary {canary} injected into parameter '{param}' of {url}; "
                f"the application fetched it — callback received via {method} "
                f"from {peer} (token {token})"
            )
        else:
            evidence = (
                f"unique canary {canary} injected into parameter '{param}' of {url}; "
                "the response reflects canary content "
                f"(HTTP {in_band and 'observed'}) — no callback yet, "
                "fetch confirmed in-band only"
            )
        return Finding(
            asset=url,
            category=("ssrf_confirmed_oob" if callback is not None else "ssrf_inband_reflection"),
            title=(
                "Application fetched an attacker-chosen destination (out-of-band confirmed)"
                if callback is not None
                else "Application fetched and reflected an attacker-chosen destination"
            ),
            severity="high" if callback is not None else "medium",
            confidence="high" if callback is not None else "medium",
            detector=self.id,
            detector_version=self.version,
            evidence=evidence,
            location=url,
            description=(
                "The parameter controls a server-side fetch. The unique canary URL was "
                "retrieved by the application"
                + (
                    " and its content was reflected to us."
                    if in_band
                    else ", confirmed by the listener callback."
                )
                + " An attacker can point this at internal services, cloud metadata "
                "addresses or arbitrary hosts."
            ),
            remediation=(
                "Validate the fetch destination server-side: allowlist schemes, hosts "
                "and ports; refuse link-local, loopback and metadata addresses; never "
                "fetch raw user-supplied URLs."
            ),
            cwe="CWE-918",
            verification="observed",
        )


MAX_TOOL_OUTPUT_BYTES = 16 * 1024 * 1024


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _bounded(value: Any, limit: int) -> str:
    """Untrusted tool/template text reduced to a bounded printable string."""
    if not isinstance(value, str):
        return ""
    return _CONTROL_CHARS.sub("", value).strip()[:limit]


def _run_tool(
    argv: list[str],
    *,
    timeout: float,
    cancel: threading.Event,
    cwd: str | Path | None = None,
    env_extra: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Run an argument array with deadlines and bounded, continuously drained output.

    Delegates to the sandbox module which provides kernel-level isolation via
    gVisor/Kata Containers when running in K8s Jobs mode, or falls back to
    in-process execution with application-layer scope gating.
    """
    try:
        result: SandboxResult = run_in_sandbox(
            argv,
            timeout=timeout,
            cancel=cancel,
            cwd=cwd,
            env_extra=env_extra,
        )
    except SandboxTimeout as exc:
        raise AdapterTimeout(str(exc)) from exc
    except SandboxCancelled as exc:
        raise AdapterCancelled(str(exc)) from exc
    except SandboxOutputLimitExceeded as exc:
        raise AdapterError(str(exc)) from exc
    except SandboxUnavailable as exc:
        raise AdapterError(str(exc)) from exc
    except SandboxError as exc:
        raise AdapterError(str(exc)) from exc

    return result.returncode, result.stdout, result.stderr


class NmapAdapter(Adapter):
    """TCP connect discovery limited to explicitly authorized service ports.

    When the scope omits ``allowed_ports``, only the target URL's port is scanned.
    Discovery only: an open port is an observed fact, not a vulnerability verdict,
    and this adapter never attempts exploitation.
    """

    id = "nmap"
    asset_types = ("web", "host")
    requires = ("nmap",)

    def __init__(self) -> None:
        self._version: str | None = None

    def available(self) -> tuple[bool, str]:
        binary = shutil.which("nmap")
        if not binary:
            return False, "nmap not installed (apt install nmap)"
        if self._version is None:
            try:
                out = subprocess.run(
                    [binary, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env={"PATH": os.environ.get("PATH", "")},
                )
                self._version = out.stdout.splitlines()[0].strip() if out.stdout else "unknown"
            except (OSError, subprocess.SubprocessError) as exc:
                return False, f"nmap present but unusable: {exc}"
        return True, self._version

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        destination = checked_destination(target)
        parsed_target = parse_url(target)
        host = parsed_target.hostname if parsed_target else None
        if not host:
            raise AdapterError(f"no host in target {target}")
        ok, detail = self.available()
        if not ok:
            raise AdapterError(detail)

        active_scope = scope.active()
        argv = [shutil.which("nmap") or "nmap", "-sT", "-Pn", "-n"]
        engagement_rate = float((context or {}).get("rate_limit_rps") or 0)
        if engagement_rate > 0:
            # nmap's own rate control: packets per second, the closest exact
            # analogue to the RoE's requests-per-second ceiling.
            argv.extend(["--max-rate", str(max(1, int(engagement_rate)))])

        if ":" in destination.ip:
            argv.append("-6")
        if active_scope and active_scope.allowed_ports:
            argv.extend(
                [
                    "-p",
                    ",".join(str(port) for port in sorted(active_scope.allowed_ports)),
                ]
            )
        else:
            argv.extend(["-p", str(destination.port)])
        argv.extend(
            [
                "--host-timeout",
                f"{max(1, int(timeout))}s",
                "-oX",
                "-",
                "--",
                destination.ip,
            ]
        )
        code, stdout, stderr = _run_tool(argv, timeout=timeout, cancel=cancel)
        if code != 0:
            raise AdapterError(f"nmap exited {code}: {stderr.strip()[:200]}")

        result = AdapterResult()
        raw = stdout.encode() if isinstance(stdout, str) else stdout
        if re.search(rb"<!ENTITY|<!DOCTYPE[^>]*\[", raw, re.I):
            raise AdapterError("nmap output contains entity declarations; refusing to parse")
        try:
            root = safe_fromstring(stdout)
        except (ET.ParseError, DefusedXmlException) as exc:
            raise AdapterError(f"unparseable nmap XML: {type(exc).__name__}") from exc

        finished = root.find("./runstats/finished")
        if finished is not None and finished.get("errormsg"):
            raise AdapterError(f"nmap reported an error: {finished.get('errormsg', '')[:200]}")
        port_elements = list(root.iter("port"))
        if not port_elements:
            raise AdapterError("nmap XML contains no port results; the scan produced no coverage")

        result = AdapterResult()
        open_ports = 0
        unanswered: list[str] = []
        for port in port_elements:
            state = port.find("state")
            port_state = state.get("state", "") if state is not None else ""
            if port_state != "open":
                if port_state not in ("closed", ""):
                    unanswered.append(f"{port.get('portid', '?')}:{port_state}")
                continue
            open_ports += 1
            number = int(port.get("portid", "0"))
            protocol = port.get("protocol", "tcp")
            service = port.find("service")
            service_name = (service.get("name") if service is not None else "") or "unknown"
            product = (service.get("product") if service is not None else "") or ""
            version = (service.get("version") if service is not None else "") or ""
            banner = " ".join(part for part in (product, version) if part).strip()
            _risk_hint_severity, risk_note = RISKY_PORTS.get(number, ("info", ""))
            result.findings.append(
                Finding(
                    asset=host,
                    category="open_tcp_port",
                    title=f"Observed open {protocol}/{number} ({service_name})",
                    severity="info",
                    confidence="high",
                    detector=self.id,
                    detector_version=self._version or self.version,
                    evidence=(
                        f"nmap TCP connect scan reported {host}:{number}/{protocol} open"
                        f"{f' — service {banner}' if banner else ''}"
                        + (f" — {risk_note}" if risk_note else "")
                    ),
                    location=f"{host}:{number}/{protocol}",
                    description=(
                        "An exposed service was observed from the assessment host. "
                        "Port exposure alone does not prove insecure authentication "
                        "or a vulnerability."
                    ),
                    remediation=(
                        "Confirm this service is intended to be reachable from the assessment "
                        "network and verify its authentication and access-control configuration."
                    ),
                    verification="observed",
                )
            )
        scanned_ports = (
            f"authorized ports {','.join(str(p) for p in sorted(active_scope.allowed_ports))}"
            if active_scope and active_scope.allowed_ports
            else f"target URL port {destination.port}"
        )
        if unanswered:
            result.partial = True
            result.notes.append(
                f"nmap got no answer for {len(unanswered)} port(s) ({', '.join(unanswered[:10])})"
            )
        result.notes.append(f"nmap -sT {scanned_ports} on {host}: {open_ports} open")
        return result


class NucleiAdapter(Adapter):
    """Template-based web checks via nuclei (template ids), JSONL output.

    Runs with a fixed, non-destructive template set: no interactsh callbacks, no
    fuzzing templates, bounded rate/concurrency and a per-template timeout.
    """

    id = "nuclei"

    def _rate_limit(self, context: dict[str, Any] | None) -> int:
        """Nuclei requests/second: the RoE ceiling when it is stricter."""
        engagement_rate = float((context or {}).get("rate_limit_rps") or 0)
        if engagement_rate > 0:
            return max(1, min(self.RATE_LIMIT, int(engagement_rate)))
        return self.RATE_LIMIT

    asset_types = ("web",)
    requires = ("nuclei",)
    RATE_LIMIT = 25
    CONCURRENCY = 10
    SEVERITIES = "info,low,medium,high,critical"

    TEMPLATE_SUBSET: tuple[str, ...] = ("http/exposures",)

    def __init__(self) -> None:
        self._version: str | None = None

    def templates_dir(self) -> Path:
        """Where the official `nuclei -update-templates` install lives."""
        return Path(os.environ.get("HOME", "")) / "nuclei-templates"

    def available(self) -> tuple[bool, str]:
        binary = shutil.which("nuclei")
        if not binary:
            return (
                False,
                "nuclei not installed (https://github.com/projectdiscovery/nuclei)",
            )
        root = self.templates_dir()
        missing = [sub for sub in self.TEMPLATE_SUBSET if not (root / sub).is_dir()]
        if not root.is_dir():
            return (
                False,
                "nuclei-templates not installed (run: nuclei -update-templates)",
            )
        if missing:
            return False, (
                f"nuclei template subset missing: {', '.join(missing)} (run: nuclei -update-templates)"
            )
        if self._version is None:
            try:
                code, stdout, stderr = _run_tool([binary, "-version"], timeout=15.0, cancel=threading.Event())
            except (AdapterError, OSError) as exc:
                return False, f"nuclei present but unusable: {exc}"
            if code != 0:
                return False, f"nuclei present but unusable (exit {code})"

            blob = stdout + stderr
            self._version = next(
                (
                    line.split(":", 1)[1].strip()
                    for line in blob.splitlines()
                    if "version" in line.lower() and ":" in line
                ),
                "unknown",
            )
        return True, f"nuclei {self._version}"

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        destination = checked_destination(target)
        parsed_target = parse_url(target)
        if parsed_target is None or not parsed_target.hostname:
            raise AdapterError("invalid URL for nuclei")

        ip_literal = f"[{destination.ip}]" if ":" in destination.ip else destination.ip
        pinned_netloc = f"{ip_literal}:{destination.port}"
        pinned_target = parsed_target._replace(netloc=pinned_netloc).geturl()
        host_header = parsed_target.hostname
        if ":" in host_header and not host_header.startswith("["):
            host_header = f"[{host_header}]"
        if parsed_target.port is not None:
            host_header = f"{host_header}:{parsed_target.port}"
        ok, detail = self.available()
        if not ok:
            raise AdapterError(detail)

        argv = [
            shutil.which("nuclei") or "nuclei",
            "-u",
            pinned_target,
            "-H",
            f"Host: {host_header}",
            "-sni",
            parsed_target.hostname,
            "-dr",
            "-t",
            ",".join(str(self.templates_dir() / sub) for sub in self.TEMPLATE_SUBSET),
            "-jsonl",
            "-silent",
            "-no-color",
            "-no-interactsh",
            "-disable-update-check",
            "-severity",
            self.SEVERITIES,
            "-rate-limit",
            str(self._rate_limit(context)),
            "-concurrency",
            str(self.CONCURRENCY),
            "-timeout",
            str(max(1, int(timeout / 4))),
        ]
        code, stdout, stderr = _run_tool(argv, timeout=timeout, cancel=cancel)

        result = AdapterResult()
        parsed = 0
        skipped = 0
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            finding = self._normalize(payload, target)
            if finding is None:
                skipped += 1
            else:
                parsed += 1
                result.findings.append(finding)

        if parsed == 0 and skipped:
            raise AdapterError(f"nuclei produced {skipped} unparseable line(s), none usable")
        if code != 0 and not result.findings:
            raise AdapterError(f"nuclei exited {code}: {stderr.strip()[:200]}")
        if code != 0:
            result.notes.append(f"nuclei exited {code} after reporting results")
        if skipped:
            result.notes.append(f"{skipped} unparseable nuclei line(s) skipped")
        result.notes.append(
            f"nuclei {self._version}: {len(result.findings)} finding(s) "
            f"[template profile: {', '.join(self.TEMPLATE_SUBSET)}]"
        )
        return result

    def _normalize(self, payload: dict[str, Any], target: str) -> Finding | None:

        template = _bounded(payload.get("template-id") or payload.get("templateID"), 120)
        info = payload.get("info") or {}
        if not isinstance(info, dict):
            return None
        title = _bounded(info.get("name") or template, 200)
        if not template or not title:
            return None

        severity = str(info.get("severity", "info")).lower()
        if severity not in SEVERITIES:
            severity = "info"
        classification = info.get("classification") or {}
        cwe = classification.get("cwe-id") or ""
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else ""
        cwe = _bounded(cwe, 60)
        if cwe and re.fullmatch(r"\d+", cwe):
            cwe = f"CWE-{cwe}"
        matched_at = _bounded(payload.get("matched-at") or payload.get("host") or target, 500)

        return Finding(
            asset=target,
            category=template,
            title=title,
            severity=severity,
            confidence="high",
            detector=self.id,
            detector_version=self._version or "unknown",
            evidence=f"template {template} matched at {matched_at}",
            location=matched_at,
            description=_bounded(info.get("description") or "", 2000),
            remediation=_bounded(info.get("remediation"), 1000)
            or "Review the template findings and remediate the affected service.",
            cwe=cwe,
            verification="observed",
        )


class NiktoAdapter(Adapter):
    """Web server vulnerability scanner using Nikto.

    Runs a bounded scan against the authorized target host with conservative
    settings: no mutation tests, limited plugin set, and a hard timeout.
    Only reports findings from the target's scope; does not follow redirects
    outside the authorized destination.
    """

    id = "nikto"
    asset_types = ("web",)
    requires = ("nikto",)
    MAX_TIMEOUT = 300.0

    def __init__(self) -> None:
        self._version: str | None = None

    def available(self) -> tuple[bool, str]:
        binary = shutil.which("nikto")
        if not binary:
            return False, "nikto not installed (apt install nikto)"
        if self._version is None:
            try:
                out = subprocess.run(
                    [binary, "-Version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env={"PATH": os.environ.get("PATH", "")},
                )
                for line in out.stdout.splitlines() + out.stderr.splitlines():
                    if "nikto" in line.lower() and any(c.isdigit() for c in line):
                        self._version = line.strip()
                        break
                if not self._version:
                    self._version = "unknown"
            except (OSError, subprocess.SubprocessError) as exc:
                return False, f"nikto present but unusable: {exc}"
        return True, self._version

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        destination = checked_destination(target)
        parsed_target = parse_url(target)
        if parsed_target is None or not parsed_target.hostname:
            raise AdapterError(f"no host in target {target}")
        host = parsed_target.hostname
        port = destination.port
        ip_literal = f"[{destination.ip}]" if ":" in destination.ip else destination.ip
        host_header = f"[{host}]" if ":" in host and not host.startswith("[") else host
        if parsed_target.port is not None:
            host_header = f"{host_header}:{parsed_target.port}"

        ok, detail = self.available()
        if not ok:
            raise AdapterError(detail)

        argv = [
            shutil.which("nikto") or "nikto",
            "-nointeractive",
            "-host",
            ip_literal,
            "-vhost",
            host_header,
            "-port",
            str(port),
            "-Format",
            "json",
            "-Display",
            "V",
            "-Tuning",
            "012345789",
            "-timeout",
            str(int(timeout / 10)),
            "-maxtime",
            str(int(timeout)),
        ]
        if parsed_target and parsed_target.scheme == "https":
            argv.append("-ssl")

        code, stdout, stderr = _run_tool(argv, timeout=timeout, cancel=cancel)
        if code != 0 and not stdout.strip():
            raise AdapterError(f"nikto exited {code}: {stderr.strip()[:200]}")

        result = AdapterResult()
        try:
            data = json.loads(stdout)
            if not isinstance(data, list):
                data = []
        except json.JSONDecodeError:
            data = []

        for item in data:
            if not isinstance(item, dict):
                continue
            osvdb = str(item.get("OSVDB", "")) or ""
            plugin_id = str(item.get("id", "")) or ""
            msg = str(item.get("msg", "")) or ""
            uri = str(item.get("uri", "")) or ""
            _ = item.get("method", "")

            if not msg:
                continue

            msg_lower = msg.lower()
            high_kws = ("shell", "backdoor", "rce", "sql inject", "xss", "command injection")
            if any(kw in msg_lower for kw in high_kws):
                severity = "high"
            elif any(
                kw in msg_lower
                for kw in ("version", "header", "cookie", "dir", "backup", "config", "exposed", "disclos")
            ):
                severity = "medium"
            else:
                severity = "low"

            finding = Finding(
                asset=target,
                category=f"nikto-{plugin_id}" if plugin_id else "nikto-finding",
                title=_bounded(msg, 200),
                severity=severity,
                confidence="medium",
                detector=self.id,
                detector_version=self._version or self.version,
                evidence=f"nikto plugin {plugin_id}: {msg}" + (f" (OSVDB: {osvdb})" if osvdb else ""),
                location=f"{host}:{port}{uri}" if uri else f"{host}:{port}",
                description=_bounded(msg, 2000),
                remediation=(
                    "Review the web server configuration and apply vendor patches. "
                    "Validate the finding manually."
                ),
                cwe="",
                verification="inferred",
            )
            result.findings.append(finding)

        if not result.findings:
            result.notes.append("nikto scan completed with no findings")
        else:
            result.notes.append(f"nikto {self._version}: {len(result.findings)} finding(s) on {host}:{port}")
        return result


class SqlmapAdapter(Adapter):
    """SQL injection detection using sqlmap.

    Runs in read-only mode with conservative settings: boolean-based and
    time-based blind detection only, no exploitation, no file read/write,
    no OS command execution. Only targets parameters identified in-scope.
    """

    id = "sqlmap"
    asset_types = ("web", "api")
    requires = ("sqlmap",)
    MAX_TIMEOUT = 300.0

    def __init__(self) -> None:
        self._version: str | None = None

    def available(self) -> tuple[bool, str]:
        binary = shutil.which("sqlmap")
        if not binary:
            return False, "sqlmap not installed (apt install sqlmap)"
        if self._version is None:
            try:
                out = subprocess.run(
                    [binary, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env={"PATH": os.environ.get("PATH", "")},
                )
                for line in out.stdout.splitlines():
                    if line.strip() and any(c.isdigit() for c in line):
                        self._version = line.strip()
                        break
                if not self._version:
                    self._version = "unknown"
            except (OSError, subprocess.SubprocessError) as exc:
                return False, f"sqlmap present but unusable: {exc}"
        return True, self._version

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        destination = checked_destination(target)
        parsed_target = parse_url(target)
        if parsed_target is None or not parsed_target.query:
            raise AdapterNotApplicable("no query parameters available; sql injection testing is inconclusive")
        ip_literal = f"[{destination.ip}]" if ":" in destination.ip else destination.ip
        host_header = (
            f"[{parsed_target.hostname}]" if ":" in (parsed_target.hostname or "") else parsed_target.hostname
        )
        if parsed_target.port is not None:
            host_header = f"{host_header}:{parsed_target.port}"
        pinned_target = parsed_target._replace(netloc=f"{ip_literal}:{destination.port}").geturl()
        proxy = os.environ.get("ISHASTRA_SQLMAP_PROXY", "").strip()
        if parsed_target.scheme == "https" and not proxy:
            raise AdapterError(
                "SQLMap HTTPS requires ISHASTRA_SQLMAP_PROXY pointing at an egress proxy "
                "that preserves the target hostname and pins the authorized destination"
            )
        tool_target = target if proxy else pinned_target

        ok, detail = self.available()
        if not ok:
            raise AdapterError(detail)

        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            argv = [
                shutil.which("sqlmap") or "sqlmap",
                "-u",
                tool_target,
                "--host",
                host_header or "",
                "--ignore-redirects",
                "--batch",
                "--crawl",
                "0",
                "--level",
                "1",
                "--risk",
                "1",
                "--technique",
                "BT",
                "--timeout",
                str(max(5, int(timeout / 20))),
                "--retries",
                "0",
                "--output-dir",
                tmpdir,
                "--purge-output",
                "--disable-coloring",
                "--flush-session",
                "--fresh-queries",
            ]
            engagement_rate = float((context or {}).get("rate_limit_rps") or 0)
            if engagement_rate > 0:
                # Calculate delay respecting RoE rate limit with precision
                # SQLMap's --delay adds a pause between requests; use a floor of 0.1s
                # and cap at 10s to avoid excessively slow scans
                raw_delay = 1.0 / engagement_rate
                delay = max(0.1, min(raw_delay, 10.0))
                argv.extend(["--delay", f"{delay:.4f}"])

            if context and "auth_principal" in context and context["auth_principal"]:
                auth = context["auth_principal"]
                if auth.cookies:
                    cookie_str = "; ".join(f"{c.name}={c.value}" for c in auth.cookies)
                    argv.extend(["--cookie", cookie_str])
                if auth.headers:
                    for k, v in auth.headers.items():
                        argv.extend(["--header", f"{k}: {v}"])
                if auth.bearer:
                    argv.extend(["--header", f"Authorization: Bearer {auth.bearer}"])

            if proxy:
                argv.extend(["--proxy", proxy])

            code, stdout, stderr = _run_tool(argv, timeout=timeout, cancel=cancel)

        result = AdapterResult()

        lines = stdout.splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if "appears to be vulnerable" in line.lower() or "is vulnerable" in line.lower():
                param_match = re.search(r"parameter\s+'([^']+)'", line)
                param = param_match.group(1) if param_match else "unknown"

                finding = Finding(
                    asset=target,
                    category="sql_injection",
                    title=f"Potential SQL injection in parameter '{param}'",
                    severity="high",
                    confidence="medium",
                    detector=self.id,
                    detector_version=self._version or self.version,
                    evidence=line,
                    location=target,
                    description=(
                        "sqlmap detected a potential SQL injection vector. This is a "
                        "detection indicator; manual verification is required before "
                        "remediation."
                    ),
                    remediation=(
                        "Use parameterized queries / prepared statements. Validate and "
                        "sanitize all user inputs. Implement a Web Application Firewall."
                    ),
                    cwe="CWE-89",
                    verification="inferred",
                )
                result.findings.append(finding)

        if not result.findings:
            result.notes.append("sqlmap scan completed with no injection indicators found")
        else:
            result.notes.append(
                f"sqlmap {self._version}: {len(result.findings)} potential injection indicator(s)"
            )
        return result


ADAPTER_PLUGIN_GROUP = "ishastra.adapters"


def _load_plugin_adapters() -> dict[str, Adapter]:
    """Adapters published by installed packages in the ``ishastra.adapters`` group.

    A plugin may add an adapter but never replace a built-in id: a typo or a
    hostile package must not silently change what an existing profile runs.
    """
    from importlib.metadata import entry_points

    logger = logging.getLogger(__name__)
    enabled = os.environ.get("ISHASTRA_ALLOW_PLUGINS", "").strip().lower()
    if enabled not in {"1", "true", "yes"}:
        return {}
    loaded: dict[str, Adapter] = {}
    for entry in entry_points(group=ADAPTER_PLUGIN_GROUP):
        try:
            candidate = entry.load()
            adapter = candidate() if isinstance(candidate, type) else candidate
        except Exception:
            logger.exception("adapter plugin %r failed to load; ignoring it", entry.name)
            continue
        adapter_id = getattr(adapter, "id", None)
        if not isinstance(adapter_id, str) or not adapter_id.strip():
            logger.warning("adapter plugin %r exposes no string id; ignoring it", entry.name)
            continue
        if adapter_id in ADAPTERS:
            logger.warning("adapter plugin %r reuses built-in id %r; built-in wins", entry.name, adapter_id)
            continue
        loaded[adapter_id] = adapter
    return loaded


_BUILTIN_ADAPTERS: tuple[Adapter, ...] = (
    HTTPAdapter(),
    CrawlerAdapter(),
    DynamicValidationAdapter(),
    OpenAPIAdapter(),
    AuthorizationDiffAdapter(),
    SSRFOOBAdapter(),
    GitExposureAdapter(),
    TCPPortAdapter(),
    NmapAdapter(),
    NucleiAdapter(),
    NiktoAdapter(),
    SqlmapAdapter(),
)

ADAPTERS: dict[str, Adapter] = {a.id: a for a in _BUILTIN_ADAPTERS}
ADAPTERS.update(_load_plugin_adapters())

_PLUGIN_ADAPTER_IDS = tuple(sorted(set(ADAPTERS) - {a.id for a in _BUILTIN_ADAPTERS}))


PROFILES: dict[str, tuple[str, ...]] = {
    "web": ("ishastra-http", "ishastra-git-exposure"),
    "web-crawl": ("ishastra-crawl", "ishastra-http", "ishastra-git-exposure"),
    "web-deep": (
        "ishastra-crawl",
        "ishastra-http",
        "ishastra-dynamic-validation",
        "ishastra-git-exposure",
        "nuclei",
        "nikto",
    ),
    "web-full": (
        "ishastra-crawl",
        "ishastra-http",
        "ishastra-dynamic-validation",
        "ishastra-git-exposure",
        "nuclei",
        "nikto",
        "sqlmap",
    ),
    "api": ("ishastra-http", "ishastra-openapi", "ishastra-git-exposure"),
    "api-deep": (
        "ishastra-crawl",
        "ishastra-http",
        "ishastra-openapi",
        "ishastra-authz",
        "ishastra-ssrf-oob",
        "ishastra-dynamic-validation",
        "ishastra-git-exposure",
        "nuclei",
    ),
    "api-full": (
        "ishastra-crawl",
        "ishastra-http",
        "ishastra-openapi",
        "ishastra-authz",
        "ishastra-ssrf-oob",
        "ishastra-dynamic-validation",
        "ishastra-git-exposure",
        "nuclei",
        "nikto",
        "sqlmap",
    ),
    "ports": ("ishastra-tcp", "nmap"),
    "network": ("ishastra-http", "ishastra-tcp", "nmap", "ishastra-git-exposure"),
}

if _PLUGIN_ADAPTER_IDS:
    PROFILES["plugins"] = _PLUGIN_ADAPTER_IDS


def select(profile: str) -> list[Adapter]:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; choose from {sorted(PROFILES)}")
    return [ADAPTERS[name] for name in PROFILES[profile]]

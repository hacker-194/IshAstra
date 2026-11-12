"""Scanner adapter framework: one capability, one tool, availability as it ran.

Every adapter re-checks the scope gate itself, and external tools run as
argument arrays with a minimal environment, a hard deadline and a kill switch.
Nmap receives the validated destination IP; Nuclei receives it too, with the
original Host header and TLS SNI preserved and redirects disabled. Keep
host-level egress filtering on as a second layer if you customize templates.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring as safe_fromstring

from strix import __version__
from strix.core import scope

# Re-exported so existing callers (jobs, tests, plugins) keep importing the
# primitives from this module, while detector modules import the base directly.
from strix.core.adapter_base import (
    Adapter,
    AdapterCancelled,
    AdapterError,
    AdapterNotApplicable,
    AdapterResult,
    AdapterTimeout,
    checked_destination,  # noqa: F401
)
from strix.core.authz import (
    AuthConfig,
    DifferentialResult,
    Principal,
    body_digest,
    candidate_endpoints,
    classify,
)
from strix.core.collab import (
    CollabClient,
    CollabConfig,
    CollabServer,
    new_token,
    shared_inprocess_server,
)
from strix.core.crawler import MAX_PAGES as CRAWL_MAX_PAGES
from strix.core.crawler import WebCrawler
from strix.core.exposure import GitExposureAdapter
from strix.core.findings import SEVERITIES, Finding
from strix.core.ports import RISKY_PORTS, TCPPortAdapter
from strix.core.probe import EndpointProbe
from strix.core.signatures import match_url_signatures
from strix.core.urls import parse_url

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Built-in HTTP assessment (always available, no external binary)
# ---------------------------------------------------------------------------
WEB_CHECKS: dict[str, tuple[str, str, str, str]] = {
    # category: (severity, title, cwe, remediation). URL signatures and marker
    # reflections are deliberately informational and unverified, not confirmed
    # vulnerability findings.
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

_URL_INDICATORS = frozenset(
    {"sqli", "xss", "open_redirect", "path_traversal", "ssrf", "secret"}
)


class HTTPAdapter(Adapter):
    """Existing Strix DAST + probe engine, normalized into findings."""

    id = "strix-http"
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

        started = time.monotonic()
        deadline = started + max(0.05, timeout)
        result = AdapterResult()
        # Probe timeout must be shorter than overall deadline to leave headroom
        probe = EndpointProbe(timeout=min(timeout * 0.8, 8.0))

        response = probe.probe(target, deadline=deadline)
        if cancel.is_set():
            raise AdapterCancelled("cancelled during HTTP probe")
        if time.monotonic() >= deadline:
            raise AdapterTimeout(
                "HTTP assessment deadline exhausted during initial probe"
            )

        reflected = probe.reflections(target, cancel=cancel, deadline=deadline)
        if cancel.is_set():
            raise AdapterCancelled("cancelled during reflection checks")
        if time.monotonic() > deadline:
            raise AdapterTimeout(
                "HTTP assessment deadline exhausted during reflection checks"
            )
        self._observe(target, response, result, reflected=reflected, notes=result.notes)

        # Crawler hand-off: pages discovered in-scope get the same probe-level
        # checks (headers, signatures, redirect judgment). Reflection tests stay
        # on the primary target so the deadline cannot be eaten by a large site.
        discovered = list((context or {}).get("discovered_urls") or [])
        for url in discovered[: self.MAX_DISCOVERED_PROBES]:
            if cancel.is_set():
                raise AdapterCancelled("cancelled during discovered-page probes")
            if time.monotonic() >= deadline:
                result.notes.append(
                    "deadline reached before every discovered page was probed"
                )
                break
            if url == target:
                continue
            page_denial, _page_reason = scope.check(url)
            if page_denial:  # crawler output is untrusted input at this boundary
                continue
            page_response = probe.probe(url, deadline=deadline)
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
            # HSTS only applies to HTTPS responses; a missing header on plain
            # HTTP is not a meaningful HSTS finding.
            if (
                parsed_url
                and parsed_url.scheme == "https"
                and not headers.get("strict-transport-security")
            ):
                observed["missing_hsts"] = (
                    f"HTTPS response {response['status']} carries no Strict-Transport-Security header"
                )
            notes.append(f"HTTP {response['status']} from {url}")
        else:
            # A refused or failed connection is not a clean result.
            notes.append(
                f"no HTTP response ({response.get('status')}: "
                f"{response.get('reason') or response.get('error') or 'unknown'})"
            )

        if response.get("redirect_to"):
            scope_note = (
                "in-scope" if response.get("redirect_in_scope") else "out-of-scope"
            )
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
            is_indicator = (
                category in _URL_INDICATORS or category == "xss" and bool(reflected)
            )
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

    id = "strix-dynamic-validation"
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
        probe = EndpointProbe(timeout=min(5.0, timeout))
        result = AdapterResult()
        redirects = probe.redirect_tests(target, cancel=cancel, deadline=deadline)
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
                    evidence=str(
                        item.get("evidence") or "External redirect canary observed"
                    ),
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
                target, cancel=cancel, deadline=deadline
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
                        evidence=str(
                            item.get("evidence") or "Database error signature observed"
                        ),
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
    probed, without credentials, and only with GET. A success is reported as an
    authorization mismatch indicator (unverified) because OpenAPI documents can
    be stale or endpoint access may be intentionally public.
    """

    id = "strix-openapi"
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
        if parsed_target.path.lower().endswith(
            ("openapi.json", "swagger.json", "api-docs")
        ):
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
        probe = EndpointProbe(timeout=min(5.0, timeout), max_body=self.MAX_SPEC_BYTES)
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
            response = probe._fetch(candidate, deadline=deadline)
            body = response.get("body", "")
            if (
                not isinstance(body, str)
                or not body
                or not isinstance(response.get("status"), int)
            ):
                continue
            if not 200 <= int(response["status"]) < 300:
                continue
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and (
                isinstance(payload.get("paths"), dict)
                and (payload.get("openapi") or payload.get("swagger"))
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
                if not isinstance(server, dict) or not isinstance(
                    server.get("url"), str
                ):
                    continue
                raw_server = server["url"].strip()
                if "{" in raw_server or "}" in raw_server:
                    continue
                absolute = urljoin(spec_url, raw_server)
                server_parsed = urlparse(absolute)
                target_parsed = urlparse(origin)
                server_port = server_parsed.port or (
                    443 if server_parsed.scheme == "https" else 80
                )
                target_port = target_parsed.port or (
                    443 if target_parsed.scheme == "https" else 80
                )
                if (
                    server_parsed.scheme in {"http", "https"}
                    and (server_parsed.hostname or "").lower()
                    == (target_parsed.hostname or "").lower()
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
            if (
                not isinstance(path, str)
                or not path.startswith("/")
                or "{" in path
                or "}" in path
            ):
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
            response = probe._fetch(endpoint, deadline=deadline)
            status_code = response.get("status")
            if isinstance(status_code, int) and 200 <= status_code < 300:
                result.findings.append(
                    Finding(
                        asset=target,
                        category="api_documented_auth_mismatch",
                        title="Endpoint documented as protected responded successfully without credentials",
                        severity="medium",
                        confidence="medium",
                        detector=self.id,
                        detector_version=self.version,
                        evidence=(
                            f"OpenAPI declares security for GET {path}; unauthenticated request "
                            f"returned HTTP {status_code}. No credentials were sent and response "
                            "content was not retained."
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
                result.notes.append(
                    f"OpenAPI endpoint limit ({self.MAX_ENDPOINTS}) reached"
                )
                break
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        result.notes.append(
            f"OpenAPI checked {endpoints_checked} documented protected GET endpoint(s)"
        )
        return result


class CrawlerAdapter(Adapter):
    """Bounded, same-origin crawl that publishes in-scope URLs to later adapters.

    This adapter produces no findings by itself: discovery is not a verdict.
    Discovered URLs are written to ``context["discovered_urls"]`` where the HTTP
    assessment adapter picks them up; both halves stay scope-gated so crawler
    output can never widen the engagement.
    """

    id = "strix-crawl"
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
        crawler = WebCrawler(max_pages=CRAWL_MAX_PAGES)
        crawl = crawler.crawl(target, deadline=deadline, cancel=cancel)
        result = AdapterResult()
        result.notes.extend(
            crawl.notes or [f"crawl completed: {len(crawl.pages)} page(s)"]
        )
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

    id = "strix-authz"
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
            return False, (
                "no test principals configured "
                "(add auth.users to the scope document)"
            )
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
            pool.extend(
                url for url in context.get("discovered_urls", []) if url != target
            )
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
            f"authorization differences checked on {checked} endpoint(s) with "
            f"{len(auth.users)} principal(s)"
        )
        return result

    def _fetch_as(
        self, url: str, principal: Principal | None
    ) -> tuple[str, int | str, str]:
        response = self._probe._fetch(url, auth=principal)
        status = response.get("status")
        status = status if isinstance(status, (int, str)) else "error"
        body = response.get("body", "") if isinstance(response.get("body"), str) else ""
        return (
            principal.id if principal else "anonymous",
            status,
            body_digest(body[: self.MAX_BODY_FOR_DIGEST]),
        )

    def _finding(
        self, category: str, endpoint: str, differential: DifferentialResult
    ) -> Finding:
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

    id = "strix-ssrf-oob"
    version = __version__
    asset_types = ("web", "api")
    MAX_PARAMS = 6
    POLL_ATTEMPTS = 6
    POLL_INTERVAL = 0.4
    # `page` and `q` are deliberately absent: pagination and search outrank
    # them as interpretations, and a wrong injection wastes the canary budget.
    SSRF_PARAM = re.compile(
        r"^(?:url|uri|fetch|source|src|dest|destination|redirect|next|target|host|"
        r"domain|proxy|callback|feed|img|image|file|path|resource|load|read|include|"
        r"data|site|html)$",
        re.IGNORECASE,
    )
    CANARY_MARKER = "strix-canary"

    def __init__(self) -> None:
        self._probe = EndpointProbe(timeout=6.0)

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
                "no out-of-band listener configured "
                "(add collab.host/collab.port to the scope document)"
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
            pool.extend(
                url for url in context.get("discovered_urls", []) if url != target
            )
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
            token = new_token()
            canary = f"{canary_base}/{token}"
            finding = self._probe_param(
                url, param, canary, token, listener, cancel=cancel, deadline=deadline
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
                    break  # one canary per URL is enough; keep the budget
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
    ) -> Finding | None:
        marked = self._inject(url, param, canary)
        response = self._probe._fetch(marked, deadline=deadline)
        body = response.get("body", "") if isinstance(response.get("body"), str) else ""
        in_band = canary in body or canary in str(response.get("redirect_to") or "")

        callbacks: list[dict[str, Any]] = []
        poll = listener.poll  # CollabServer and CollabClient expose the same shape
        for _attempt in range(self.POLL_ATTEMPTS):
            if cancel.is_set():
                raise AdapterCancelled("cancelled while polling the collab listener")
            try:
                callbacks = poll(token)
            except AdapterError:
                raise
            except Exception:  # a failed poll is retried, then given up quietly
                callbacks = []
            if callbacks:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(self.POLL_INTERVAL, remaining))
        if not callbacks:
            if in_band:  # reflected without callback: still meaningful, weaker
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
            category=(
                "ssrf_confirmed_oob"
                if callback is not None
                else "ssrf_inband_reflection"
            ),
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


# ---------------------------------------------------------------------------
# nmap discovery (external binary, distinct from vulnerability assessment)
# ---------------------------------------------------------------------------
# RISKY_PORTS lives in strix.core.ports, shared with the native TCP detector.

MAX_TOOL_OUTPUT_BYTES = 16 * 1024 * 1024


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _bounded(value: Any, limit: int) -> str:
    """Untrusted tool/template text reduced to a bounded printable string."""
    if not isinstance(value, str):
        return ""
    return _CONTROL_CHARS.sub("", value).strip()[:limit]


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the tool and everything it spawned.

    External scanners fork workers. Killing only the parent leaves children
    holding the output pipes (so the drain threads never finish) and, worse,
    still scanning after the job reported it stopped. The child is started in
    its own session, so its process group id equals its pid.
    """
    killpg = getattr(os, "killpg", None)  # POSIX only; absent on Windows
    if killpg is not None:
        with contextlib.suppress(OSError):
            killpg(proc.pid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        proc.kill()


def _run_tool(
    argv: list[str],
    *,
    timeout: float,
    cancel: threading.Event,
    cwd: str | Path | None = None,
    env_extra: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Run an argument array with deadlines and bounded, continuously drained output.

    Reading stdout/stderr only after process exit can deadlock when a child fills
    an OS pipe buffer. Dedicated drainers avoid that deadlock; each stream is
    capped, and excess output terminates the tool instead of exhausting memory.

    ``env_extra`` are individually named additions to the minimal environment
    (a tool that needs its own provider variables); the platform's environment
    is never passed through wholesale. ``cwd`` exists because some tools write
    their results relative to the working directory (strix-agent writes
    ``strix_runs/`` there).
    """
    if cancel.is_set():
        raise AdapterCancelled(f"{Path(argv[0]).name} cancelled before start")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "LC_ALL": "C",
        "HOME": os.environ.get("HOME", ""),
    }
    if env_extra:
        env.update(env_extra)
    try:
        # stdin is pinned to /dev/null: some tools (nuclei) read target URLs
        # from stdin when it is open, which otherwise parks them forever.
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=False,
            env=env,
            cwd=str(cwd) if cwd is not None else None,
            # Own session/process group: see _kill_tree.
            start_new_session=True,
        )
    except OSError as exc:
        log.warning("cannot execute %s: %s", argv[0], exc)  # detail stays server-side
        raise AdapterError(f"cannot execute {Path(argv[0]).name}") from exc

    captured: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    sizes = {"stdout": 0, "stderr": 0}
    overflow = {"stdout": False, "stderr": False}

    def drain(channel: str, pipe) -> None:
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
            # Killed processes may close their file descriptors during teardown.
            pass
        finally:
            with contextlib.suppress(OSError):
                pipe.close()

    assert proc.stdout is not None and proc.stderr is not None
    out_thread = threading.Thread(
        target=drain,
        args=("stdout", proc.stdout),
        daemon=True,
        name="strix-tool-stdout",
    )
    err_thread = threading.Thread(
        target=drain,
        args=("stderr", proc.stderr),
        daemon=True,
        name="strix-tool-stderr",
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
        raise AdapterCancelled(f"{Path(argv[0]).name} cancelled")
    if failure == "timeout":
        raise AdapterTimeout(f"{Path(argv[0]).name} exceeded {timeout:g}s")
    if failure == "output_limit" or overflow["stdout"] or overflow["stderr"]:
        raise AdapterError(
            f"{Path(argv[0]).name} output exceeded {MAX_TOOL_OUTPUT_BYTES} bytes per stream"
        )
    if out_thread.is_alive() or err_thread.is_alive():
        raise AdapterError(f"{Path(argv[0]).name} output streams did not close")

    stdout = b"".join(captured["stdout"]).decode("utf-8", errors="replace")
    stderr = b"".join(captured["stderr"]).decode("utf-8", errors="replace")
    return proc.returncode, stdout, stderr


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
                self._version = (
                    out.stdout.splitlines()[0].strip() if out.stdout else "unknown"
                )
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
        if active_scope and active_scope.allowed_ports:
            # Honor an explicitly restricted engagement scope; do not widen it
            # to the conventional top-ports list.
            argv.extend(
                [
                    "-p",
                    ",".join(str(port) for port in sorted(active_scope.allowed_ports)),
                ]
            )
        else:
            # A hostname authorization plus a URL is not blanket permission to
            # probe unrelated services. Without an explicit allowlist, limit
            # discovery to the exact port named by the authorized target URL.
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
        )  # IP is pinned after scope validation
        code, stdout, stderr = _run_tool(argv, timeout=timeout, cancel=cancel)
        if code != 0:
            raise AdapterError(f"nmap exited {code}: {stderr.strip()[:200]}")

        result = AdapterResult()
        raw = stdout.encode() if isinstance(stdout, str) else stdout
        if re.search(rb"<!ENTITY|<!DOCTYPE[^>]*\[", raw, re.I):
            raise AdapterError(
                "nmap output contains entity declarations; refusing to parse"
            )
        try:
            root = safe_fromstring(
                stdout
            )  # defusedxml: no DTDs, entities or external refs
        except (ET.ParseError, DefusedXmlException) as exc:
            raise AdapterError(f"unparseable nmap XML: {type(exc).__name__}") from exc

        # A scanner that returns XML without results (truncated output, refused
        # scan, nmap error) must not be scored as "nothing open".
        finished = root.find("./runstats/finished")
        if finished is not None and finished.get("errormsg"):
            raise AdapterError(
                f"nmap reported an error: {finished.get('errormsg', '')[:200]}"
            )
        port_elements = list(root.iter("port"))
        if not port_elements:
            raise AdapterError(
                "nmap XML contains no port results; the scan produced no coverage"
            )

        result = AdapterResult()
        open_ports = 0
        unanswered: list[str] = []
        for port in port_elements:
            state = port.find("state")
            port_state = state.get("state", "") if state is not None else ""
            if port_state != "open":
                # closed = a refusal we can trust; filtered/unresolved = no answer.
                if port_state not in ("closed", ""):
                    unanswered.append(f"{port.get('portid', '?')}:{port_state}")
                continue
            open_ports += 1
            number = int(port.get("portid", "0"))
            protocol = port.get("protocol", "tcp")
            service = port.find("service")
            service_name = (
                service.get("name") if service is not None else ""
            ) or "unknown"
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
            # A filtered port is not a closed port: nmap got no answer, so the
            # job cannot claim that surface was assessed.
            result.partial = True
            result.notes.append(
                "nmap got no answer for "
                f"{len(unanswered)} port(s) ({', '.join(unanswered[:10])})"
            )
        result.notes.append(f"nmap -sT {scanned_ports} on {host}: {open_ports} open")
        return result


class NucleiAdapter(Adapter):
    """Template-based web checks via nuclei (template ids), JSONL output.

    Runs with a fixed, non-destructive template set: no interactsh callbacks, no
    fuzzing templates, bounded rate/concurrency and a per-template timeout.
    """

    id = "nuclei"
    asset_types = ("web",)
    requires = ("nuclei",)
    RATE_LIMIT = 25
    CONCURRENCY = 10
    SEVERITIES = "info,low,medium,high,critical"

    # Bounded by design, measured against the real binary: the full default
    # sweep is 13k+ requests (≈9 minutes at the conservative 25 req/s — no job
    # deadline survives it), while this subset is ~1.9k requests (≈65s at
    # 25 req/s) and covers exposed credentials, configs, backups and repos.
    # Fixed subset for every job; a per-profile table (exposures / vulns / cves)
    # with matching rate and deadline budgets would be the next step.
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
                "nuclei template subset missing: "
                f"{', '.join(missing)} (run: nuclei -update-templates)"
            )
        if self._version is None:
            try:
                code, stdout, stderr = _run_tool(
                    [binary, "-version"], timeout=15.0, cancel=threading.Event()
                )
            except (AdapterError, OSError) as exc:
                return False, f"nuclei present but unusable: {exc}"
            if code != 0:
                return False, f"nuclei present but unusable (exit {code})"
            # The engine prints its version banner on stderr, not stdout
            # (verified against the real binary).
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
        # Pin the URL hostname to the validated IP. Preserve the original
        # virtual-host header and TLS SNI for name-based hosting, and disable
        # redirects so the tool cannot silently leave the authorized endpoint.
        ip_literal = f"[{destination.ip}]" if ":" in destination.ip else destination.ip
        pinned_netloc = f"{ip_literal}:{destination.port}"
        pinned_target = parsed_target._replace(netloc=pinned_netloc).geturl()
        host_header = parsed_target.hostname
        if ":" in host_header and not host_header.startswith("["):
            host_header = f"[{host_header}]"  # IPv6 literals must be bracketed in Host
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
            "-dr",  # external redirects are never followed by a scanner
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
            str(self.RATE_LIMIT),
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
            raise AdapterError(
                f"nuclei produced {skipped} unparseable line(s), none usable"
            )
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
        # Every string here comes from a template file and a remote response;
        # it is bounded and stripped of control characters before it becomes a
        # finding (the same rule the AI analyst applies to untrusted text).
        template = _bounded(
            payload.get("template-id") or payload.get("templateID"), 120
        )
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
            cwe = f"CWE-{cwe}"  # templates may carry the bare number
        matched_at = _bounded(
            payload.get("matched-at") or payload.get("host") or target, 500
        )

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


ADAPTERS: dict[str, Adapter] = {
    a.id: a
    for a in (
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
    )
}
# Every profile includes the built-in git-exposure check: it is two bounded
# requests and the only exposure class that is detectable without an external
# tool, so leaving it out of a default profile would be a self-inflicted blind
# spot. "ports" runs the native TCP scan and nmap together; the findings
# de-duplicate on (asset, category, location), so an nmap-equipped deployment
# gains nmap's service banners without losing the native fallback.
PROFILES: dict[str, tuple[str, ...]] = {
    "web": ("strix-http", "strix-git-exposure"),
    "web-crawl": ("strix-crawl", "strix-http", "strix-git-exposure"),
    "web-deep": (
        "strix-crawl",
        "strix-http",
        "strix-dynamic-validation",
        "strix-git-exposure",
        "nuclei",
    ),
    "api": ("strix-http", "strix-openapi", "strix-git-exposure"),
    "api-deep": (
        "strix-crawl",
        "strix-http",
        "strix-openapi",
        "strix-authz",
        "strix-ssrf-oob",
        "strix-dynamic-validation",
        "strix-git-exposure",
        "nuclei",
    ),
    "ports": ("strix-tcp", "nmap"),
    "network": ("strix-http", "strix-tcp", "nmap", "strix-git-exposure"),
}


def select(profile: str) -> list[Adapter]:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; choose from {sorted(PROFILES)}")
    return [ADAPTERS[name] for name in PROFILES[profile]]

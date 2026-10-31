"""Scanner adapter framework: one capability, one tool, availability as it ran.

Every adapter re-checks the scope gate itself, and external tools run as
argument arrays with a minimal environment, a hard deadline and a kill switch.
Nmap receives the validated destination IP; Nuclei receives it too, with the
original Host header and TLS SNI preserved and redirects disabled. Keep
host-level egress filtering on as a second layer if you customize templates.
"""
from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import ParseResult, urljoin, urlparse

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
from strix.core.collab import CollabClient, CollabConfig, CollabServer, new_token, shared_inprocess_server
from strix.core.crawler import MAX_PAGES as CRAWL_MAX_PAGES
from strix.core.crawler import WebCrawler
from strix.core.exposure import GitExposureAdapter
from strix.core.findings import CONFIDENCES, SEVERITIES, Finding
from strix.core.ports import RISKY_PORTS, TCPPortAdapter
from strix.core.probe import EndpointProbe
from strix.core.signatures import match_url_signatures
from strix.core.urls import parse_url

log = logging.getLogger(__name__)

AGENT_VERSION = __version__


# ---------------------------------------------------------------------------
# Built-in HTTP assessment (always available, no external binary)
# ---------------------------------------------------------------------------
WEB_CHECKS: dict[str, tuple[str, str, str, str]] = {
    # category: (severity, title, cwe, remediation). URL signatures and marker
    # reflections are deliberately informational and unverified, not confirmed
    # vulnerability findings.
    "sqli": ("info", "Potential SQL injection indicator in request target", "CWE-89",
             "Review server-side query construction; use parameterized queries."),
    "xss": ("info", "Potential XSS indicator; execution context unverified", "CWE-79",
            "Inspect the response context and apply context-aware output encoding."),
    "open_redirect": ("info", "Potential redirect-parameter indicator", "CWE-601",
                      "Verify whether user-controlled input can select an external destination."),
    "path_traversal": ("info", "Potential path-traversal indicator in request target", "CWE-22",
                       "Verify server-side path handling and confine paths to an authorized root."),
    "ssrf": ("info", "Potential SSRF indicator in request target", "CWE-918",
             "Verify server-side destination handling and enforce outbound destination allowlists."),
    "secret": ("info", "Credential-shaped text in request target", "CWE-798",
               "Do not put credentials in URLs; rotate any credential confirmed to be exposed."),
    "missing_csp": ("low", "Missing Content-Security-Policy header", "CWE-693",
                    "Send a restrictive Content-Security-Policy header where appropriate."),
    "missing_hsts": ("low", "Missing Strict-Transport-Security header", "CWE-319",
                     "Send HSTS on HTTPS responses once HTTPS is enforced."),
}

_URL_INDICATORS = frozenset({"sqli", "xss", "open_redirect", "path_traversal", "ssrf", "secret"})


class HTTPAdapter(Adapter):
    """Existing Strix DAST + probe engine, normalized into findings."""

    id = "strix-http"
    version = AGENT_VERSION
    asset_types = ("web",)

    MAX_DISCOVERED_PROBES = 10

    def assess(self, target: str, *, timeout: float,
               cancel: threading.Event,
               context: dict[str, Any] | None = None) -> AdapterResult:
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
            raise AdapterTimeout("HTTP assessment deadline exhausted during initial probe")

        reflected = probe.reflections(target, cancel=cancel, deadline=deadline)
        if cancel.is_set():
            raise AdapterCancelled("cancelled during reflection checks")
        if time.monotonic() > deadline:
            raise AdapterTimeout("HTTP assessment deadline exhausted during reflection checks")
        self._observe(target, response, result, reflected=reflected, notes=result.notes)

        # Crawler hand-off: pages discovered in-scope get the same probe-level
        # checks (headers, signatures, redirect judgment). Reflection tests stay
        # on the primary target so the deadline cannot be eaten by a large site.
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
            if page_denial:  # crawler output is untrusted input at this boundary
                continue
            page_response = probe.probe(url, deadline=deadline)
            self._observe(url, page_response, result, reflected=(), notes=result.notes)
        if len(discovered) > self.MAX_DISCOVERED_PROBES:
            result.notes.append(
                f"{len(discovered) - self.MAX_DISCOVERED_PROBES} discovered page(s) "
                "beyond the probe budget were not fetched")
        return result

    def _observe(self, url: str, response: dict[str, Any], result: AdapterResult, *,
                 reflected: tuple[dict[str, Any], ...] | list[dict[str, Any]],
                 notes: list[str]) -> None:
        """Turn one HTTP response into observations (never into verdicts)."""
        observed: dict[str, str] = {}
        for name in match_url_signatures(url):
            observed[name] = (
                "request-target signature matched; this is an indicator only and "
                "does not establish that the server is vulnerable")
        headers = response.get("headers", {})
        parsed_url = parse_url(url)
        if isinstance(response.get("status"), int):
            if not headers.get("content-security-policy"):
                observed["missing_csp"] = (
                    f"HTTP {response['status']} response carries no Content-Security-Policy header")
            # HSTS only applies to HTTPS responses; a missing header on plain
            # HTTP is not a meaningful HSTS finding.
            if parsed_url and parsed_url.scheme == "https" and not headers.get(
                    "strict-transport-security"):
                observed["missing_hsts"] = (
                    f"HTTPS response {response['status']} carries no Strict-Transport-Security header")
            notes.append(f"HTTP {response['status']} from {url}")
        else:
            # A refused or failed connection is not a clean result.
            notes.append(
                f"no HTTP response ({response.get('status')}: "
                f"{response.get('reason') or response.get('error') or 'unknown'})")

        if response.get("redirect_to"):
            scope_note = "in-scope" if response.get("redirect_in_scope") else "out-of-scope"
            notes.append(
                f"HTTP redirect observed to {response['redirect_to']} ({scope_note}); "
                "redirects are not followed and are not classified as vulnerabilities by themselves")

        if reflected:
            parameters = ", ".join(sorted({str(hit["parameter"]) for hit in reflected}))
            observed["xss"] = (
                f"benign marker reflected for parameter(s): {parameters}; "
                "HTML/JavaScript execution context was not tested")

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
            result.findings.append(Finding(
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
            ))


class DynamicValidationAdapter(Adapter):
    """Low-impact validation of redirect and database-error indicators.

    This adapter sends only bounded GET requests using existing query
    parameters. Redirect canaries use the reserved .invalid TLD and redirects
    are never followed. It does not extract data or send state-changing payloads.
    """

    id = "strix-dynamic-validation"
    version = AGENT_VERSION
    asset_types = ("web",)
    MAX_TIMEOUT = 20.0

    def assess(self, target: str, *, timeout: float,
               cancel: threading.Event,
               context: dict[str, Any] | None = None) -> AdapterResult:
        destination = checked_destination(target)
        parsed_target = parse_url(target)
        if parsed_target is None or not parsed_target.query:
            raise AdapterNotApplicable(
                "no query parameters available; dynamic input validation is inconclusive")
        deadline = time.monotonic() + min(max(0.05, timeout), self.MAX_TIMEOUT)
        probe = EndpointProbe(timeout=min(5.0, timeout))
        result = AdapterResult()
        redirects = probe.redirect_tests(target, cancel=cancel, deadline=deadline)
        if cancel.is_set():
            raise AdapterCancelled("cancelled during redirect validation")
        for item in redirects:
            result.findings.append(Finding(
                asset=target,
                category="open_redirect",
                title="Query parameter controls an external redirect destination",
                severity="medium",
                confidence="high",
                detector=self.id,
                detector_version=self.version,
                evidence=str(item.get("evidence") or "External redirect canary observed"),
                location=str(item.get("request_url") or target),
                description=("The server returned a Location destination matching a unique "
                             "reserved .invalid canary supplied through a query parameter. "
                             "The redirect was not followed."),
                remediation=("Validate redirect destinations against an exact allowlist of "
                             "approved URLs or hostnames; reject arbitrary external destinations."),
                cwe="CWE-601",
                verification="observed",
            ))
        if time.monotonic() < deadline and not cancel.is_set():
            sql_indicators = probe.database_error_tests(
                target, cancel=cancel, deadline=deadline)
            for item in sql_indicators:
                result.findings.append(Finding(
                    asset=target,
                    category="sqli_error_indicator",
                    title="Database error signature exposed after query input variation",
                    severity="medium",
                    confidence="medium",
                    detector=self.id,
                    detector_version=self.version,
                    evidence=str(item.get("evidence") or "Database error signature observed"),
                    location=str(item.get("request_url") or target),
                    description=("A database error signature appeared after a low-impact quote "
                                 "mutation. This is evidence of a possible injection path, not "
                                 "proof that a query can be exploited."),
                    remediation=("Use parameterized queries and avoid returning database exceptions "
                                 "to clients. Validate the suspected path with a controlled test."),
                    cwe="CWE-89",
                    verification="inferred",
                ))
        if cancel.is_set():
            raise AdapterCancelled("cancelled during dynamic validation")
        if time.monotonic() >= deadline:
            result.notes.append("dynamic validation reached its bounded deadline")
        else:
            result.notes.append(
                f"dynamic validation completed: {len(redirects)} redirect behavior(s), "
                f"{len(sql_indicators) if 'sql_indicators' in locals() else 0} database error indicator(s)")
        return result


class OpenAPIAdapter(Adapter):
    """Discover OpenAPI/Swagger descriptions and check declared protected GETs.

    Only same-origin, in-scope endpoints documented as security-protected are
    probed, without credentials, and only with GET. A success is reported as an
    authorization mismatch indicator (unverified) because OpenAPI documents can
    be stale or endpoint access may be intentionally public.
    """

    id = "strix-openapi"
    version = AGENT_VERSION
    asset_types = ("web",)
    SPEC_CANDIDATES = ("openapi.json", "swagger.json", "api-docs", "v3/api-docs")
    MAX_SPEC_BYTES = 262144
    MAX_ENDPOINTS = 30

    def assess(self, target: str, *, timeout: float,
               cancel: threading.Event,
               context: dict[str, Any] | None = None) -> AdapterResult:
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
        candidates.extend([
            f"{origin}{path_base}/openapi.json",
            f"{origin}{path_base}/swagger.json",
            f"{origin}/openapi.json",
            f"{origin}/swagger.json",
            f"{origin}/api-docs",
            f"{origin}/v3/api-docs",
        ])
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
            if not isinstance(body, str) or not body or not isinstance(response.get("status"), int):
                continue
            if not 200 <= int(response["status"]) < 300:
                continue
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and (isinstance(payload.get("paths"), dict)
                                              and (payload.get("openapi") or payload.get("swagger"))):
                spec = payload
                spec_url = candidate
                break
        if spec is None:
            raise AdapterNotApplicable(
                "no supported OpenAPI/Swagger JSON document found at common same-scope "
                "paths; API coverage is inconclusive")
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
                if (server_parsed.scheme in {"http", "https"}
                        and (server_parsed.hostname or "").lower() == (target_parsed.hostname or "").lower()
                        and server_port == target_port):
                    server_denial, _ = scope.check(absolute)
                    if not server_denial:
                        chosen = absolute.rstrip("/")
                        break
            if chosen:
                server_base = chosen
            else:
                raise AdapterError(
                    "OpenAPI server URL is not same-origin/in-scope; refusing to probe external endpoints")

        paths = spec.get("paths")
        global_security = spec.get("security", [])
        if not isinstance(paths, dict):
            raise AdapterError(
                "OpenAPI document contains no usable paths object; API coverage is inconclusive")
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
                isinstance(item, dict) and bool(item) for item in security)
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
                result.findings.append(Finding(
                    asset=target,
                    category="api_documented_auth_mismatch",
                    title="Endpoint documented as protected responded successfully without credentials",
                    severity="medium",
                    confidence="medium",
                    detector=self.id,
                    detector_version=self.version,
                    evidence=(f"OpenAPI declares security for GET {path}; unauthenticated request "
                              f"returned HTTP {status_code}. No credentials were sent and response "
                              "content was not retained."),
                    location=endpoint,
                    description=("This is an authorization mismatch indicator, not definitive proof: "
                                 "the specification may be stale or this route may intentionally be public."),
                    remediation=("Verify the endpoint's intended access policy. Enforce authorization "
                                 "server-side and keep the OpenAPI security declaration synchronized."),
                    cwe="CWE-862",
                    verification="unverified",
                ))
            if endpoints_checked >= self.MAX_ENDPOINTS:
                result.notes.append(f"OpenAPI endpoint limit ({self.MAX_ENDPOINTS}) reached")
                break
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        result.notes.append(f"OpenAPI checked {endpoints_checked} documented protected GET endpoint(s)")
        return result


class CrawlerAdapter(Adapter):
    """Bounded, same-origin crawl that publishes in-scope URLs to later adapters.

    This adapter produces no findings by itself: discovery is not a verdict.
    Discovered URLs are written to ``context["discovered_urls"]`` where the HTTP
    assessment adapter picks them up; both halves stay scope-gated so crawler
    output can never widen the engagement.
    """

    id = "strix-crawl"
    version = AGENT_VERSION
    asset_types = ("web",)
    MAX_DISCOVERED = 50

    def assess(self, target: str, *, timeout: float,
               cancel: threading.Event,
               context: dict[str, Any] | None = None) -> AdapterResult:
        checked_destination(target)
        deadline = time.monotonic() + max(0.05, timeout)
        crawler = WebCrawler(max_pages=CRAWL_MAX_PAGES)
        crawl = crawler.crawl(target, deadline=deadline, cancel=cancel)
        result = AdapterResult()
        result.notes.extend(crawl.notes or [f"crawl completed: {len(crawl.pages)} page(s)"])
        result.notes.append(
            f"discovered {len(crawl.discovered)} in-scope link(s) across {len(crawl.pages)} page(s)")
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
    version = AGENT_VERSION
    asset_types = ("web", "api")
    MAX_ENDPOINTS = 8
    MAX_BODY_FOR_DIGEST = 32768

    def __init__(self) -> None:
        self._probe = EndpointProbe(timeout=6.0)

    def available(self) -> tuple[bool, str]:
        authorized = scope.active()
        auth = authorized.auth if authorized else None
        if not isinstance(auth, AuthConfig) or not auth.users:
            return False, ("no test principals configured "
                           "(add auth.users to the scope document)")
        return True, f"{len(auth.users)} principal(s): {', '.join(auth.ids)}"

    def assess(self, target: str, *, timeout: float,
               cancel: threading.Event,
               context: dict[str, Any] | None = None) -> AdapterResult:
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
                "authorization differences cannot be exercised")
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
                isinstance(status_first, int) and isinstance(anonymous[1], int)
                and 200 <= status_first < 300 and anonymous[1] == status_first
                and anonymous[2] == responses[0][2])
            principals_identical = (
                len(responses) >= 2
                and isinstance(responses[0][1], int) and 200 <= responses[0][1] < 300
                and isinstance(responses[1][1], int)
                and responses[1][1] == responses[0][1]
                and responses[1][2] == responses[0][2])
            differential = DifferentialResult(
                endpoint=endpoint, responses=tuple(responses),
                anonymous_matches_first=anonymous_matches,
                principals_identical=principals_identical)
            for category in classify(differential):
                result.findings.append(self._finding(category, endpoint, differential))
            enforced = (isinstance(responses[0][1], int)
                        and isinstance(responses[-1][1], int)
                        and 200 <= responses[0][1] < 300 and responses[-1][1] >= 400)
            if enforced and not result.findings:
                result.notes.append(
                    f"{endpoint}: anonymous caller refused (HTTP {responses[-1][1]}) — "
                    "authorization enforced on this endpoint")
        result.notes.append(
            f"authorization differences checked on {checked} endpoint(s) with "
            f"{len(auth.users)} principal(s)")
        return result

    def _fetch_as(self, url: str,
                  principal: Principal | None) -> tuple[str, int | str, str]:
        response = self._probe._fetch(url, auth=principal)
        status = response.get("status")
        status = status if isinstance(status, (int, str)) else "error"
        body = response.get("body", "") if isinstance(response.get("body"), str) else ""
        return (principal.id if principal else "anonymous", status,
                body_digest(body[: self.MAX_BODY_FOR_DIGEST]))

    def _finding(self, category: str, endpoint: str,
                 differential: DifferentialResult) -> Finding:
        if category == "authorization_missing":
            return Finding(
                asset=endpoint,
                category="authorization_missing",
                title="Object endpoint returns identical data to anonymous callers",
                severity="high",
                confidence="medium",
                detector=self.id,
                detector_version=self.version,
                evidence=(f"{differential.evidence_line()} — the anonymous response is "
                          "byte-identical to the authenticated response"),
                location=endpoint,
                description=("The endpoint returned the same response body to an unauthenticated "
                             "request and to an authenticated principal. Authentication either is "
                             "not enforced or does not change the response. Confirm whether the "
                             "data is intentionally public."),
                remediation=("Require authentication for this endpoint and return 401/403 for "
                             "anonymous callers; keep authorization checks server-side."),
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
            evidence=(f"{differential.evidence_line()} — both principals received "
                      "byte-identical responses for the same object reference"),
            location=endpoint,
            description=("Two different test principals requested the same object reference and "
                         "received identical responses. This is a BOLA/IDOR indicator: object "
                         "access may not be scoped to the owning principal. Public-by-design data "
                         "or principal-independent responses can also explain this, so treat it "
                         "as inferred until object ownership is confirmed."),
            remediation=("Enforce object-level authorization on every request (check that the "
                         "authenticated principal owns or may access the requested object); "
                         "return 403 for cross-tenant object access."),
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
    version = AGENT_VERSION
    asset_types = ("web", "api")
    MAX_PARAMS = 6
    POLL_ATTEMPTS = 6
    POLL_INTERVAL = 0.4
    # `page` and `q` are deliberately absent: pagination and search outrank
    # them as interpretations, and a wrong injection wastes the canary budget.
    SSRF_PARAM = re.compile(
        r"^(?:url|uri|fetch|source|src|dest|destination|redirect|next|target|host|"
        r"domain|proxy|callback|feed|img|image|file|path|resource|load|read|include|"
        r"data|site|html)$", re.IGNORECASE)
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
        return CollabClient(collab.host, collab.port), f"http://{collab.host}:{collab.port}"

    def available(self) -> tuple[bool, str]:
        authorized = scope.active()
        collab = authorized.collab if authorized else None
        if not isinstance(collab, CollabConfig):
            return False, ("no out-of-band listener configured "
                           "(add collab.host/collab.port to the scope document)")
        if collab.port == 0:
            return True, "in-process collab listener (ephemeral port)"
        return True, f"collab listener at {collab.host}:{collab.port}"

    def assess(self, target: str, *, timeout: float,
               cancel: threading.Event,
               context: dict[str, Any] | None = None) -> AdapterResult:
        checked_destination(target)
        listener, canary_base = self._listener()
        deadline = time.monotonic() + max(0.05, timeout)
        pool = [target]
        if context:
            pool.extend(url for url in context.get("discovered_urls", []) if url != target)
        candidates = self._candidate_params(pool)
        result = AdapterResult()
        if not candidates:
            result.notes.append(
                "no SSRF-shaped parameter found on the assessed URLs; "
                "out-of-band probing had nothing to inject into")
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
            finding = self._probe_param(url, param, canary, token, listener,
                                        cancel=cancel, deadline=deadline)
            if finding is not None:
                confirmed += 1
                result.findings.append(finding)
        result.notes.append(
            f"SSRF canaries injected into {len(candidates)} parameter(s); "
            f"{confirmed} confirmed by out-of-band callback")
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
        params = [(name, canary if name == param else value)
                  for name, value in parse_qsl(parsed.query, keep_blank_values=True)]
        return parsed._replace(query=urlencode(params)).geturl()

    def _probe_param(self, url: str, param: str, canary: str, token: str,
                     listener: CollabServer | CollabClient, *,
                     cancel: threading.Event, deadline: float) -> Finding | None:
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

    def _finding(self, url: str, param: str, canary: str, token: str,
                 callbacks: list[dict[str, Any]], *, in_band: bool) -> Finding:
        callback = callbacks[0] if callbacks else None
        if callback is not None:
            peer = str(callback.get("peer") or "unknown peer")
            method = str(callback.get("method") or "GET")
            evidence = (f"unique canary {canary} injected into parameter '{param}' of {url}; "
                        f"the application fetched it — callback received via {method} "
                        f"from {peer} (token {token})")
        else:
            evidence = (f"unique canary {canary} injected into parameter '{param}' of {url}; "
                        "the response reflects canary content "
                        f"(HTTP {in_band and 'observed'}) — no callback yet, "
                        "fetch confirmed in-band only")
        return Finding(
            asset=url,
            category="ssrf_confirmed_oob" if callback is not None else "ssrf_inband_reflection",
            title=("Application fetched an attacker-chosen destination (out-of-band confirmed)"
                   if callback is not None else
                   "Application fetched and reflected an attacker-chosen destination"),
            severity="high" if callback is not None else "medium",
            confidence="high" if callback is not None else "medium",
            detector=self.id,
            detector_version=self.version,
            evidence=evidence,
            location=url,
            description=("The parameter controls a server-side fetch. The unique canary URL was "
                         "retrieved by the application" +
                         (" and its content was reflected to us." if in_band
                          else ", confirmed by the listener callback.") +
                         " An attacker can point this at internal services, cloud metadata "
                         "addresses or arbitrary hosts."),
            remediation=("Validate the fetch destination server-side: allowlist schemes, hosts "
                         "and ports; refuse link-local, loopback and metadata addresses; never "
                         "fetch raw user-supplied URLs."),
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


def _run_tool(argv: list[str], *, timeout: float,
              cancel: threading.Event, cwd: str | Path | None = None,
              env_extra: dict[str, str] | None = None) -> tuple[int, str, str]:
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
    env = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C",
           "HOME": os.environ.get("HOME", "")}
    if env_extra:
        env.update(env_extra)
    try:
        # stdin is pinned to /dev/null: some tools (nuclei) read target URLs
        # from stdin when it is open, which otherwise parks them forever.
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.DEVNULL,
                                text=False, env=env,
                                cwd=str(cwd) if cwd is not None else None,
                                # Own session/process group: see _kill_tree.
                                start_new_session=True)
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
    out_thread = threading.Thread(target=drain, args=("stdout", proc.stdout),
                                  daemon=True, name="strix-tool-stdout")
    err_thread = threading.Thread(target=drain, args=("stderr", proc.stderr),
                                  daemon=True, name="strix-tool-stderr")
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
            f"{Path(argv[0]).name} output exceeded {MAX_TOOL_OUTPUT_BYTES} bytes per stream")
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
                out = subprocess.run([binary, "--version"], capture_output=True,
                                     text=True, timeout=10, env={"PATH": os.environ.get("PATH", "")})
                self._version = out.stdout.splitlines()[0].strip() if out.stdout else "unknown"
            except (OSError, subprocess.SubprocessError) as exc:
                return False, f"nmap present but unusable: {exc}"
        return True, self._version

    def assess(self, target: str, *, timeout: float,
               cancel: threading.Event,
               context: dict[str, Any] | None = None) -> AdapterResult:
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
            argv.extend(["-p", ",".join(str(port) for port in sorted(active_scope.allowed_ports))])
        else:
            # A hostname authorization plus a URL is not blanket permission to
            # probe unrelated services. Without an explicit allowlist, limit
            # discovery to the exact port named by the authorized target URL.
            argv.extend(["-p", str(destination.port)])
        argv.extend(["--host-timeout", f"{max(1, int(timeout))}s",
                     "-oX", "-", "--", destination.ip])  # IP is pinned after scope validation
        code, stdout, stderr = _run_tool(argv, timeout=timeout, cancel=cancel)
        if code != 0:
            raise AdapterError(f"nmap exited {code}: {stderr.strip()[:200]}")

        result = AdapterResult()
        raw = stdout.encode() if isinstance(stdout, str) else stdout
        if re.search(rb"<!ENTITY|<!DOCTYPE[^>]*\[", raw, re.I):
            raise AdapterError("nmap output contains entity declarations; refusing to parse")
        try:
            root = safe_fromstring(stdout)  # defusedxml: no DTDs, entities or external refs
        except (ET.ParseError, DefusedXmlException) as exc:
            raise AdapterError(f"unparseable nmap XML: {type(exc).__name__}") from exc

        # A scanner that returns XML without results (truncated output, refused
        # scan, nmap error) must not be scored as "nothing open".
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
                # closed = a refusal we can trust; filtered/unresolved = no answer.
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
            result.findings.append(Finding(
                asset=host,
                category="open_tcp_port",
                title=f"Observed open {protocol}/{number} ({service_name})",
                severity="info",
                confidence="high",
                detector=self.id,
                detector_version=self._version or self.version,
                evidence=(f"nmap TCP connect scan reported {host}:{number}/{protocol} open"
                          f"{f' — service {banner}' if banner else ''}"
                          + (f" — {risk_note}" if risk_note else "")),
                location=f"{host}:{number}/{protocol}",
                description=("An exposed service was observed from the assessment host. "
                             "Port exposure alone does not prove insecure authentication "
                             "or a vulnerability."),
                remediation=("Confirm this service is intended to be reachable from the assessment "
                             "network and verify its authentication and access-control configuration."),
                verification="observed",
            ))
        scanned_ports = (f"authorized ports {','.join(str(p) for p in sorted(active_scope.allowed_ports))}"
                         if active_scope and active_scope.allowed_ports
                         else f"target URL port {destination.port}")
        if unanswered:
            # A filtered port is not a closed port: nmap got no answer, so the
            # job cannot claim that surface was assessed.
            result.partial = True
            result.notes.append(
                "nmap got no answer for "
                f"{len(unanswered)} port(s) ({', '.join(unanswered[:10])})")
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
            return False, "nuclei not installed (https://github.com/projectdiscovery/nuclei)"
        root = self.templates_dir()
        missing = [sub for sub in self.TEMPLATE_SUBSET if not (root / sub).is_dir()]
        if not root.is_dir():
            return False, "nuclei-templates not installed (run: nuclei -update-templates)"
        if missing:
            return False, ("nuclei template subset missing: "
                           f"{', '.join(missing)} (run: nuclei -update-templates)")
        if self._version is None:
            try:
                code, stdout, stderr = _run_tool([binary, "-version"], timeout=15.0,
                                                 cancel=threading.Event())
            except (AdapterError, OSError) as exc:
                return False, f"nuclei present but unusable: {exc}"
            if code != 0:
                return False, f"nuclei present but unusable (exit {code})"
            # The engine prints its version banner on stderr, not stdout
            # (verified against the real binary).
            blob = stdout + stderr
            self._version = next(
                (line.split(":", 1)[1].strip() for line in blob.splitlines()
                 if "version" in line.lower() and ":" in line), "unknown")
        return True, f"nuclei {self._version}"

    def assess(self, target: str, *, timeout: float,
               cancel: threading.Event,
               context: dict[str, Any] | None = None) -> AdapterResult:
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
            "-u", pinned_target,
            "-H", f"Host: {host_header}",
            "-sni", parsed_target.hostname,
            "-dr",  # external redirects are never followed by a scanner
            "-t", ",".join(str(self.templates_dir() / sub)
                           for sub in self.TEMPLATE_SUBSET),
            "-jsonl", "-silent", "-no-color",
            "-no-interactsh", "-disable-update-check",
            "-severity", self.SEVERITIES,
            "-rate-limit", str(self.RATE_LIMIT),
            "-concurrency", str(self.CONCURRENCY),
            "-timeout", str(max(1, int(timeout / 4))),
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
            f"[template profile: {', '.join(self.TEMPLATE_SUBSET)}]")
        return result

    def _normalize(self, payload: dict[str, Any], target: str) -> Finding | None:
        # Every string here comes from a template file and a remote response;
        # it is bounded and stripped of control characters before it becomes a
        # finding (the same rule the AI analyst applies to untrusted text).
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
            cwe = f"CWE-{cwe}"  # templates may carry the bare number
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


# ---------------------------------------------------------------------------
# strix-agent: the upstream autonomous engine, run as an isolated subprocess
# ---------------------------------------------------------------------------
# Upstream project: https://github.com/usestrix/strix.git (Apache-2.0). This
# adapter invokes the *installed* CLI and reads the run artifacts it writes; no
# upstream code is vendored into this repository and the engine is never
# imported, so it can be upgraded or replaced on its own schedule. The
# invocation below is derived from the upstream CLI itself
# (strix/interface/cli_args.py), not from documentation prose:
#
#   --target URL       the asset to test (URL, repo, directory, domain, IP)
#   --non-interactive  headless: no TUI, exits on completion
#   --scan-mode        quick | standard | deep (upstream default: deep)
#   --max-turns N      per-agent turn ceiling
#   --max-budget USD   stop the run at this LLM spend
#   --version          prints "strix <version>"
#
# Headless exit status: 0 = no findings, 2 = a finding at or above --fail-on
# (upstream default: any finding). Any other status is a run failure. A run
# writes <cwd>/strix_runs/<run-name>/: run.json (the run record, with a status
# that is "completed" only when the run finished) and vulnerabilities.json (the
# finding reports). The engine needs Docker and an LLM provider of its own;
# both are operator prerequisites, and a missing one surfaces as a failed run
# rather than as a clean result.
#
# Verified live on 2026-10-27 against the installed 1.7.0, its real sandbox
# image (ghcr.io/usestrix/strix-sandbox:1.3.0, 5.9 GB) and a real container:
#   * `--version` prints "strix <version>".
#   * The LLM connection is preflighted before any work. A provider failure
#     exits 1, prints a "LLM CONNECTION FAILED" panel on **stdout** (stderr
#     stays empty) and writes no run directory at all.
#   * A completed run exits 0 with run.json status "completed" — and writes
#     vulnerabilities.json **only if it filed at least one finding**.
#   * A loopback target is rewritten so the sandbox can reach the host
#     (http://127.0.0.1:8765/ -> http://host.docker.internal:8765/) and
#     findings are filed against the rewritten URL.
#   * The engine persists the provider configuration it was handed into
#     ~/.strix/cli-config.json: that file is a secret at rest for whichever
#     account runs the engine, and a value it cannot parse there (a string
#     where a dict is expected) breaks every later run until it is fixed.

AGENT_BIN_ENV = "STRIX_AGENT_BIN"
AGENT_WORKDIR_ENV = "STRIX_AGENT_WORKDIR"
AGENT_SCAN_MODE_ENV = "STRIX_AGENT_SCAN_MODE"
AGENT_MAX_TURNS_ENV = "STRIX_AGENT_MAX_TURNS"
AGENT_MAX_BUDGET_ENV = "STRIX_AGENT_MAX_BUDGET_USD"
# The engine's own configuration, forwarded by name so no unrelated variable of
# the platform's environment is handed to it. Taken from the engine's settings
# model (strix/config/settings.py, verified against installed 1.7.0):
#   STRIX_LLM         model, e.g. "openrouter/..." or "openai/<local model>"
#   STRIX_IMAGE       sandbox image, for a mirror or an air-gapped registry
#   <key>             LLM_API_KEY or OPENAI_API_KEY
#   <base>            LLM_API_BASE / OPENAI_API_BASE / OPENAI_BASE_URL /
#                     OLLAMA_API_BASE / LITELLM_BASE_URL
AGENT_PROVIDER_ENV = ("STRIX_LLM", "STRIX_IMAGE", "LLM_API_KEY", "OPENAI_API_KEY",
                      "LLM_API_BASE", "OPENAI_API_BASE", "OPENAI_BASE_URL",
                      "OLLAMA_API_BASE", "LITELLM_BASE_URL")
AGENT_SCAN_MODES = ("quick", "standard", "deep")
AGENT_DEFAULT_SCAN_MODE = "quick"
AGENT_FINDINGS_EXIT = 2
AGENT_RUNS_DIR = "strix_runs"
AGENT_RUN_RECORD = "run.json"
AGENT_VULN_INDEX = "vulnerabilities.json"

# ---------------------------------------------------------------------------
# Optional, enforceable network boundary for the upstream engine
# ---------------------------------------------------------------------------
# The upstream engine drives its own browser, proxy and shell inside its
# sandbox container, so this platform cannot pin the connection the way the
# nmap and nuclei adapters pin the validated IP. The enforceable layer below is
# therefore an *optional runtime policy* — when it can be installed it limits
# the assessment host's egress to the addresses the scope gate already accepted,
# plus explicit break-glass exceptions. When it cannot be installed and the
# deployment has asked for it, the adapter refuses rather than silently running
# with no network constraint.
#
# Design notes (for the person operating this in production):
#   * It uses nftables user-space chains under a dedicated table, one chain per
#     run, deleted when the run finishes or is cancelled or times out.
#   * Rules are ordered so the deny rules win: drop cloud-metadata / RFC1918 /
#     loopback / link-local / multicast / broadcast / bogon prefixes first,
#     then allow the exact destination IPs the scope gate resolved, then a
#     break-glass accept for explicitly authorized provider/Sandbox registries
#     and DNS, then an explicit final drop for everything else.
#   * DNS is allowed only to the configured resolver(s) or, when none are
#     configured, to the system resolver the host already uses. No random DNS.
#   * The table/chain/nft invocation is the thing that could be denied by host
#     policy (no CAP_NET_ADMIN, restricted sudo, container without
#     NET_ADMIN, SELinux/AppArmor). That is the controlled, explicit failure
#     point, not a silent no-op.
#
# Environment (read once at run time, not from a scope document):
NET_BOUNDARY_ENV = "STRIX_NET_BOUNDARY"
NET_BOUNDARY_REQUIRED_ENV = "STRIX_NET_BOUNDARY_REQUIRED"
NET_BOUNDARY_NFT_TABLE = "inet strix-net-boundary"
NET_BOUNDARY_CHAIN_PREFIX = "strix-run-"
NET_BOUNDARY_DNS_TIMEOUT_S = 2.0
NET_BOUNDARY_INSTALL_TIMEOUT_S = 5.0

# Addresses that must never be reached by an assessment engine, regardless of
# scope. These mirror the address classes scope.is_special_use already refuses
# at the application layer; the network layer repeats them so a mistake in the
# application layer cannot become a live connection.
#   * 169.254.169.254/32 is the well-known cloud-metadata anchor. Checking only
#     that literal is not enough (Amazon uses link-local 169.254.169.254 but
#     GCP uses 169.254.169.254 as well; some clouds use 100.100.100.200 etc.),
#     so the broader 169.254.0.0/16 link-local block is denied and the engine
#     is not given any link-local destination by the scope gate in the first
#     place.
#   * 127.0.0.0/8, ::1/128, fe80::/10, fc00::/7, 100.64.0.0/10, 10.0.0.0/8,
#     172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 0.0.0.0/8, 100.64.0.0/10,
#     multicast 224.0.0.0/4 and ff00::/8, broadcast, and the bogon prefixes
#     that are never legitimate assessment targets.
_NET_BOUNDARY_DENY_IPV4 = frozenset({
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("169.254.0.0/16"),     # link-local incl. metadata anchor
    ipaddress.IPv4Network("100.64.0.0/10"),      # CGNAT shared space
    ipaddress.IPv4Network("0.0.0.0/8"),           # "this" network
    ipaddress.IPv4Network("192.0.0.0/24"),        # IETF protocol assignments
    ipaddress.IPv4Network("192.0.2.0/24"),        # TEST-NET-1
    ipaddress.IPv4Network("192.51.100.0/24"),     # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),      # TEST-NET-3
    ipaddress.IPv4Network("224.0.0.0/4"),         # multicast
    ipaddress.IPv4Network("240.0.0.0/4"),         # reserved/future
    ipaddress.IPv4Network("255.255.255.255/32"),  # broadcast
})
_NET_BOUNDARY_DENY_IPV6 = frozenset({
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fe80::/10"),           # link-local
    ipaddress.IPv6Network("fc00::/7"),            # unique local
    ipaddress.IPv6Network("ff00::/8"),             # multicast
    ipaddress.IPv6Network("2001:db8::/32"),       # documentation
    ipaddress.IPv6Network("2001:10::/28"),        # ORCHID
    ipaddress.IPv6Network("2001:20::/28"),        # ORCHIDv2
    ipaddress.IPv6Network("fc00::/7"),
})


def _net_boundary_dns_resolvers() -> list[str]:
    """Up to a few explicit DNS resolvers the host is allowed to use.

    When the deployment sets ``STRIX_NET_BOUNDARY_DNS`` (space/comma separated
    IPv4/IPv6 literals), only those are permitted. Otherwise the engine is
    allowed to use whichever resolver the host's resolver configuration points
    at — but only the resolver, never a random DNS server the engine might
    choose to query directly (that would defeat the boundary).

    This is intentionally narrow: the engine needs DNS to resolve the one target
    it is authorized to contact. It does not need arbitrary DNS.
    """
    configured = os.environ.get(
        "STRIX_NET_BOUNDARY_DNS", "").strip()
    if configured:
        out: list[str] = []
        for token in re.split(r"[\s,;]+", configured):
            token = token.strip()
            if not token:
                continue
            try:
                ipaddress.ip_address(token)
            except ValueError:
                raise ValueError(
                    "STRIX_NET_BOUNDARY_DNS must be space/comma separated IP literals "
                    f"(got {token!r})") from None
            out.append(token)
        if not out:
            raise ValueError(
                "STRIX_NET_BOUNDARY_DNS is set but contains no usable resolver")
        return out
    # Best-effort system resolver gathering for the 'use the host resolver'
    # break-glass path. This is intentionally not a guarantee of completeness;
    # deployments that need a strict boundary should configure
    # STRIX_NET_BOUNDARY_DNS explicitly.
    return _net_boundary_system_resolvers()


def _net_boundary_system_resolvers() -> list[str]:
    """Best-effort read of the host's configured resolvers.

    No resolver is guaranteed here: some hosts use a local stub (127.0.0.53),
    some use a DNS forwarder, some have no readable resolver config. This
    function returns what it can, and the caller treats an empty list as
    'no explicit resolver — DNS is not allowed by default'.
    """
    out: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        try:
            addr = ipaddress.ip_address(value.split("%")[0])
        except ValueError:
            return
        key = str(addr)
        if key in seen:
            return
        seen.add(key)
        out.append(value)

    _add("127.0.0.53")  # systemd-resolved default
    _add("127.0.0.54")
    try:
        for line in Path("/etc/resolv.conf").read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("nameserver "):
                _add(line.split(None, 1)[1].strip())
    except OSError:
        pass
    for _path in (Path("/etc/systemd/resolved.conf"), Path("/etc/dnsmasq.conf"),
                 Path("/etc/bind/cached.root"), Path("/var/run/nscd/socket")):
        # We only read resolv.conf above; the other paths are not parsed because
        # their formats differ and reading them blindly is more risk than value.
        pass
    return out


class NetBoundaryError(AdapterError):
    """The network boundary could not be established or could not be removed."""


class NetBoundary:
    """One assessment run's enforceable egress policy.

    Lifecycle: create -> install -> (run) -> uninstall. The install step is the
    controlled failure point: if the deployment has asked for an enforceable
    boundary and install fails, the adapter refuses to run. If the deployment
    has not asked for one, or the platform cannot create nft chains at all,
    the adapter runs with a logged warning and a documented remaining deployment
    requirement rather than failing — because requiring a capability the host
    does not have would turn a working install into a permanently broken one.

    Instances are meant to be short-lived and one-per-run; they are not a
    long-lived singleton.
    """

    def __init__(self, *, run_id: str, destinations: list[str],
                 dns_resolvers: list[str] | None = None,
                 break_glass_registries: list[str] | None = None) -> None:
        if not run_id or not isinstance(run_id, str):
            raise ValueError("NetBoundary requires a non-empty run_id string")
        self._run_id = run_id
        self._destinations = list(destinations)
        self._dns_resolvers = list(dns_resolvers) if dns_resolvers else []
        self._break_glass_registries = list(
            break_glass_registries) if break_glass_registries else []
        self._chain_name: str | None = None
        self._installed = False
        self._rules_text: str | None = None
        self._install_error: str | None = None

    # ------------------------------------------------------------------
    # Construction: build the rule set as text
    # ------------------------------------------------------------------
    def _build_rules(self) -> str:
        """The nftables ruleset text for this run.

        Ordering is intentional:
          1. table + chain (fresh per run)
          2. explicit drops for the special-use / bogon space
          3. allow the exact IPs the scope gate resolved
          4. allow DNS only to configured/system resolvers
          5. break-glass allow for provider/Sandbox registries the engine may
             legitimately pull from (when the deployment names them)
          6. explicit final drop for everything else
        """
        chain = self._chain_name or f"strix-run-{self._run_id}"
        parts: list[str] = []
        parts.append(f"table inet {NET_BOUNDARY_NFT_TABLE.split()[0]} {self._run_id}")
        parts.append(
            f"    chain {chain} {{ type filter hook output priority 0; "
            "policy accept; "
            "counter; "
            "aspect classid; }}"
        )

        # Deny special-use and bogon space unconditionally.
        def _deny_cidr(cidr: ipaddress.IPv4Network | ipaddress.IPv6Network,
                       family: str) -> str:
            if family == "ip":
                return f"        ip daddr {cidr} drop"
            return f"        ip6 daddr {cidr} drop"

        for network in sorted(_NET_BOUNDARY_DENY_IPV4):
            parts.append(_deny_cidr(network, "ip"))
        for network6 in sorted(_NET_BOUNDARY_DENY_IPV6):
            parts.append(_deny_cidr(network6, "ip6"))

        # Allow the exact destination IPs the scope gate resolved. These are the
        # only addresses the engine is authorized to contact for the assessment.
        if self._destinations:
            parts.append("        # Authorized assessment destinations")
            for ip in sorted(set(self._destinations)):
                try:
                    addr = ipaddress.ip_address(ip.split("%")[0])
                except ValueError:
                    raise ValueError(
                        f"NetBoundary destination {ip!r} is not a valid IP literal") from None
                if addr.version == 4:
                    parts.append(f"        ip daddr {ip} accept")
                else:
                    parts.append(f"        ip6 daddr {ip} accept")

        # DNS: only to the configured/system resolvers.
        if self._dns_resolvers:
            parts.append("        # Authorized DNS resolvers")
            for resolver in sorted(set(self._dns_resolvers)):
                try:
                    addr = ipaddress.ip_address(resolver.split("%")[0])
                except ValueError:
                    raise ValueError(
                        f"NetBoundary DNS resolver {resolver!r} is not a valid IP literal") from None
                if addr.version == 4:
                    parts.append(f"        ip daddr {resolver} udp dport {{ 53 }} accept")
                else:
                    parts.append(f"        ip6 daddr {resolver} udp dport {{ 53 }} accept")

        # Break-glass: provider/Sandbox registries the engine may pull the
        # sandbox image from, or contact for its LLM provider. These are
        # explicitly named by the deployment, not inferred.
        if self._break_glass_registries:
            parts.append("        # Break-glass: explicitly authorized registries/providers")
            for entry in sorted(set(self._break_glass_registries)):
                try:
                    ipaddress.ip_address(entry.split("%")[0])
                except ValueError:
                    raise ValueError(
                        f"NetBoundary break-glass entry {entry!r} must be an IP literal") from None
                parts.append(f"        ip daddr {entry} accept")
                parts.append(f"        ip6 daddr {entry} accept")

        # Final drop: nothing else leaves this host for this run.
        parts.append("        # Default deny: no other egress for this run")
        parts.append("        ip daddr 0.0.0.0/0 drop")
        parts.append("        ip6 daddr ::/0 drop")
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Install / uninstall (the controlled failure points)
    # ------------------------------------------------------------------
    def install(self) -> None:
        """Create the table/chain and install the rules.

        Raises ``NetBoundaryError`` when the boundary cannot be established.
        """
        if self._installed:
            return
        chain = f"{NET_BOUNDARY_CHAIN_PREFIX}{self._run_id}"
        self._chain_name = chain
        rules = self._build_rules()
        self._rules_text = rules

        try:
            code, out, err = _run_net_tool(rules, timeout=NET_BOUNDARY_INSTALL_TIMEOUT_S)
        except NetBoundaryError:
            raise
        except Exception as exc:
            raise NetBoundaryError(
                f"nftables boundary installation failed ({type(exc).__name__})"
            ) from exc
        if code != 0:
            self._install_error = err.strip() or out.strip() or "non-zero exit"
            raise NetBoundaryError(
                f"nftables boundary installation failed: {self._install_error[:300]}")
        self._installed = True

    def uninstall(self) -> None:
        """Remove the per-run table/chain.

        Best-effort: if removal fails the run's findings are still recorded, but
        the failure is logged because a table left behind would persist until the
        host is restarted or an operator cleans it.
        """
        if not self._installed:
            return
        try:
            _run_net_tool(
                f"delete table inet strix-net-boundary {self._run_id}\n",
                timeout=NET_BOUNDARY_INSTALL_TIMEOUT_S)
        except Exception as exc:
            log.warning(
                "strix-agent net boundary %s could not be removed: %s",
                self._run_id, exc)
        finally:
            self._installed = False

    @property
    def installed(self) -> bool:
        return self._installed

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def destinations(self) -> list[str]:
        return list(self._destinations)

    @property
    def rules_text(self) -> str | None:
        return self._rules_text

    @property
    def install_error(self) -> str | None:
        return self._install_error


def _run_net_tool(rules: str, *, timeout: float) -> tuple[int, str, str]:
    """Run ``nft -f -`` with the given ruleset text.

    The same bounded, deadline-and-cancel execution used for scanner tools is
    used here: nft can be slow under contention and its stdin is the ruleset, so
    we feed it via a pipe and enforce the same timeouts.

    This is a separate helper from ``_run_tool`` because it uses ``nft`` and a
    ruleset fed on stdin, not a scanner binary with argument arrays.
    """
    import subprocess as _subprocess
    proc = _subprocess.Popen(
        ["nft", "-f", "-"],
        stdin=_subprocess.PIPE,
        stdout=_subprocess.PIPE,
        stderr=_subprocess.PIPE,
        text=True,
        env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"},
    )
    if proc.stdin is None or proc.stdout is None or proc.stderr is None:
        raise NetBoundaryError("nft process missing stdio")
    dead = time.monotonic() + max(0.01, timeout)
    try:
        proc.stdin.write(rules)
        proc.stdin.flush()
        proc.stdin.close()
    except OSError as exc:
        with contextlib.suppress(OSError):
            proc.kill()
        raise NetBoundaryError(
            f"nft stdin could not be written ({type(exc).__name__})") from exc
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    while time.monotonic() < dead:
        if proc.poll() is not None:
            break
        time.sleep(0.02)
    else:
        with contextlib.suppress(OSError):
            proc.kill()
        raise NetBoundaryError(
            f"nft did not finish within {timeout:g}s")
    try:
        proc.wait(timeout=2.0)
    except _subprocess.TimeoutExpired:
        with contextlib.suppress(OSError):
            proc.kill()
        proc.wait()
        raise NetBoundaryError("nft did not terminate after kill") from None
    stdout_chunks.append(proc.stdout.read())
    stderr_chunks.append(proc.stderr.read())
    stdout = "".join(stdout_chunks)
    stderr = "".join(stderr_chunks)
    return proc.returncode, stdout, stderr


def _net_boundary_build_destinations(target: str) -> list[str]:
    """The IPs the scope gate resolved for ``target``, for the network policy.

    The adapter calls this after ``checked_destination`` — i.e. after the target
    has been scope-validated — so these are the only addresses the boundary needs
    to allow.
    """
    denial, _, destination = scope.destination(target)
    if denial or destination is None:
        raise NetBoundaryError(
            f"cannot build network boundary for unvalidated target {target!r}")
    return [destination.ip]


def _net_boundary_create_for_run(target: str, run_id: str) -> NetBoundary | None:
    """Build and return a NetBoundary for one run, or None when it cannot/must not.

    This is the factory the adapter calls. It does not install — the run's
    lifecycle object owns install/uninstall.
    """
    try:
        destinations = _net_boundary_build_destinations(target)
    except NetBoundaryError as exc:
        log.warning("strix-agent net boundary: %s", exc)
        return None

    dns = _net_boundary_dns_resolvers()
    if not dns:
        # No resolver known: DNS is not allowed. That is fine when the target is
        # an IP literal, but for a hostname the engine would be unable to resolve
        # it. We allow the run to proceed without a boundary rather than fail it,
        # and log the remaining deployment requirement.
        log.warning(
            "strix-agent net boundary: no DNS resolver configured for this run; "
            "boundary will not be enforced (deployment requirement: set "
            "STRIX_NET_BOUNDARY_DNS or ensure host resolver is reachable)")
        return None

    registries: list[str] = []
    configured = os.environ.get(
        "STRIX_NET_BOUNDARY_BREAKGLASS", "").strip()
    if configured:
        for token in re.split(r"[\s,;]+", configured):
            token = token.strip()
            if token:
                registries.append(token)

    return NetBoundary(
        run_id=run_id,
        destinations=destinations,
        dns_resolvers=dns,
        break_glass_registries=registries,
    )
# Bounded ingestion: a model-authored run is untrusted input, and one report is
# kept per finding at bounded length rather than in full.
MAX_AGENT_FINDINGS = 200
MAX_AGENT_TITLE = 200
MAX_AGENT_TEXT = 4000
MAX_AGENT_EVIDENCE = 6000
_AGENT_SLUG = re.compile(r"[^a-z0-9]+")


def _agent_binary() -> Path:
    """The configured engine CLI; never a PATH lookup.

    A PATH search for ``strix`` would find this project's own console script
    (same name) and recursively re-enter the platform instead of testing a
    target, so the setting has to name the upstream binary explicitly.
    """
    configured = os.environ.get(AGENT_BIN_ENV, "").strip()
    if not configured:
        raise AdapterError(
            f"{AGENT_BIN_ENV} is not set (path to the installed strix-agent CLI, "
            "e.g. `pipx install strix-agent` then the strix-agent binary it ships)")
    path = Path(configured)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise AdapterError(f"{AGENT_BIN_ENV} does not name an executable file")
    return path


def _agent_limits() -> list[str]:
    """Optional turn/budget ceilings, validated instead of passed through."""
    argv: list[str] = []
    turns = os.environ.get(AGENT_MAX_TURNS_ENV, "").strip()
    if turns:
        if not re.fullmatch(r"[1-9][0-9]*", turns):
            raise AdapterError(f"{AGENT_MAX_TURNS_ENV} must be a positive integer")
        argv.extend(["--max-turns", turns])
    budget = os.environ.get(AGENT_MAX_BUDGET_ENV, "").strip()
    if budget:
        try:
            amount = float(budget)
        except ValueError:
            amount = 0.0
        if amount <= 0 or amount != amount or amount in (float("inf"), float("-inf")):
            raise AdapterError(f"{AGENT_MAX_BUDGET_ENV} must be a positive USD amount")
        argv.extend(["--max-budget", budget])
    return argv


def _agent_provider_env() -> dict[str, str]:
    """The engine's provider variables that are actually set, by name."""
    return {name: os.environ[name] for name in AGENT_PROVIDER_ENV if os.environ.get(name)}


def _agent_workspace() -> Path:
    """A private working directory for one run's artifacts (mode 0700)."""
    base = os.environ.get(AGENT_WORKDIR_ENV, "").strip()
    if base:
        Path(base).mkdir(parents=True, exist_ok=True)
    # mkdtemp already creates the directory owner-only. The artifacts are kept
    # for the operator to inspect; the platform never deletes them silently.
    return Path(tempfile.mkdtemp(prefix="strix-agent-", dir=base or None))


def _latest_agent_run(workspace: Path) -> Path | None:
    """The newest run directory under ``workspace``, as upstream defines it.

    A run is a directory carrying ``run.json``; that file is rewritten as the
    run progresses, so its mtime tracks activity better than the directory's.
    """
    runs = workspace / AGENT_RUNS_DIR
    if not runs.is_dir():
        return None
    candidates = [child for child in runs.iterdir()
                  if (child / AGENT_RUN_RECORD).is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda child: (child / AGENT_RUN_RECORD).stat().st_mtime)


def _read_agent_json(path: Path, *, missing_ok: bool = False) -> Any:
    """Parse one artifact the engine wrote; a corrupt file is a failed run.

    ``missing_ok`` exists for the finding index: a run that files nothing writes
    no ``vulnerabilities.json`` at all (verified against strix-agent 1.7.0), and
    a clean run must not be mistaken for a broken one. Errors still name only
    the file, never a server-side path.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if missing_ok:
            return None
        raise AdapterError(f"strix-agent artifact {path.name} is missing") from None
    except OSError as exc:
        raise AdapterError(f"strix-agent artifact {path.name} is unreadable "
                           f"({type(exc).__name__})") from exc
    try:
        return json.loads(text)
    except ValueError as exc:
        raise AdapterError(f"strix-agent artifact {path.name} is unreadable "
                           f"({type(exc).__name__})") from exc


def _agent_scrub(text: str) -> str:
    """Remove credentials this process handed the engine from text it echoes.

    The engine prints provider failures verbatim and a provider echoes the
    offending key back in its 401 body, so an error excerpt or a report can
    carry the key itself. Whatever the platform forwarded is removed before the
    text reaches coverage, the API, a report or the database.
    """
    scrubbed = text
    for name in AGENT_PROVIDER_ENV:
        value = os.environ.get(name, "").strip()
        if len(value) >= 8 and value in scrubbed:
            scrubbed = scrubbed.replace(value, "[redacted]")
    return scrubbed


def _agent_parse(url: str) -> ParseResult | None:
    """Parse a URL the engine may hand back."""
    return parse_url(url)


def _agent_target_host(target: str) -> str:
    """The URL we hand the engine, preserving the original endpoint."""
    parsed = parse_url(target)
    if parsed is None or not parsed.hostname:
        raise AdapterError(f"target is not a usable URL: {target!r}")
    return parsed.geturl()


def _agent_port(parsed: Any) -> int:
    """Effective port of a parsed URL, for origin comparison."""
    if parsed.port is not None:
        return int(parsed.port)
    return 443 if str(parsed.scheme).lower() == "https" else 80


def _agent_same_origin(left_url: str, right_url: str) -> bool:
    """Whether two URLs name the same scheme, host and port."""
    left, right = parse_url(left_url), parse_url(right_url)
    if left is None or right is None or not left.hostname or not right.hostname:
        return False
    return ((str(left.scheme).lower(), left.hostname.lower(), _agent_port(left))
            == (str(right.scheme).lower(), right.hostname.lower(), _agent_port(right)))


def _agent_target_rewrites(record: dict[str, Any], target: str) -> list[str]:
    """The engine's own view of the authorized target, from its run record.

    The engine rewrites the target so its sandbox can reach the host
    (``http://127.0.0.1:8765/`` becomes ``http://host.docker.internal:8765/``)
    and files findings against the rewritten URL. Only an entry whose recorded
    ``original`` is the target this platform authorized is honored: the engine
    never gets to introduce an asset of its own.
    """
    rewrites: list[str] = []
    for entry in record.get("targets_info") or []:
        if not isinstance(entry, dict):
            continue
        original = str(entry.get("original") or "").strip()
        if not original or not _agent_same_origin(original, target):
            continue
        details = entry.get("details") or {}
        contacted = str(details.get("target_url") or "").strip()
        if contacted and contacted not in rewrites:
            rewrites.append(contacted)
    return rewrites


class StrixAgentAdapter(Adapter):
    """The upstream autonomous AI engine, invoked as an external process.

    The engine drives a browser, an interception proxy and a shell inside its
    own sandbox container, so it resolves and contacts the target itself. Two
    consequences follow from that:

    * The connection cannot be pinned to the address this gate validated the way
      the nmap and nuclei adapters pin it. Authorization here is the target URL;
      artifact/target validation and per-finding scope re-checks are what
      protect the engagement from an engine that contacts something else. When
      the host can install nftables user chains, the optional
      :class:`NetBoundary` layer hardens the run's egress to the addresses the
      scope gate already accepted; when it cannot, the adapter runs with a logged
      warning and the remaining deployment requirement documented below.
    * Every finding is the engine's own claim and is recorded as ``unverified``
      with a provenance line: Strix did not independently reproduce it.
    """

    id = "strix-agent"
    asset_types = ("web",)
    requires = (AGENT_BIN_ENV,)

    def __init__(self) -> None:
        self._version: str | None = None

    def scan_mode(self) -> str:
        """Configured scan mode, refused when it is not one upstream accepts."""
        mode = os.environ.get(AGENT_SCAN_MODE_ENV, AGENT_DEFAULT_SCAN_MODE).strip().lower()
        if mode not in AGENT_SCAN_MODES:
            raise AdapterError(
                f"{AGENT_SCAN_MODE_ENV} must be one of "
                f"{', '.join(AGENT_SCAN_MODES)} (got {mode!r})"
            )
        return mode

    def _version_banner(self, timeout: float = 15.0) -> str | None:
        """The engine's own version banner, or None when it cannot speak.

        Returns None instead of raising so it can be used as a soft probe
        (for tests and for the adapter info endpoint) without spending a real
        scan run.
        """
        try:
            binary = _agent_binary()
        except AdapterError:
            return None
        try:
            code, stdout, _stderr = _run_tool(
                [str(binary), "--version"], timeout=timeout, cancel=threading.Event()
            )
        except (AdapterError, OSError):
            return None
        banner = stdout.strip().splitlines()[0].strip() if stdout.strip() else ""
        if code != 0 or not re.fullmatch(r"strix\s+\S+", banner):
            return None
        return banner

    def available(self) -> tuple[bool, str]:
        mode = self.scan_mode()
        banner = self._version_banner()
        if banner is None:
            try:
                image = _agent_binary()
            except AdapterError as exc:
                return False, str(exc)
            # Re-run the version probe so we can distinguish "binary exists but
            # is not strix-agent" from "binary cannot be executed / pre-flight
            # failed". The first _version_banner call already consumed one probe.
            try:
                code, stdout, _stderr = _run_tool(
                    [str(image), "--version"], timeout=15.0, cancel=threading.Event()
                )
            except (AdapterError, OSError):
                return (
                    False,
                    f"{image.name} is not usable right now "
                    "(missing engine binary, missing provider, or pre-flight failed "
                    "before the first run started)",
                )
            if code == 0:
                candidate = (stdout.strip().splitlines()[0].strip()
                             if stdout.strip() else "")
                if not re.fullmatch(r"strix\s+\S+", candidate):
                    return False, f"{image.name} is not the strix-agent CLI"
            return (
                False,
                f"{image.name} is not usable right now "
                "(missing engine binary, missing provider, or pre-flight failed "
                "before the first run started)",
            )
        self._version = banner.split(None, 1)[1]
        return True, f"strix-agent {self._version} (scan-mode {mode})"

    def net_boundary_state(self) -> str:
        """Whether this run enforces an optional/required/optional network boundary."""
        required = os.environ.get(NET_BOUNDARY_REQUIRED_ENV, "").strip().lower()
        if required in ("1", "true", "yes"):
            return "required"
        if os.environ.get(NET_BOUNDARY_ENV, "").strip().lower() in ("1", "true", "yes"):
            return "on"
        return "optional"

    def assess(self, target: str, *, timeout: float,
               cancel: threading.Event,
               context: dict[str, Any] | None = None) -> AdapterResult:
        # Scope first: a refused target never reaches the engine, and no LLM
        # call is spent on it.
        checked_destination(target)
        mode = self.scan_mode()
        target_host = _agent_target_host(target)
        argv = [str(_agent_binary()), "--target", target_host,
                "--non-interactive", "--scan-mode", mode, *_agent_limits()]
        workspace = _agent_workspace()

        # Optional enforceable network boundary for the run.
        boundary: NetBoundary | None = None
        run_id = _bounded(
            f"{target_host}-{int(time.time()*1000000)}", 64).strip("-")
        boundary = _net_boundary_create_for_run(target, run_id=run_id)
        boundary_installed = False
        if boundary is not None:
            try:
                boundary.install()
                boundary_installed = True
            except NetBoundaryError as exc:
                # When the deployment has asked for an enforceable boundary and
                # it cannot be established, refuse rather than let the engine run
                # with no network constraint. When boundary creation itself failed
                # (no nft, no CAP_NET_ADMIN, wrong host policy), that is a
                # deployment/prerequisite problem, not a clean target.
                if os.environ.get(NET_BOUNDARY_REQUIRED_ENV, "").strip().lower() in (
                    "1", "true", "yes"
                ):
                    raise AdapterError(
                        f"strix-agent net boundary required but could not be installed: "
                        f"{exc}") from exc
                log.warning(
                    "strix-agent net boundary could not be installed for %s: %s; "
                    "running without an enforced network boundary", run_id, exc)

        try:
            code, stdout, stderr = _run_tool(
                argv, timeout=timeout, cancel=cancel,
                cwd=workspace, env_extra=_agent_provider_env())
        finally:
            if boundary is not None:
                try:
                    boundary.uninstall()
                except Exception:
                    log.warning(
                        "strix-agent net boundary %s teardown failed (run artifacts "
                        "still retained on the assessment host)", run_id)

        if (not boundary_installed and boundary is None
            and os.environ.get(NET_BOUNDARY_REQUIRED_ENV, "").strip().lower() in (
                "1", "true", "yes")):
            # No boundary was created at all: log the remaining deployment
            # requirement but do not fail the run. A DNS-less host that still
            # wants the engine to run should set STRIX_NET_BOUNDARY_DNS.
            raise AdapterError(
                "strix-agent net boundary required but could not be created "
                "(no DNS resolver configured for the boundary)")

        if code not in (0, AGENT_FINDINGS_EXIT):
            # A non-headless-exit status is a failed run: the platform reports
            # no coverage rather than an empty ("clean") result. The engine
            # prints its failure panel on stdout and keeps stderr for the
            # traceback, so both are consulted (verified against 1.7.0).
            spoken = stderr.strip() or stdout.strip()
            excerpt = _bounded(" ".join(spoken.split()), 200) or "no output"
            raise AdapterError(f"strix-agent exited {code}: {_agent_scrub(excerpt)}")
        return self._collect(target, workspace, mode)

    def _collect(self, target: str, workspace: Path, mode: str) -> AdapterResult:
        """Map one finished run's artifacts into normalized findings."""
        run_dir = _latest_agent_run(workspace)
        if run_dir is None:
            raise AdapterError("strix-agent exited without writing a run record")
        record = _read_agent_json(run_dir / AGENT_RUN_RECORD)
        if not isinstance(record, dict):
            raise AdapterError("strix-agent run record is not a JSON object")
        reports = _read_agent_json(run_dir / AGENT_VULN_INDEX, missing_ok=True)
        if reports is None:
            # A run that filed nothing writes no index file; absence means zero
            # findings, not a broken run (verified against strix-agent 1.7.0).
            reports = []
        elif not isinstance(reports, list):
            raise AdapterError("strix-agent vulnerability index is not a JSON array")
        rewrites = _agent_target_rewrites(record, target)

        run_id = _bounded(str(record.get("run_id") or run_dir.name), 80)
        status = _bounded(str(record.get("status") or "unknown"), 40)
        result = AdapterResult()
        if status != "completed":
            # The engine's own record says the run did not finish. Whatever it
            # did report is kept, but completeness may not be claimed.
            result.partial = True
            result.notes.append(f"strix-agent run {run_id} ended with status {status!r}")

        out_of_scope = 0
        unusable = 0
        rewritten = 0
        for report in reports[:MAX_AGENT_FINDINGS]:
            if not isinstance(report, dict):
                unusable += 1
                continue
            finding, reason = self._normalize(report, target, run_id, rewrites)
            if finding is None:
                if reason == "out_of_scope":
                    out_of_scope += 1
                else:
                    unusable += 1
                continue
            filed = str(report.get("target") or "").strip()
            if filed and not _agent_same_origin(filed, target):
                rewritten += 1
            result.findings.append(finding)

        if len(reports) > MAX_AGENT_FINDINGS:
            result.partial = True
            result.notes.append(f"{len(reports) - MAX_AGENT_FINDINGS} report(s) beyond the "
                               f"{MAX_AGENT_FINDINGS}-finding ingestion cap were not read")
        if out_of_scope:
            # A run that named assets this engagement does not authorize did
            # not cover what it claims, and its remaining findings are not a
            # complete picture of the target.
            result.partial = True
            result.notes.append(f"{out_of_scope} engine finding(s) named assets outside the "
                                "authorized scope and were dropped")
        if unusable:
            result.notes.append(f"{unusable} engine report(s) were unusable and were dropped")
        if rewritten:
            result.notes.append(
                f"{rewritten} finding(s) were filed against the engine's sandbox view of "
                "the authorized target and were treated as in scope")
        result.notes.append(f"strix-agent {self._version} ({mode}) run {run_id}: "
                            f"{len(result.findings)} finding(s); run artifacts are retained "
                            "on the assessment host")
        return result

    def _normalize(self, report: dict[str, Any], target: str, run_id: str,
                   rewrites: list[str]) -> tuple[Finding | None, str]:
        """One engine report as a finding, or ``(None, why it was dropped)``.

        Every string here was written by a model that was reading attacker-
        influenced responses, so it is bounded and stripped of control
        characters, and the asset it names is re-validated against the
        engagement scope rather than trusted because an agent produced it.
        """
        title = _bounded(str(report.get("title") or ""), MAX_AGENT_TITLE)
        if not title:
            return None, "unusable"
        reported = _bounded(str(report.get("target") or ""), 500) or target
        denial, _reason = scope.check(reported)
        if denial and not any(_agent_same_origin(reported, candidate)
                              for candidate in rewrites):
            # An asset the engagement does not authorize is dropped, however
            # confidently an agent reported it. The engine's own rewrite of the
            # target it was given is not a new asset (see _agent_target_rewrites).
            return None, "out_of_scope"
        slug = _AGENT_SLUG.sub("_", title.lower()).strip("_")[:60]
        if not slug:
            return None, "unusable"

        claimed_severity = _bounded(str(report.get("severity") or ""), 20).lower()
        severity = claimed_severity if claimed_severity in SEVERITIES else "info"
        claimed_confidence = _bounded(str(report.get("confidence") or ""), 20).lower()
        confidence = claimed_confidence if claimed_confidence in CONFIDENCES else "low"
        agent = _bounded(str(report.get("agent_name") or ""), 80)

        location = _bounded(str(report.get("endpoint") or ""), 500) or reported
        parts = [f"strix-agent run {run_id} reported {claimed_severity or 'an unstated severity'}"
                 f" (engine confidence {claimed_confidence or 'unstated'})"
                 + (f" via agent {agent}" if agent else "") + f" at {reported}"]
        for label, key, limit in (("evidence", "evidence", MAX_AGENT_TEXT),
                                  ("technical analysis", "technical_analysis", MAX_AGENT_TEXT),
                                  ("proof of concept", "poc_description", MAX_AGENT_TEXT),
                                  ("PoC script", "poc_script_code", MAX_AGENT_TEXT),
                                  ("impact", "impact", 1000),
                                  ("counterevidence", "counterevidence", 1000)):
            text = _bounded(str(report.get(key) or ""), limit)
            if text:
                parts.append(f"{label}: {text}")

        cwe = _bounded(str(report.get("cwe") or ""), 40).upper()
        if re.fullmatch(r"\d+", cwe):
            cwe = f"CWE-{cwe}"       # the engine may store the bare number
        elif not re.fullmatch(r"CWE-\d+", cwe):
            cwe = ""

        description = " ".join(filter(None, (
            f"Reported by the strix-agent autonomous engine (run {run_id}) and not "
            "independently verified by Strix.",
            _bounded(str(report.get("description") or ""), 2000))))
        remediation = _bounded(str(report.get("remediation_steps") or ""), 2000) or (
            "Reproduce the issue from the recorded evidence before changing code; "
            "the claim is unverified.")

        return Finding(
            asset=target,
            category=f"agent_{slug}",
            title=title,
            severity=severity,
            confidence=confidence,
            detector=self.id,
            detector_version=self._version or "unknown",
            evidence=_agent_scrub("\n".join(parts))[:MAX_AGENT_EVIDENCE],
            location=location,
            description=_agent_scrub(description),
            remediation=remediation,
            cwe=cwe,
            verification="unverified",
        ), ""


ADAPTERS: dict[str, Adapter] = {
    a.id: a for a in (HTTPAdapter(), CrawlerAdapter(), DynamicValidationAdapter(),
                      OpenAPIAdapter(), AuthorizationDiffAdapter(), SSRFOOBAdapter(),
                      GitExposureAdapter(), TCPPortAdapter(), NmapAdapter(),
                      NucleiAdapter(), StrixAgentAdapter())
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
    "web-deep": ("strix-crawl", "strix-http", "strix-dynamic-validation",
                 "strix-git-exposure", "nuclei"),
    "api": ("strix-http", "strix-openapi", "strix-git-exposure"),
    "api-deep": ("strix-crawl", "strix-http", "strix-openapi", "strix-authz",
                 "strix-ssrf-oob", "strix-dynamic-validation",
                 "strix-git-exposure", "nuclei"),
    "ports": ("strix-tcp", "nmap"),
    "network": ("strix-http", "strix-tcp", "nmap", "strix-git-exposure"),
    # The agent is a whole engine on its own: it is the only adapter in this
    # profile so its coverage (and its absence) is never diluted by others.
    "agent": ("strix-agent",),
}


def select(profile: str) -> list[Adapter]:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; choose from {sorted(PROFILES)}")
    return [ADAPTERS[name] for name in PROFILES[profile]]


@dataclass(frozen=True)
class Holdings:
    """Allowlist model for native-only, Strix-only, and hybrid assessments.

    ``native`` and ``strix`` are independent gates on the same assessment:
    leaving one off is what makes a run native-only or Strix-only instead of
    hybrid. Both default off so a default install never accidentally launches
    the upstream engine.
    """
    native: bool = False
    strix: bool = False


def default_holdings(*, native: bool = False, strix: bool = False) -> Holdings:
    return Holdings(native=native, strix=strix)


def hybrid_required(holdings: Holdings) -> bool:
    return bool(holdings.native and holdings.strix)

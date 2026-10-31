"""Bounded same-origin crawler: discovery is filtered, capped and scope-gated.

The crawler only decides which pages exist. Every assertion here checks a
boundary that keeps it honest: same-origin, scope gate, page/depth/link caps,
and the hand-off contract with the HTTP assessment adapter.
"""
from __future__ import annotations

import contextlib
import threading
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

from strix.core.adapter_base import (
    Adapter,
    AdapterResult,
    checked_destination,
)
from strix.core.probe import EndpointProbe
from strix.core.scope import check as scope_check
from strix.core.scope import destination as scope_destination

# Budget caps: discovery is not a fuzzer.
MAX_PAGES = 100
MAX_DEPTH = 3
MAX_LINKS_PER_PAGE = 50
MAX_TOTAL_LINKS = 500

# Schemes that never produce a fetchable HTTP resource.
SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "blob:")


@dataclass
class CrawledPage:
    """A page that was actually fetched."""
    url: str
    status: int
    depth: int

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "status": self.status, "depth": self.depth}


@dataclass
class CrawlResult:
    """What the crawler discovered and what it actually fetched."""
    pages: list[CrawledPage] = field(default_factory=list)
    discovered: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class _LinkExtractor(HTMLParser):
    """Collect href/src values from a page."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_map = {k.lower(): v for k, v in attrs}
        if tag.lower() == "a" and "href" in attr_map:
            val = attr_map["href"]
            if val is not None:
                self.urls.append(val)
        elif tag.lower() in ("img", "script", "link", "iframe") and "src" in attr_map:
            val = attr_map["src"]
            if val is not None:
                self.urls.append(val)
        elif tag.lower() == "form" and "action" in attr_map:
            val = attr_map["action"]
            if val is not None:
                self.urls.append(val)


def normalize_candidate(base: str, candidate: str) -> str | None:
    """Normalize a link candidate against a base URL.

    Returns None for fragments, javascript:, mailto:, empty strings,
    and any URL with userinfo (credentials in URL).
    """
    if not candidate:
        return None

    candidate = candidate.strip()
    if not candidate:
        return None

    # Fragment-only: no new resource
    if candidate.startswith("#"):
        return None

    # Skip non-http schemes
    for scheme in SKIP_SCHEMES:
        if candidate.startswith(scheme):
            return None

    # Resolve relative URLs
    resolved = urljoin(base, candidate)

    # Parse to validate
    try:
        parsed = urlparse(resolved)
    except ValueError:
        return None

    # Reject URLs with credentials
    if parsed.username is not None or parsed.password is not None:
        return None

    # Only http/https
    if parsed.scheme not in ("http", "https"):
        return None

    # Strip fragment
    return parsed._replace(fragment="").geturl()


class WebCrawler:
    """Bounded same-origin crawler."""

    def __init__(
        self,
        max_pages: int = MAX_PAGES,
        max_depth: int = MAX_DEPTH,
        max_links_per_page: int = MAX_LINKS_PER_PAGE,
        max_total_links: int = MAX_TOTAL_LINKS,
        timeout: float = 10.0,
    ):
        self.max_pages = min(max_pages, MAX_PAGES)
        self.max_depth = min(max_depth, MAX_DEPTH)
        self.max_links_per_page = min(max_links_per_page, MAX_LINKS_PER_PAGE)
        self.max_total_links = min(max_total_links, MAX_TOTAL_LINKS)
        self.timeout = timeout

    def crawl(self, start_url: str, *, deadline: float,
               cancel: threading.Event | None = None) -> CrawlResult:
        """Crawl from start_url until deadline or budget exhausted."""
        result = CrawlResult()

        # Scope check the seed
        denial, reason, destination = scope_destination(start_url)
        if denial or destination is None:
            raise ValueError(f"scope refused {start_url}: {reason or 'destination unavailable'}")

        seed_origin = f"{destination.scheme}://{destination.host}"
        if destination.port not in (80, 443):
            seed_origin += f":{destination.port}"

        probe = EndpointProbe(timeout=self.timeout)

        # Queue of (url, depth)
        queue: list[tuple[str, int]] = [(start_url, 0)]
        seen: set[str] = {start_url}
        fetched: set[str] = set()
        link_count = 0

        while queue and len(fetched) < self.max_pages:
            if time.monotonic() >= deadline:
                result.notes.append("deadline reached before queue exhausted")
                break
            if cancel is not None and cancel.is_set():
                result.notes.append("crawl cancelled")
                break

            url, depth = queue.pop(0)

            if depth > self.max_depth:
                continue

            # Fetch the page
            try:
                response = probe._fetch(url, deadline=deadline)
            except Exception as exc:
                result.notes.append(f"fetch failed for {url}: {exc}")
                continue

            status = response.get("status", 0)
            if isinstance(status, int) and 200 <= status < 300:
                body = response.get("body", "")
                result.pages.append(CrawledPage(url=url, status=status, depth=depth))
                fetched.add(url)

                # Extract links if HTML (even at max_depth for discovery, but don't queue beyond max_depth)
                content_type = response.get("headers", {}).get("content-type", "").lower()
                if "text/html" in content_type and depth <= self.max_depth:
                    extractor = _LinkExtractor(url)
                    with contextlib.suppress(Exception):
                        extractor.feed(body)  # Malformed HTML - just skip link extraction

                    for raw_link in extractor.urls[:self.max_links_per_page]:
                        if link_count >= self.max_total_links:
                            result.notes.append("link budget exhausted")
                            break

                        normalized = normalize_candidate(url, raw_link)
                        if normalized is None:
                            continue

                        link_count += 1

                        # Same-origin check
                        try:
                            link_parsed = urlparse(normalized)
                            link_origin = f"{link_parsed.scheme}://{link_parsed.hostname}"
                            if link_parsed.port not in (80, 443, None):
                                link_origin += f":{link_parsed.port}"
                        except Exception:
                            continue

                        if link_origin != seed_origin:
                            continue

                        # Scope check each discovered URL
                        link_denial, link_reason = scope_check(normalized)
                        if link_denial:
                            continue

                        if normalized not in seen:
                            seen.add(normalized)
                            result.discovered.append(normalized)
                            # Only queue for fetching if we haven't reached max_depth
                            if depth < self.max_depth:
                                queue.append((normalized, depth + 1))
            else:
                result.pages.append(CrawledPage(url=url, status=status, depth=depth))
                fetched.add(url)
                if status == 404:
                    result.notes.append(f"{url} returned {status}")

        if len(fetched) >= self.max_pages:
            result.notes.append(f"max_pages ({self.max_pages}) reached")

        return result


class CrawlerAdapter(Adapter):
    """Adapter that runs the crawler and publishes discovered URLs to context."""

    id = "strix-crawl"
    version = "1.0"
    asset_types = ("web",)
    requires = ()

    def available(self) -> tuple[bool, str]:
        return True, "built in"

    def assess(
        self,
        target: str,
        *,
        timeout: float,
        cancel: threading.Event,
        context: dict[str, Any] | None = None,
    ) -> AdapterResult:
        destination = checked_destination(target)
        result = AdapterResult()

        deadline = time.monotonic() + timeout
        crawler = WebCrawler(timeout=min(10.0, timeout / 2))
        # Destination has no url attribute; construct it
        start_url = f"{destination.scheme}://{destination.host}:{destination.port}"
        crawl_result = crawler.crawl(start_url, deadline=deadline)

        if crawl_result.pages:
            result.notes.append(
                f"crawled {len(crawl_result.pages)} pages, "
                f"discovered {len(crawl_result.discovered)} URLs"
            )
        else:
            result.notes.append("no pages crawled")

        # Publish discovered URLs to context for downstream adapters
        if context is not None:
            context["discovered_urls"] = crawl_result.discovered
            context["crawl_pages"] = [
                {"url": p.url, "status": p.status, "depth": p.depth}
                for p in crawl_result.pages
            ]

        return result

"""Bounded same-origin crawler: discovery is filtered, capped and scope-gated.

The crawler only decides which pages exist. Every assertion here checks a
boundary that keeps it honest: same-origin, scope gate, page/depth/link caps,
and the hand-off contract with the HTTP assessment adapter.
"""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest

from strix.core.adapters import CrawlerAdapter
from strix.core.crawler import WebCrawler, normalize_candidate
from strix.core.jobs import JobState, run_assessment


class SiteHandler(BaseHTTPRequestHandler):
    """Tiny multi-page site. `pages` maps path -> (status, html body)."""

    pages: dict[str, tuple[int, str]] = {}
    hits: list[str] = []

    def do_GET(self):
        path = urlparse(self.path).path
        type(self).hits.append(path)
        status, body = type(self).pages.get(path, (404, "<html>missing</html>"))
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def site(monkeypatch):
    """A loopback mini-site served through the real scope gate."""
    SiteHandler.pages = {}
    SiteHandler.hits = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), SiteHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield type("Site", (), {"base": f"http://127.0.0.1:{server.server_port}",
                                "hits": SiteHandler.hits, "pages": SiteHandler.pages})
    finally:
        server.shutdown()
        server.server_close()


PAGE = """<html><body>
<a href="/alpha">alpha</a>
<a href="/beta?q=1">beta</a>
<a href="/#section">fragment</a>
<a href="mailto:x@example.com">mail</a>
<a href="javascript:void(0)">js</a>
<a href="https://example.com/cross">cross origin, in scope</a>
<a href="https://evil.com/x">cross origin, in scope</a>
<a href="/loop">self loop</a>
</body></html>"""


def test_same_origin_and_scope_boundaries(site):
    site.pages["/"] = (200, PAGE)
    crawl = WebCrawler(max_pages=10, max_depth=1).crawl(
        site.base + "/", deadline=time.monotonic() + 20)
    # Only same-origin links are discovered — even though the fixture scope
    # would allow example.com and evil.com, the crawler never leaves the origin.
    assert site.base + "/alpha" in crawl.discovered
    assert site.base + "/beta?q=1" in crawl.discovered
    assert "https://example.com/cross" not in crawl.discovered
    assert "https://evil.com/x" not in crawl.discovered
    # Fragments, mailto, javascript produce no candidates.
    assert site.base + "/loop" in crawl.discovered  # loop is deduped against queue, kept once
    assert crawl.discovered.count(site.base + "/loop") == 1
    assert all(not url.startswith("mailto:") for url in crawl.discovered)


def test_out_of_scope_links_are_never_discovered(site, monkeypatch):
    """A link inside the origin but outside the scope cannot be discovered."""
    site.pages["/"] = (200, '<a href="http://127.0.0.1:1/secret">other port</a>')
    crawl = WebCrawler(max_pages=5, max_depth=1).crawl(
        site.base + "/", deadline=time.monotonic() + 10)
    assert crawl.discovered == []  # different port = different origin AND refused port scope


def test_page_and_depth_limits(site):
    body = "".join(f'<a href="/page{i}">p{i}</a>' for i in range(10))
    site.pages["/"] = (200, body)
    crawl = WebCrawler(max_pages=3, max_depth=2).crawl(
        site.base + "/", deadline=time.monotonic() + 20)
    assert len(crawl.pages) == 3
    assert any("max_pages" in note for note in crawl.notes)
    # discovered links still enumerate everything harvested from fetched pages
    assert len(crawl.discovered) >= 10


def test_depth_limit_stops_following(site):
    site.pages["/"] = (200, '<a href="/level1">l1</a>')
    site.pages["/level1"] = (200, '<a href="/level2">l2</a>')
    site.pages["/level2"] = (200, '<a href="/level3">l3</a>')
    crawl = WebCrawler(max_pages=10, max_depth=1).crawl(
        site.base + "/", deadline=time.monotonic() + 20)
    fetched = {page.url for page in crawl.pages}
    assert site.base + "/level1" in fetched
    assert site.base + "/level2" not in fetched  # depth 2 > max_depth 1
    # discovery is independent of queueing: /level2 was harvested from /level1
    assert site.base + "/level2" in crawl.discovered
    assert site.base + "/level3" not in crawl.discovered


def test_error_pages_are_not_crawled_for_more_links(site):
    site.pages["/"] = (200, '<a href="/gone">gone</a>')
    site.pages["/gone"] = (404, '<a href="/ghost">ghost</a>')
    crawl = WebCrawler(max_pages=5, max_depth=2).crawl(
        site.base + "/", deadline=time.monotonic() + 20)
    fetched = {page.url for page in crawl.pages}
    assert site.base + "/gone" in fetched        # the 404 page itself was fetched
    assert site.base + "/ghost" not in crawl.discovered  # its links were not harvested


def test_deadline_stops_crawl(site):
    site.pages["/"] = (200, PAGE)
    deadline = time.monotonic()
    crawl = WebCrawler(max_pages=10, max_depth=2).crawl(
        site.base + "/", deadline=deadline)
    assert any("deadline" in note for note in crawl.notes)
    # a fully expired budget fetched nothing
    assert crawl.pages == []


def test_crawler_refuses_out_of_scope_seed():
    with pytest.raises(ValueError, match="scope refused"):
        WebCrawler().crawl("https://not-in-scope.example/",
                           deadline=time.monotonic() + 5)


def test_normalize_candidate_variants():
    base = "https://app.example.com/dir/page"
    assert normalize_candidate(base, "/x") == "https://app.example.com/x"
    assert normalize_candidate(base, "sub") == "https://app.example.com/dir/sub"
    assert normalize_candidate(base, "?q=2") == "https://app.example.com/dir/page?q=2"
    assert normalize_candidate(base, "//other.example.com/p") == \
        "https://other.example.com/p"
    assert normalize_candidate(base, "#frag") is None
    assert normalize_candidate(base, "javascript:alert(1)") is None
    assert normalize_candidate(base, "https://u:p@host/x") is None
    assert normalize_candidate(base, "") is None


def test_crawler_adapter_publishes_context_for_http_adapter(site):
    site.pages["/"] = (200, PAGE)
    adapter = CrawlerAdapter()
    context: dict = {}
    result = adapter.assess(site.base + "/", timeout=30.0,
                            cancel=threading.Event(), context=context)
    assert result.findings == []  # discovery is not a verdict
    assert context["discovered_urls"]
    assert all(url.startswith(site.base) for url in context["discovered_urls"])
    assert any("discovered" in note for note in result.notes)
    assert isinstance(context["crawl_pages"], list)


def test_http_adapter_probes_crawler_discovered_pages(site):
    from strix.core.adapters import HTTPAdapter
    site.pages["/"] = (200, '<a href="/admin">admin</a><a href="/public">public</a>')
    site.pages["/admin"] = (200, "admin page")
    site.pages["/public"] = (200, "public page")
    # unauthorized.example is not in the fixture scope (evil.com is, which is
    # why the previous version of this test made a real outbound connection and
    # passed or failed depending on what the environment answered).
    context = {"discovered_urls": [site.base + "/admin", site.base + "/public",
                                   "https://unauthorized.example/injected"]}
    result = HTTPAdapter().assess(site.base + "/", timeout=30.0,
                                  cancel=threading.Event(), context=context)
    # both in-scope discovered pages were really fetched through the gate
    assert "/admin" in site.hits and "/public" in site.hits
    # the out-of-scope injection was re-checked and never contacted
    assert all("unauthorized.example" not in finding.location
               for finding in result.findings)
    # each discovered page contributed its own missing-CSP observation
    assert sum(1 for f in result.findings if f.category == "missing_csp") == 3


def test_http_adapter_never_probes_discovered_urls_without_scope(site):
    from strix.core.adapters import HTTPAdapter
    before = len(site.hits)
    context = {"discovered_urls": ["https://unauthorized.example/x"]}
    HTTPAdapter().assess(site.base + "/", timeout=20.0,
                         cancel=threading.Event(), context=context)
    # only the seed fetch happened; the out-of-scope URL was re-checked and refused
    assert len(site.hits) == before + 1
    assert all("unauthorized.example" not in hit for hit in site.hits)


def test_web_crawl_profile_runs_crawler_then_http(site):
    site.pages["/"] = (200, '<a href="/discovered-page">d</a>')
    site.pages["/discovered-page"] = (200, "found")
    job = run_assessment(site.base + "/", profile="web-crawl", timeout=60.0)
    assert job.state is JobState.COMPLETED, job.error
    states = {run.adapter: run.state.value for run in job.runs}
    assert states["strix-crawl"] == "ok"
    assert states["strix-http"] == "ok"
    assert "/discovered-page" in site.hits  # the hand-off really fetched it
    crawler_note = next(run.detail for run in job.runs if run.adapter == "strix-crawl")
    assert "discovered" in crawler_note


def test_crawl_job_without_crawler_context_still_assesses_target(site):
    job = run_assessment(site.base + "/", profile="web", timeout=30.0)
    assert job.state is JobState.COMPLETED, job.error
    assert "/" in site.hits

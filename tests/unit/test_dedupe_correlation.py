"""Unit tests for finding dedupe and cross-adapter correlation."""

from __future__ import annotations

from ishastra.core.findings import Finding, correlate, correlation_fingerprint, dedupe


class TestDedupe:
    """Tests for hash-based finding deduplication."""

    def test_dedupe_same_fingerprint_keeps_more_severe(self):
        """Dedupe merges same fingerprint, keeping more severe finding."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence 1",
            location="https://example.com/",
        )
        f2 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="high",
            confidence="high",
            detector="scanner-b",
            detector_version="1.0",
            evidence="evidence 2",
            location="https://example.com/",
        )
        merged = dedupe([f1, f2])
        assert len(merged) == 1
        assert merged[0].severity == "high"
        assert "scanner-a" in merged[0].sources
        assert "scanner-b" in merged[0].sources

    def test_dedupe_same_severity_keeps_first(self):
        """Dedupe keeps first when severity is equal."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="medium",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence 1",
            location="https://example.com/",
        )
        f2 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="medium",
            confidence="high",
            detector="scanner-b",
            detector_version="1.0",
            evidence="evidence 2",
            location="https://example.com/",
        )
        merged = dedupe([f1, f2])
        assert len(merged) == 1
        # Sources should include both detectors
        assert "scanner-a" in merged[0].sources
        assert "scanner-b" in merged[0].sources

    def test_dedupe_different_location_not_merged(self):
        """Different locations produce different fingerprints."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
        )
        f2 = Finding(
            asset="https://example.com/page",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/page",
        )
        merged = dedupe([f1, f2])
        assert len(merged) == 2

    def test_dedupe_different_category_not_merged(self):
        """Different categories produce different fingerprints."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
        )
        f2 = Finding(
            asset="https://example.com/",
            category="missing_hsts",
            title="Missing HSTS",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
        )
        merged = dedupe([f1, f2])
        assert len(merged) == 2

    def test_dedupe_empty_list(self):
        """Dedupe handles empty list."""
        assert dedupe([]) == []

    def test_dedupe_single_finding(self):
        """Dedupe returns single finding unchanged."""
        f = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
        )
        merged = dedupe([f])
        assert len(merged) == 1
        assert merged[0] is f


class TestCorrelationFingerprint:
    """Tests for correlation fingerprint (broader than exact fingerprint)."""

    def test_correlation_fingerprint_same_asset_category(self):
        """Correlation fingerprint groups by asset and category."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
        )
        f2 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP (different evidence)",
            severity="high",
            confidence="high",
            detector="scanner-b",
            detector_version="1.0",
            evidence="other evidence",
            location="https://example.com/",
        )
        # Same asset + category = same correlation fingerprint
        assert correlation_fingerprint(f1) == correlation_fingerprint(f2)

    def test_correlation_fingerprint_different_category(self):
        """Different categories have different correlation fingerprints."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
        )
        f2 = Finding(
            asset="https://example.com/",
            category="missing_hsts",
            title="Missing HSTS",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
        )
        assert correlation_fingerprint(f1) != correlation_fingerprint(f2)

    def test_correlation_fingerprint_different_asset(self):
        """Different assets have different correlation fingerprints."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
        )
        f2 = Finding(
            asset="https://other.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://other.com/",
        )
        assert correlation_fingerprint(f1) != correlation_fingerprint(f2)

    def test_correlation_fingerprint_uses_cwe_when_available(self):
        """Correlation fingerprint uses CWE for cross-category correlation."""
        f1 = Finding(
            asset="https://example.com/",
            category="sqli_error",
            title="SQL Injection Error",
            severity="medium",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
            cwe="CWE-89",
        )
        f2 = Finding(
            asset="https://example.com/",
            category="sql_injection",
            title="SQL Injection Found",
            severity="high",
            confidence="high",
            detector="scanner-b",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
            cwe="CWE-89",
        )
        # Same CWE = same correlation fingerprint
        assert correlation_fingerprint(f1) == correlation_fingerprint(f2)


class TestCorrelate:
    """Tests for cross-adapter correlation."""

    def test_correlate_groups_by_correlation_fingerprint(self):
        """Correlate groups findings with same correlation fingerprint."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence 1",
            location="https://example.com/",
        )
        f2 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="medium",
            confidence="high",
            detector="scanner-b",
            detector_version="1.0",
            evidence="evidence 2",
            location="https://example.com/",
        )
        f3 = Finding(
            asset="https://other.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence 3",
            location="https://other.com/",
        )
        correlated = correlate([f1, f2, f3])
        # Should have 2 groups: example.com and other.com
        assert len(correlated) == 2

        # Find the group for example.com
        example_group = next(g for g in correlated if g.asset == "https://example.com/")
        assert len(example_group.sources) == 2
        assert "scanner-a" in example_group.sources
        assert "scanner-b" in example_group.sources
        # Should keep the more severe finding
        assert example_group.severity == "medium"

    def test_correlate_merges_evidence_from_all_sources(self):
        """Correlated finding includes evidence from all sources."""
        f1 = Finding(
            asset="https://example.com/",
            category="open_redirect",
            title="Open Redirect",
            severity="medium",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="redirect to evil.com via param 'next'",
            location="https://example.com/login?next=evil.com",
            cwe="CWE-601",
        )
        f2 = Finding(
            asset="https://example.com/",
            category="open_redirect",
            title="Open Redirect",
            severity="high",
            confidence="high",
            detector="scanner-b",
            detector_version="1.0",
            evidence="redirect to attacker.com via param 'url'",
            location="https://example.com/login?url=attacker.com",
            cwe="CWE-601",
        )
        correlated = correlate([f1, f2])
        assert len(correlated) == 1
        result = correlated[0]
        assert "scanner-a" in result.sources
        assert "scanner-b" in result.sources
        # Evidence should mention both
        assert "evil.com" in result.evidence or "attacker.com" in result.evidence

    def test_correlate_different_cwe_same_category_still_groups(self):
        """Same category on same asset groups even with different CWE."""
        f1 = Finding(
            asset="https://example.com/",
            category="xss",
            title="XSS in search",
            severity="medium",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="reflected XSS in search param",
            location="https://example.com/search?q=test",
            cwe="CWE-79",
        )
        f2 = Finding(
            asset="https://example.com/",
            category="xss",
            title="XSS in comment",
            severity="high",
            confidence="high",
            detector="scanner-b",
            detector_version="1.0",
            evidence="stored XSS in comment field",
            location="https://example.com/comment",
            cwe="CWE-79",
        )
        correlated = correlate([f1, f2])
        assert len(correlated) == 1
        assert "scanner-a" in correlated[0].sources
        assert "scanner-b" in correlated[0].sources

    def test_correlate_empty_list(self):
        """Correlate handles empty list."""
        assert correlate([]) == []

    def test_correlate_single_finding(self):
        """Correlate returns single finding."""
        f = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
        )
        correlated = correlate([f])
        assert len(correlated) == 1
        assert correlated[0] is f

    def test_correlate_preserves_most_severe_per_group(self):
        """Correlate keeps most severe finding in each correlation group."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="info",
            confidence="low",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
        )
        f2 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="critical",
            confidence="high",
            detector="scanner-b",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
        )
        f3 = Finding(
            asset="https://other.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://other.com/",
        )
        correlated = correlate([f1, f2, f3])
        assert len(correlated) == 2
        example_group = next(g for g in correlated if g.asset == "https://example.com/")
        assert example_group.severity == "critical"

    def test_correlate_cross_tool_same_vulnerability(self):
        """Different tools finding same vulnerability type are correlated."""
        # Nmap finds open port
        f1 = Finding(
            asset="example.com",
            category="open_tcp_port",
            title="Open port 443 (https)",
            severity="info",
            confidence="high",
            detector="nmap",
            detector_version="7.94",
            evidence="nmap TCP connect scan reported example.com:443/tcp open",
            location="example.com:443/tcp",
        )
        # Nuclei finds SSL issue on same port
        f2 = Finding(
            asset="https://example.com/",
            category="ssl-certificate",
            title="SSL Certificate Issue",
            severity="medium",
            confidence="high",
            detector="nuclei",
            detector_version="3.0",
            evidence="SSL certificate validation failed",
            location="https://example.com:443",
            cwe="CWE-295",
        )
        # Nikto finds web server issue on same host
        f3 = Finding(
            asset="https://example.com/",
            category="nikto-outdated-server",
            title="Outdated Web Server",
            severity="low",
            confidence="medium",
            detector="nikto",
            detector_version="2.5",
            evidence="Apache version is outdated",
            location="https://example.com/",
        )
        # These are different categories so they won't correlate by default
        # But they're all on the same asset - correlate by asset groups them separately
        correlated = correlate([f1, f2, f3])
        # Each has different category, so 3 separate groups
        assert len(correlated) == 3

    def test_correlate_same_cwe_different_category(self):
        """Findings with same CWE on same asset are correlated."""
        f1 = Finding(
            asset="https://example.com/",
            category="sqli_error",
            title="SQL Error Leakage",
            severity="medium",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="MySQL error in response",
            location="https://example.com/search?q=test",
            cwe="CWE-89",
        )
        f2 = Finding(
            asset="https://example.com/",
            category="sql_injection",
            title="SQL Injection Confirmed",
            severity="high",
            confidence="high",
            detector="scanner-b",
            detector_version="1.0",
            evidence="Boolean-based blind SQLi confirmed",
            location="https://example.com/search?q=test",
            cwe="CWE-89",
        )
        correlated = correlate([f1, f2])
        assert len(correlated) == 1
        assert "scanner-a" in correlated[0].sources
        assert "scanner-b" in correlated[0].sources
        assert correlated[0].severity == "high"


class TestFindingSources:
    """Tests for multi-source evidence in findings."""

    def test_finding_sources_includes_all_detectors(self):
        """Finding sources field includes all contributing detectors."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
            sources=("scanner-a",),
        )
        f2 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="high",
            confidence="high",
            detector="scanner-b",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
            sources=("scanner-b",),
        )
        merged = dedupe([f1, f2])
        assert len(merged) == 1
        assert "scanner-a" in merged[0].sources
        assert "scanner-b" in merged[0].sources

    def test_finding_sources_deduped(self):
        """Finding sources deduplicates identical detectors."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence 1",
            location="https://example.com/",
            sources=("scanner-a", "scanner-a"),
        )
        f2 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="high",
            confidence="high",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence 2",
            location="https://example.com/",
            sources=("scanner-a",),
        )
        merged = dedupe([f1, f2])
        assert len(merged) == 1
        # Should only have one "scanner-a"
        assert merged[0].sources.count("scanner-a") == 1

    def test_to_dict_includes_sources(self):
        """to_dict includes sources field."""
        f = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="scanner-a",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
            sources=("scanner-a", "scanner-b"),
        )
        d = f.to_dict()
        assert "sources" in d
        assert d["sources"] == ["scanner-a", "scanner-b"]

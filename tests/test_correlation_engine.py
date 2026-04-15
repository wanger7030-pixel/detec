"""
Unit tests for the correlation engine.

Tests the five-dimension weighted correlation logic:
IP address, domain, file hash, behaviour/TTP matching,
and multiplicative time window boosting.
"""

import pytest

from src.correlation_engine import CorrelationEngine, CorrelationReport
from src.plugin_framework import (
    Alert, AlertSeverity, AnalysisResult, AnalysisSource,
    IoC, IoCType,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def engine():
    return CorrelationEngine(
        weights={
            "ip_address": 0.35,
            "domain": 0.20,
            "file_hash": 0.30,
            "behavior": 0.15,
        },
        threshold=0.3,
        time_window=300,
        time_boost=1.3,
    )


def make_alert(
    alert_id, source, iocs=None, details=None,
    timestamp="2025-01-15T12:00:00Z"
):
    """Helper to create test alerts."""
    return Alert(
        alert_id=alert_id,
        source=source,
        severity=AlertSeverity.MEDIUM,
        message=f"Test alert {alert_id}",
        timestamp=timestamp,
        details=details or {},
        iocs=iocs or [],
    )


def make_ioc(ioc_type, value, source):
    return IoC(ioc_type=ioc_type, value=value, source=source)


# ============================================================================
# Basic Correlation Tests
# ============================================================================

class TestCorrelationBasic:

    def test_no_alerts(self, engine):
        results = engine.correlate()
        assert results == []

    def test_single_alert(self, engine):
        engine.add_alerts([
            make_alert("A-001", AnalysisSource.SNORT)
        ])
        results = engine.correlate()
        assert results == []

    def test_same_source_not_correlated(self, engine):
        """Alerts from the same source should NOT be correlated."""
        ip_ioc = make_ioc(IoCType.IP_ADDRESS, "10.0.0.1", AnalysisSource.SNORT)
        engine.add_alerts([
            make_alert("A-001", AnalysisSource.SNORT, iocs=[ip_ioc]),
            make_alert("A-002", AnalysisSource.SNORT, iocs=[ip_ioc]),
        ])
        results = engine.correlate()
        assert len(results) == 0


# ============================================================================
# IP Address Correlation
# ============================================================================

class TestIPCorrelation:

    def test_matching_ip(self, engine):
        ip_ioc = make_ioc(IoCType.IP_ADDRESS, "192.168.1.100", AnalysisSource.SNORT)
        ip_ioc2 = make_ioc(IoCType.IP_ADDRESS, "192.168.1.100", AnalysisSource.YARA)

        engine.add_alerts([
            make_alert("A-001", AnalysisSource.SNORT, iocs=[ip_ioc]),
            make_alert("A-002", AnalysisSource.YARA, iocs=[ip_ioc2]),
        ])
        results = engine.correlate()
        assert len(results) > 0
        assert results[0].total_score >= 0.35  # IP weight

    def test_no_matching_ip(self, engine):
        engine.add_alerts([
            make_alert("A-001", AnalysisSource.SNORT,
                       iocs=[make_ioc(IoCType.IP_ADDRESS, "1.1.1.1", AnalysisSource.SNORT)]),
            make_alert("A-002", AnalysisSource.YARA,
                       iocs=[make_ioc(IoCType.IP_ADDRESS, "2.2.2.2", AnalysisSource.YARA)]),
        ])
        results = engine.correlate()
        # No IP match, only possibly time window
        for r in results:
            ip_matches = [m for m in r.matches if m.correlation_type == "ip_address"]
            assert len(ip_matches) == 0

    def test_ip_from_details(self, engine):
        """IPs in alert details should also be matched."""
        engine.add_alerts([
            make_alert("A-001", AnalysisSource.SNORT,
                       details={"src_ip": "10.0.0.5"}),
            make_alert("A-002", AnalysisSource.YARA,
                       details={"dst_ip": "10.0.0.5"}),
        ])
        results = engine.correlate()
        # Should find IP match in details
        has_ip = any(
            any(m.correlation_type == "ip_address" for m in r.matches)
            for r in results
        )
        assert has_ip


# ============================================================================
# Domain Correlation
# ============================================================================

class TestDomainCorrelation:

    def test_matching_domain(self):
        """Domain match should correctly identify shared domains."""
        # Use lower threshold since domain weight (0.20) < default threshold (0.30)
        eng = CorrelationEngine(
            weights={"ip_address": 0.35, "domain": 0.20, "file_hash": 0.30, "behavior": 0.15},
            threshold=0.1, time_window=300, time_boost=1.3,
        )
        dom1 = make_ioc(IoCType.DOMAIN, "evil.com", AnalysisSource.SNORT)
        dom2 = make_ioc(IoCType.DOMAIN, "evil.com", AnalysisSource.DYNAMIC_CAPE)

        eng.add_alerts([
            make_alert("A-001", AnalysisSource.SNORT, iocs=[dom1]),
            make_alert("A-002", AnalysisSource.DYNAMIC_CAPE, iocs=[dom2]),
        ])
        results = eng.correlate()
        assert len(results) > 0
        domain_matches = [
            m for r in results for m in r.matches
            if m.correlation_type == "domain"
        ]
        assert len(domain_matches) >= 1


# ============================================================================
# File Hash Correlation
# ============================================================================

class TestHashCorrelation:

    def test_matching_sha256(self, engine):
        hash_val = "a" * 64
        h1 = make_ioc(IoCType.FILE_HASH_SHA256, hash_val, AnalysisSource.STATIC)
        h2 = make_ioc(IoCType.FILE_HASH_SHA256, hash_val, AnalysisSource.YARA)

        engine.add_alerts([
            make_alert("A-001", AnalysisSource.STATIC, iocs=[h1]),
            make_alert("A-002", AnalysisSource.YARA, iocs=[h2]),
        ])
        results = engine.correlate()
        hash_matches = [
            m for r in results for m in r.matches
            if m.correlation_type == "file_hash"
        ]
        assert len(hash_matches) >= 1

    def test_matching_md5(self, engine):
        md5_val = "b" * 32
        h1 = make_ioc(IoCType.FILE_HASH_MD5, md5_val, AnalysisSource.STATIC)
        h2 = make_ioc(IoCType.FILE_HASH_MD5, md5_val, AnalysisSource.DYNAMIC_CAPE)

        engine.add_alerts([
            make_alert("A-001", AnalysisSource.STATIC, iocs=[h1]),
            make_alert("A-002", AnalysisSource.DYNAMIC_CAPE, iocs=[h2]),
        ])
        results = engine.correlate()
        assert any(
            m.correlation_type == "file_hash"
            for r in results for m in r.matches
        )


# ============================================================================
# Time Window Correlation
# ============================================================================

class TestTimeCorrelation:
    """Time window is now a multiplicative booster, not an additive dimension."""

    @pytest.fixture
    def boost_engine(self):
        """Engine to test multiplicative time boosting."""
        return CorrelationEngine(
            weights={
                "ip_address": 0.35,
                "domain": 0.20,
                "file_hash": 0.30,
                "behavior": 0.15,
            },
            threshold=0.05,
            time_window=300,
            time_boost=1.3,
        )

    def test_time_boosts_existing_match(self, boost_engine):
        """Time proximity should boost score when IoC match exists."""
        ip1 = make_ioc(IoCType.IP_ADDRESS, "10.0.0.1", AnalysisSource.SNORT)
        ip2 = make_ioc(IoCType.IP_ADDRESS, "10.0.0.1", AnalysisSource.YARA)
        boost_engine.add_alerts([
            make_alert("A-001", AnalysisSource.SNORT,
                       iocs=[ip1],
                       timestamp="2025-01-15T12:00:00Z"),
            make_alert("A-002", AnalysisSource.YARA,
                       iocs=[ip2],
                       timestamp="2025-01-15T12:04:00Z"),
        ])
        results = boost_engine.correlate()
        assert len(results) > 0
        report = results[0]
        # Score should be IP (0.35) * time_boost (1.3) = 0.455
        assert report.total_score > 0.35
        time_matches = [
            m for m in report.matches
            if m.correlation_type == "time_window"
        ]
        assert len(time_matches) == 1

    def test_time_alone_no_boost(self, boost_engine):
        """Time proximity alone (no IoC match) should NOT produce correlation."""
        boost_engine.add_alerts([
            make_alert("A-001", AnalysisSource.SNORT,
                       timestamp="2025-01-15T12:00:00Z"),
            make_alert("A-002", AnalysisSource.YARA,
                       timestamp="2025-01-15T12:04:00Z"),
        ])
        results = boost_engine.correlate()
        time_matches = [
            m for r in results for m in r.matches
            if m.correlation_type == "time_window"
        ]
        assert len(time_matches) == 0

    def test_outside_window_no_boost(self, boost_engine):
        """Events outside time window should not get time boost."""
        ip1 = make_ioc(IoCType.IP_ADDRESS, "10.0.0.1", AnalysisSource.SNORT)
        ip2 = make_ioc(IoCType.IP_ADDRESS, "10.0.0.1", AnalysisSource.YARA)
        boost_engine.add_alerts([
            make_alert("A-001", AnalysisSource.SNORT,
                       iocs=[ip1],
                       timestamp="2025-01-15T12:00:00Z"),
            make_alert("A-002", AnalysisSource.YARA,
                       iocs=[ip2],
                       timestamp="2025-01-15T13:00:00Z"),
        ])
        results = boost_engine.correlate()
        time_matches = [
            m for r in results for m in r.matches
            if m.correlation_type == "time_window"
        ]
        assert len(time_matches) == 0
        # Score should be exactly IP weight (0.35), no boost
        if results:
            assert results[0].total_score == pytest.approx(0.35, abs=0.01)


# ============================================================================
# Multi-Dimension Correlation
# ============================================================================

class TestMultiDimensionCorrelation:

    def test_all_dimensions_match(self, engine):
        """Alert pair matching on all 5 dimensions should score ~1.0."""
        shared_ip = make_ioc(IoCType.IP_ADDRESS, "10.0.0.1", AnalysisSource.SNORT)
        shared_ip2 = make_ioc(IoCType.IP_ADDRESS, "10.0.0.1", AnalysisSource.YARA)
        shared_dom = make_ioc(IoCType.DOMAIN, "c2.evil.org", AnalysisSource.SNORT)
        shared_dom2 = make_ioc(IoCType.DOMAIN, "c2.evil.org", AnalysisSource.YARA)
        shared_hash = make_ioc(IoCType.FILE_HASH_SHA256, "x" * 64, AnalysisSource.SNORT)
        shared_hash2 = make_ioc(IoCType.FILE_HASH_SHA256, "x" * 64, AnalysisSource.YARA)

        engine.add_alerts([
            make_alert("A-001", AnalysisSource.SNORT,
                       iocs=[shared_ip, shared_dom, shared_hash],
                       details={"malware_family": "ramnit"},
                       timestamp="2025-01-15T12:00:00Z"),
            make_alert("A-002", AnalysisSource.YARA,
                       iocs=[shared_ip2, shared_dom2, shared_hash2],
                       details={"malware_family": "ramnit"},
                       timestamp="2025-01-15T12:02:00Z"),
        ])
        results = engine.correlate()
        assert len(results) == 1
        report = results[0]
        assert report.is_correlated is True
        # Should have matches from multiple dimensions (IP+domain+hash+behavior+time)
        assert len(report.matches) >= 4
        assert report.total_score >= 0.9

    def test_threshold_filter(self):
        """Pairs below threshold should not be flagged as correlated."""
        engine = CorrelationEngine(threshold=0.9, time_window=300)
        engine.add_alerts([
            make_alert("A-001", AnalysisSource.SNORT,
                       iocs=[make_ioc(IoCType.IP_ADDRESS, "1.1.1.1", AnalysisSource.SNORT)],
                       timestamp="2025-01-15T12:00:00Z"),
            make_alert("A-002", AnalysisSource.YARA,
                       iocs=[make_ioc(IoCType.IP_ADDRESS, "1.1.1.1", AnalysisSource.YARA)],
                       timestamp="2025-01-15T12:02:00Z"),
        ])
        results = engine.correlate()
        # IP (0.35) * time_boost (1.3) = 0.455, below 0.9 threshold
        assert all(not r.is_correlated for r in results)


# ============================================================================
# Engine State Management
# ============================================================================

class TestEngineState:

    def test_clear(self, engine):
        engine.add_alerts([make_alert("A-001", AnalysisSource.SNORT)])
        engine.clear()
        results = engine.correlate()
        assert results == []

    def test_add_analysis_results(self, engine):
        result = AnalysisResult(
            analyzer_name="Test",
            source=AnalysisSource.SNORT,
            success=True,
            alerts=[make_alert("A-001", AnalysisSource.SNORT)],
        )
        engine.add_analysis_results([result])
        assert len(engine._alerts) == 1

    def test_results_sorted_by_score(self, engine):
        """Results should be sorted descending by score."""
        ip_shared = make_ioc(IoCType.IP_ADDRESS, "5.5.5.5", AnalysisSource.SNORT)
        ip_shared2 = make_ioc(IoCType.IP_ADDRESS, "5.5.5.5", AnalysisSource.STATIC)
        dom = make_ioc(IoCType.DOMAIN, "shared.org", AnalysisSource.SNORT)
        dom2 = make_ioc(IoCType.DOMAIN, "shared.org", AnalysisSource.YARA)

        engine.add_alerts([
            make_alert("A-001", AnalysisSource.SNORT, iocs=[ip_shared, dom]),
            make_alert("A-002", AnalysisSource.STATIC, iocs=[ip_shared2]),
            make_alert("A-003", AnalysisSource.YARA, iocs=[dom2]),
        ])
        results = engine.correlate()
        if len(results) >= 2:
            assert results[0].total_score >= results[1].total_score

    def test_correlation_report_to_dict(self, engine):
        ip = make_ioc(IoCType.IP_ADDRESS, "1.2.3.4", AnalysisSource.SNORT)
        ip2 = make_ioc(IoCType.IP_ADDRESS, "1.2.3.4", AnalysisSource.YARA)
        engine.add_alerts([
            make_alert("A-001", AnalysisSource.SNORT, iocs=[ip]),
            make_alert("A-002", AnalysisSource.YARA, iocs=[ip2]),
        ])
        results = engine.correlate()
        if results:
            d = results[0].to_dict()
            assert "alert_id_1" in d
            assert "total_score" in d
            assert "matches" in d

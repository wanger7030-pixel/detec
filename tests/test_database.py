"""
Unit tests for the database module.

Tests SQLite table creation, CRUD operations for alerts,
IoCs, samples, correlations, and statistics queries.
"""

import json
from pathlib import Path

import pytest

from src.database import Database
from src.plugin_framework import (
    Alert, AlertSeverity, AnalysisResult, AnalysisSource,
    IoC, IoCType,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def db(tmp_path):
    """Create a fresh in-memory-like database for each test."""
    db_path = tmp_path / "test.db"
    return Database(db_path=db_path)


@pytest.fixture
def sample_alert():
    return Alert(
        alert_id="TEST-ALERT-001",
        source=AnalysisSource.SNORT,
        severity=AlertSeverity.HIGH,
        message="Suspicious network traffic detected",
        timestamp="2025-06-15T10:00:00Z",
        details={"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1"},
        iocs=[
            IoC(
                ioc_type=IoCType.IP_ADDRESS,
                value="192.168.1.100",
                source=AnalysisSource.SNORT,
                context="Source IP",
            )
        ],
    )


@pytest.fixture
def sample_ioc():
    return IoC(
        ioc_type=IoCType.DOMAIN,
        value="evil.example.com",
        source=AnalysisSource.YARA,
        confidence=0.9,
        context="Found in YARA rule match",
    )


# ============================================================================
# Table Initialisation
# ============================================================================

class TestDatabaseInit:

    def test_database_created(self, db):
        assert db.db_path.exists()

    def test_tables_exist(self, db):
        stats = db.get_stats()
        assert stats["total_alerts"] == 0
        assert stats["total_iocs"] == 0
        assert stats["total_samples"] == 0
        assert stats["total_correlations"] == 0


# ============================================================================
# Alert CRUD
# ============================================================================

class TestAlertOperations:

    def test_insert_alert(self, db, sample_alert):
        row_id = db.insert_alert(sample_alert)
        assert row_id > 0

    def test_get_alerts(self, db, sample_alert):
        db.insert_alert(sample_alert)
        alerts = db.get_alerts()
        assert len(alerts) == 1
        assert alerts[0]["alert_id"] == "TEST-ALERT-001"
        assert alerts[0]["severity"] == "high"

    def test_get_alert_by_id(self, db, sample_alert):
        db.insert_alert(sample_alert)
        alert = db.get_alert_by_id("TEST-ALERT-001")
        assert alert is not None
        assert alert["message"] == "Suspicious network traffic detected"

    def test_get_alert_not_found(self, db):
        alert = db.get_alert_by_id("NONEXISTENT")
        assert alert is None

    def test_filter_by_source(self, db, sample_alert):
        db.insert_alert(sample_alert)

        yara_alert = Alert(
            alert_id="TEST-ALERT-002",
            source=AnalysisSource.YARA,
            severity=AlertSeverity.MEDIUM,
            message="YARA match",
            timestamp="2025-06-15T10:01:00Z",
        )
        db.insert_alert(yara_alert)

        snort_alerts = db.get_alerts(source="snort")
        assert len(snort_alerts) == 1
        assert snort_alerts[0]["source"] == "snort"

    def test_filter_by_severity(self, db, sample_alert):
        db.insert_alert(sample_alert)
        high_alerts = db.get_alerts(severity="high")
        assert len(high_alerts) == 1

        low_alerts = db.get_alerts(severity="low")
        assert len(low_alerts) == 0

    def test_duplicate_alert_ignored(self, db, sample_alert):
        db.insert_alert(sample_alert)
        db.insert_alert(sample_alert)  # Same alert_id
        alerts = db.get_alerts()
        assert len(alerts) == 1


# ============================================================================
# IoC CRUD
# ============================================================================

class TestIoCOperations:

    def test_insert_ioc(self, db, sample_ioc):
        db.insert_ioc(sample_ioc)
        iocs = db.get_iocs()
        assert len(iocs) == 1
        assert iocs[0]["value"] == "evil.example.com"

    def test_filter_by_type(self, db, sample_ioc):
        db.insert_ioc(sample_ioc)

        ip_ioc = IoC(
            ioc_type=IoCType.IP_ADDRESS,
            value="10.0.0.1",
            source=AnalysisSource.SNORT,
        )
        db.insert_ioc(ip_ioc)

        domain_iocs = db.get_iocs(ioc_type="domain")
        assert len(domain_iocs) == 1

        ip_iocs = db.get_iocs(ioc_type="ip_address")
        assert len(ip_iocs) == 1

    def test_find_matching_iocs(self, db, sample_ioc):
        db.insert_ioc(sample_ioc)
        matches = db.find_matching_iocs("evil.example.com")
        assert len(matches) == 1

        matches = db.find_matching_iocs("nonexistent.com")
        assert len(matches) == 0

    def test_alert_inserts_associated_iocs(self, db, sample_alert):
        db.insert_alert(sample_alert)
        iocs = db.get_iocs()
        # Alert has 1 IoC attached
        assert len(iocs) >= 1
        ip_values = [i["value"] for i in iocs]
        assert "192.168.1.100" in ip_values


# ============================================================================
# Sample CRUD
# ============================================================================

class TestSampleOperations:

    def test_insert_sample(self, db):
        sample_info = {
            "file_name": "malware.exe",
            "file_path": "/tmp/malware.exe",
            "md5": "abc123",
            "sha256": "def456",
            "file_size": 1024,
            "entropy": 7.5,
            "analysis_source": "static",
        }
        row_id = db.insert_sample(sample_info)
        assert row_id > 0

    def test_get_samples(self, db):
        db.insert_sample({"file_name": "test.exe"})
        samples = db.get_samples()
        assert len(samples) == 1


# ============================================================================
# Correlation CRUD
# ============================================================================

class TestCorrelationOperations:

    def test_insert_correlation(self, db, sample_alert):
        db.insert_alert(sample_alert)

        alert2 = Alert(
            alert_id="TEST-ALERT-002",
            source=AnalysisSource.YARA,
            severity=AlertSeverity.MEDIUM,
            message="YARA match",
            timestamp="2025-06-15T10:01:00Z",
        )
        db.insert_alert(alert2)

        corr = {
            "alert_id_1": "TEST-ALERT-001",
            "alert_id_2": "TEST-ALERT-002",
            "correlation_type": "ip_address",
            "score": 0.75,
            "matched_ioc": "192.168.1.100",
        }
        row_id = db.insert_correlation(corr)
        assert row_id > 0

    def test_get_correlations_with_score_filter(self, db, sample_alert):
        db.insert_alert(sample_alert)
        alert2 = Alert("TEST-002", AnalysisSource.YARA,
                        AlertSeverity.LOW, "Low", "2025-01-01T00:00:00Z")
        db.insert_alert(alert2)

        db.insert_correlation({
            "alert_id_1": "TEST-ALERT-001",
            "alert_id_2": "TEST-002",
            "correlation_type": "ip_address",
            "score": 0.3,
        })
        db.insert_correlation({
            "alert_id_1": "TEST-ALERT-001",
            "alert_id_2": "TEST-002",
            "correlation_type": "domain",
            "score": 0.8,
        })

        high_score = db.get_correlations(min_score=0.5)
        assert len(high_score) == 1
        assert high_score[0]["score"] == 0.8


# ============================================================================
# Statistics
# ============================================================================

class TestStatistics:

    def test_stats_counts(self, db, sample_alert, sample_ioc):
        db.insert_alert(sample_alert)
        db.insert_ioc(sample_ioc)
        db.insert_sample({"file_name": "test.exe"})

        stats = db.get_stats()
        assert stats["total_alerts"] == 1
        # alert also inserts 1 IoC + we inserted 1 standalone = 2
        assert stats["total_iocs"] >= 1
        assert stats["total_samples"] == 1

    def test_alerts_by_source(self, db, sample_alert):
        db.insert_alert(sample_alert)
        stats = db.get_stats()
        assert "snort" in stats["alerts_by_source"]


# ============================================================================
# Bulk Operations
# ============================================================================

class TestBulkOperations:

    def test_store_analysis_result(self, db):
        result = AnalysisResult(
            analyzer_name="TestAnalyzer",
            source=AnalysisSource.STATIC,
            success=True,
            alerts=[
                Alert("BULK-001", AnalysisSource.STATIC, AlertSeverity.HIGH,
                      "Alert 1", "2025-01-01T00:00:00Z"),
                Alert("BULK-002", AnalysisSource.STATIC, AlertSeverity.LOW,
                      "Alert 2", "2025-01-01T00:01:00Z"),
            ],
            iocs=[
                IoC(IoCType.IP_ADDRESS, "1.2.3.4", AnalysisSource.STATIC),
            ],
        )
        db.store_analysis_result(result)

        assert len(db.get_alerts()) == 2
        assert len(db.get_iocs()) >= 1


# ============================================================================
# Timeline
# ============================================================================

class TestTimeline:

    def test_timeline_data(self, db, sample_alert):
        db.insert_alert(sample_alert)
        data = db.get_timeline_data()
        assert "events" in data
        assert "links" in data
        assert len(data["events"]) == 1

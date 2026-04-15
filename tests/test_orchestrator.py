"""
Unit tests for the orchestrator module.

Tests pipeline setup, sample collection, report generation,
and CLI argument parsing.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from src.orchestrator import Orchestrator, main
from src.database import Database
from src.plugin_framework import AnalysisResult, AnalysisSource


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def db(tmp_path):
    return Database(db_path=tmp_path / "test.db")


@pytest.fixture
def orchestrator(db, tmp_path):
    """Create orchestrator with fresh DB and temp directories."""
    with patch("src.orchestrator.config") as mock_config:
        mock_config.ensure_directories = MagicMock()
        mock_config.DASHBOARD_HOST = "127.0.0.1"
        mock_config.DASHBOARD_PORT = 5000
        mock_config.DASHBOARD_DEBUG = False
        mock_config.CORRELATION_WEIGHTS = {
            "ip_address": 0.35,
            "domain": 0.25,
            "file_hash": 0.30,
            "time_window": 0.10,
        }
        mock_config.CORRELATION_THRESHOLD = 0.5
        mock_config.CORRELATION_TIME_WINDOW = 300
        mock_config.YARA_RULES_DIR = tmp_path / "rules" / "yara"
        mock_config.YARA_MAX_FILE_SIZE = 100 * 1024 * 1024
        mock_config.YARA_SCAN_TIMEOUT = 60
        mock_config.SNORT_BINARY = "/usr/local/bin/snort"
        mock_config.SNORT_CONFIG = "/etc/snort/snort.lua"
        mock_config.CAPE_API_URL = "http://localhost:8000/apiv2"
        mock_config.CAPE_API_TOKEN = ""
        mock_config.CAPE_MACHINE_NAME = "win10"
        mock_config.CAPE_ANALYSIS_TIMEOUT = 120
        mock_config.CAPE_POLL_INTERVAL = 10
        mock_config.ENTROPY_SUSPICIOUS_THRESHOLD = 7.0
        mock_config.STRINGS_MIN_LENGTH = 4
        mock_config.LOG_LEVEL = "WARNING"
        mock_config.LOG_FORMAT = "%(message)s"
        mock_config.LOG_DATE_FORMAT = "%H:%M:%S"
        mock_config.LOG_FILE = tmp_path / "test.log"
        mock_config.LOG_DIR = tmp_path
        mock_config.DATABASE_PATH = tmp_path / "test.db"
        mock_config.PROJECT_ROOT = tmp_path

        orch = Orchestrator(db=db)
        return orch


# ============================================================================
# Initialisation Tests
# ============================================================================

class TestOrchestratorInit:

    def test_analyzers_registered(self, orchestrator):
        assert "static" in orchestrator.analyzers
        assert "snort" in orchestrator.analyzers
        assert "yara" in orchestrator.analyzers
        assert "cape" in orchestrator.analyzers

    def test_database_attached(self, orchestrator, db):
        assert orchestrator.db is db


# ============================================================================
# Sample Collection Tests
# ============================================================================

class TestSampleCollection:

    def test_collect_files(self, tmp_path):
        f1 = tmp_path / "sample1.exe"
        f2 = tmp_path / "sample2.bin"
        f1.write_bytes(b"MZ" + b"\x00" * 100)
        f2.write_bytes(b"\x00" * 50)

        samples = Orchestrator._collect_samples(
            sample_files=[f1, f2],
            sample_dirs=None,
        )
        assert len(samples) == 2

    def test_collect_from_dir(self, tmp_path):
        d = tmp_path / "samples"
        d.mkdir()
        (d / "a.exe").write_bytes(b"MZ")
        (d / "b.exe").write_bytes(b"MZ")

        samples = Orchestrator._collect_samples(
            sample_files=None,
            sample_dirs=[d],
        )
        assert len(samples) == 2

    def test_collect_nonexistent_ignored(self, tmp_path):
        samples = Orchestrator._collect_samples(
            sample_files=[tmp_path / "nope.exe"],
            sample_dirs=None,
        )
        assert len(samples) == 0

    def test_collect_empty(self):
        samples = Orchestrator._collect_samples(None, None)
        assert samples == []


# ============================================================================
# Pipeline Tests (mocked external tools)
# ============================================================================

class TestPipeline:

    def test_full_analysis_no_inputs(self, orchestrator):
        """Running with no inputs should succeed with empty results."""
        report = orchestrator.run_full_analysis()
        assert "summary" in report
        assert report["summary"]["total_analyses"] == 0

    def test_full_analysis_static_only(self, orchestrator, tmp_path):
        """Static analysis on a test file should produce results."""
        sample = tmp_path / "test.exe"
        sample.write_bytes(
            b"MZ" + b"\x00" * 50
            + b"cmd.exe /c net user"
            + b"\x00" * 50
        )

        report = orchestrator.run_full_analysis(
            sample_files=[sample],
            skip_dynamic=True,
        )
        assert report["summary"]["total_analyses"] >= 1
        assert report["summary"]["successful_analyses"] >= 1

    def test_report_structure(self, orchestrator):
        report = orchestrator.run_full_analysis()
        assert "report_timestamp" in report
        assert "summary" in report
        assert "correlations" in report
        assert "analysis_results" in report

        summary = report["summary"]
        assert "total_analyses" in summary
        assert "total_alerts" in summary
        assert "total_iocs" in summary
        assert "alerts_by_source" in summary
        assert "alerts_by_severity" in summary


# ============================================================================
# Report Generation
# ============================================================================

class TestReportGeneration:

    def test_generate_report_empty_db(self, orchestrator):
        report = orchestrator._generate_report([])
        assert report["summary"]["total_alerts"] == 0
        assert report["correlations"] == []

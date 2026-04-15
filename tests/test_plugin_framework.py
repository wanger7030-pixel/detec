"""
Unit tests for the plugin framework.

Tests data models (IoC, Alert, AnalysisResult), BaseAnalyzer
interface, and PluginLoader functionality.
"""

import tempfile
from pathlib import Path
from typing import Any, List

import pytest

from src.plugin_framework import (
    Alert,
    AlertSeverity,
    AnalysisResult,
    AnalysisSource,
    BaseAnalyzer,
    IoC,
    IoCType,
    PluginLoader,
)


# ============================================================================
# Concrete Analyzer for Testing
# ============================================================================

class MockAnalyzer(BaseAnalyzer):
    """Concrete implementation of BaseAnalyzer for testing."""

    def __init__(self):
        super().__init__(name="MockAnalyzer", source=AnalysisSource.CUSTOM)

    def analyze(self, input_data: Any) -> AnalysisResult:
        iocs = [
            IoC(
                ioc_type=IoCType.IP_ADDRESS,
                value="192.168.1.1",
                source=self.source,
            )
        ]
        alerts = [
            Alert(
                alert_id="MOCK-001",
                source=self.source,
                severity=AlertSeverity.MEDIUM,
                message=f"Mock alert for {input_data}",
                timestamp="2025-01-01T00:00:00Z",
                iocs=iocs,
            )
        ]
        result = AnalysisResult(
            analyzer_name=self.name,
            source=self.source,
            success=True,
            alerts=alerts,
            iocs=iocs,
        )
        self._results.append(result)
        return result

    def get_iocs(self) -> List[IoC]:
        all_iocs = []
        for r in self._results:
            all_iocs.extend(r.iocs)
        return all_iocs


# ============================================================================
# IoC Tests
# ============================================================================

class TestIoC:

    def test_create_ioc(self):
        ioc = IoC(
            ioc_type=IoCType.IP_ADDRESS,
            value="10.0.0.1",
            source=AnalysisSource.SNORT,
        )
        assert ioc.ioc_type == IoCType.IP_ADDRESS
        assert ioc.value == "10.0.0.1"
        assert ioc.confidence == 1.0

    def test_ioc_to_dict(self):
        ioc = IoC(
            ioc_type=IoCType.DOMAIN,
            value="evil.com",
            source=AnalysisSource.YARA,
            confidence=0.8,
            context="Found in YARA match",
        )
        d = ioc.to_dict()
        assert d["type"] == "domain"
        assert d["value"] == "evil.com"
        assert d["source"] == "yara"
        assert d["confidence"] == 0.8

    def test_ioc_types(self):
        """Verify all IoC types are defined."""
        expected = [
            "ip_address", "domain", "file_hash_md5",
            "file_hash_sha256", "url", "file_path",
            "registry_key", "mutex",
        ]
        for val in expected:
            assert IoCType(val) is not None


# ============================================================================
# Alert Tests
# ============================================================================

class TestAlert:

    def test_create_alert(self):
        alert = Alert(
            alert_id="TEST-001",
            source=AnalysisSource.SNORT,
            severity=AlertSeverity.HIGH,
            message="Test alert",
            timestamp="2025-01-01T00:00:00Z",
        )
        assert alert.alert_id == "TEST-001"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.iocs == []
        assert alert.details == {}

    def test_alert_to_dict(self):
        alert = Alert(
            alert_id="TEST-002",
            source=AnalysisSource.STATIC,
            severity=AlertSeverity.CRITICAL,
            message="Critical finding",
            timestamp="2025-06-15T10:30:00Z",
            details={"file": "malware.exe"},
        )
        d = alert.to_dict()
        assert d["alert_id"] == "TEST-002"
        assert d["source"] == "static"
        assert d["severity"] == "critical"
        assert d["details"]["file"] == "malware.exe"

    def test_alert_with_iocs(self):
        ioc = IoC(
            ioc_type=IoCType.URL,
            value="http://c2.evil.com",
            source=AnalysisSource.DYNAMIC_CAPE,
        )
        alert = Alert(
            alert_id="TEST-003",
            source=AnalysisSource.DYNAMIC_CAPE,
            severity=AlertSeverity.HIGH,
            message="C2 connection",
            timestamp="2025-01-01T00:00:00Z",
            iocs=[ioc],
        )
        d = alert.to_dict()
        assert len(d["iocs"]) == 1
        assert d["iocs"][0]["value"] == "http://c2.evil.com"


# ============================================================================
# AnalysisResult Tests
# ============================================================================

class TestAnalysisResult:

    def test_create_result(self):
        result = AnalysisResult(
            analyzer_name="TestAnalyzer",
            source=AnalysisSource.YARA,
            success=True,
        )
        assert result.success is True
        assert result.alerts == []
        assert result.iocs == []

    def test_result_to_dict(self):
        result = AnalysisResult(
            analyzer_name="TestAnalyzer",
            source=AnalysisSource.STATIC,
            success=False,
            metadata={"error": "File not found"},
        )
        d = result.to_dict()
        assert d["success"] is False
        assert d["metadata"]["error"] == "File not found"

    def test_result_with_data(self):
        ioc = IoC(IoCType.FILE_HASH_MD5, "abc123", AnalysisSource.STATIC)
        alert = Alert("A-001", AnalysisSource.STATIC, AlertSeverity.LOW,
                       "Test", "2025-01-01T00:00:00Z")
        result = AnalysisResult(
            analyzer_name="Test",
            source=AnalysisSource.STATIC,
            success=True,
            alerts=[alert],
            iocs=[ioc],
        )
        d = result.to_dict()
        assert len(d["alerts"]) == 1
        assert len(d["iocs"]) == 1


# ============================================================================
# BaseAnalyzer Tests
# ============================================================================

class TestBaseAnalyzer:

    def test_mock_analyzer(self):
        analyzer = MockAnalyzer()
        assert analyzer.name == "MockAnalyzer"
        assert analyzer.source == AnalysisSource.CUSTOM

    def test_analyze(self):
        analyzer = MockAnalyzer()
        result = analyzer.analyze("test_file.exe")
        assert result.success is True
        assert len(result.alerts) == 1
        assert len(result.iocs) == 1

    def test_get_iocs(self):
        analyzer = MockAnalyzer()
        analyzer.analyze("file1.exe")
        analyzer.analyze("file2.exe")
        iocs = analyzer.get_iocs()
        assert len(iocs) == 2

    def test_get_results(self):
        analyzer = MockAnalyzer()
        analyzer.analyze("file.exe")
        results = analyzer.get_results()
        assert len(results) == 1

    def test_clear_results(self):
        analyzer = MockAnalyzer()
        analyzer.analyze("file.exe")
        analyzer.clear_results()
        assert len(analyzer.get_results()) == 0

    def test_is_available(self):
        analyzer = MockAnalyzer()
        assert analyzer.is_available() is True

    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            BaseAnalyzer("fail", AnalysisSource.CUSTOM)


# ============================================================================
# PluginLoader Tests
# ============================================================================

class TestPluginLoader:

    def test_register_plugin(self):
        loader = PluginLoader()
        loader.register_plugin("Mock", MockAnalyzer)
        instance = loader.create_instance("Mock")
        assert instance.name == "MockAnalyzer"

    def test_register_non_analyzer_fails(self):
        loader = PluginLoader()
        with pytest.raises(TypeError):
            loader.register_plugin("Bad", dict)

    def test_create_unregistered_fails(self):
        loader = PluginLoader()
        with pytest.raises(KeyError):
            loader.create_instance("NonExistent")

    def test_get_all_instances(self):
        loader = PluginLoader()
        loader.register_plugin("Mock", MockAnalyzer)
        loader.create_instance("Mock")
        instances = loader.get_all_instances()
        assert "Mock" in instances

    def test_discover_empty_dir(self, tmp_path):
        loader = PluginLoader()
        discovered = loader.discover_plugins(tmp_path)
        assert discovered == []

    def test_discover_nonexistent_dir(self, tmp_path):
        loader = PluginLoader()
        discovered = loader.discover_plugins(tmp_path / "nonexistent")
        assert discovered == []

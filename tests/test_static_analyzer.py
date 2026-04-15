"""
Unit tests for the static analyzer module.

Tests file analysis with hashing, entropy, string extraction,
suspicious keyword detection, and PE header analysis.
"""

import struct
from pathlib import Path
from typing import List

import pytest

from src.static_analyzer import StaticAnalyzer
from src.plugin_framework import AnalysisSource, IoCType


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def analyzer():
    return StaticAnalyzer()


@pytest.fixture
def normal_text_file(tmp_path):
    """A normal text file — should produce low entropy, few alerts."""
    p = tmp_path / "readme.txt"
    p.write_text(
        "This is a normal document. No malware here.\n" * 20,
        encoding="utf-8",
    )
    return p


@pytest.fixture
def suspicious_file(tmp_path):
    """A file containing suspicious strings and embedded IoCs."""
    p = tmp_path / "suspicious.bin"
    content = (
        b"MZ"  # PE header magic (just the first two bytes)
        + b"\x00" * 50
        + b"cmd.exe /c net user hacker"
        + b"\x00" * 10
        + b"powershell -enc base64stuff"
        + b"\x00" * 10
        + b"http://malware.evil.com/payload.exe"
        + b"\x00" * 10
        + b"192.168.1.100"
        + b"\x00" * 10
        + b"HKEY_LOCAL_MACHINE\\SOFTWARE\\evil"
        + b"\x00" * 50
    )
    p.write_bytes(content)
    return p


@pytest.fixture
def high_entropy_file(tmp_path):
    """A file with high entropy (pseudo-random bytes)."""
    import os
    p = tmp_path / "packed.bin"
    p.write_bytes(os.urandom(4096))
    return p


# ============================================================================
# Basic Analysis Tests
# ============================================================================

class TestStaticAnalyzerBasic:

    def test_analyzer_name(self, analyzer):
        assert analyzer.name == "StaticAnalyzer"
        assert analyzer.source == AnalysisSource.STATIC

    def test_analyze_normal_file(self, analyzer, normal_text_file):
        result = analyzer.analyze(normal_text_file)
        assert result.success is True
        assert result.metadata["file_name"] == "readme.txt"
        assert result.metadata["hashes"]["md5"] is not None
        assert result.metadata["hashes"]["sha256"] is not None

    def test_analyze_nonexistent_file(self, analyzer, tmp_path):
        result = analyzer.analyze(tmp_path / "nonexistent.exe")
        assert result.success is False
        assert "error" in result.metadata

    def test_hash_iocs_generated(self, analyzer, normal_text_file):
        result = analyzer.analyze(normal_text_file)
        hash_iocs = [
            ioc for ioc in result.iocs
            if ioc.ioc_type in (IoCType.FILE_HASH_MD5, IoCType.FILE_HASH_SHA256)
        ]
        assert len(hash_iocs) == 2  # MD5 + SHA256


# ============================================================================
# Suspicious Content Detection Tests
# ============================================================================

class TestSuspiciousDetection:

    def test_suspicious_strings_detected(self, analyzer, suspicious_file):
        result = analyzer.analyze(suspicious_file)
        assert result.success is True
        # Should detect cmd.exe, powershell, http://
        suspicious_alert = [
            a for a in result.alerts
            if "suspicious strings" in a.message.lower()
        ]
        assert len(suspicious_alert) > 0

    def test_ip_iocs_extracted(self, analyzer, suspicious_file):
        result = analyzer.analyze(suspicious_file)
        ip_iocs = [
            ioc for ioc in result.iocs if ioc.ioc_type == IoCType.IP_ADDRESS
        ]
        ip_values = [ioc.value for ioc in ip_iocs]
        assert "192.168.1.100" in ip_values

    def test_url_iocs_extracted(self, analyzer, suspicious_file):
        result = analyzer.analyze(suspicious_file)
        url_iocs = [
            ioc for ioc in result.iocs if ioc.ioc_type == IoCType.URL
        ]
        url_values = [ioc.value for ioc in url_iocs]
        assert any("malware.evil.com" in u for u in url_values)


# ============================================================================
# Entropy Tests
# ============================================================================

class TestEntropyDetection:

    def test_high_entropy_alert(self, analyzer, high_entropy_file):
        result = analyzer.analyze(high_entropy_file)
        entropy = result.metadata.get("entropy")
        assert entropy is not None
        assert entropy > 7.0
        # Should trigger entropy alert
        entropy_alerts = [
            a for a in result.alerts
            if "entropy" in a.message.lower()
        ]
        assert len(entropy_alerts) > 0

    def test_low_entropy_no_alert(self, analyzer, normal_text_file):
        result = analyzer.analyze(normal_text_file)
        entropy_alerts = [
            a for a in result.alerts
            if "entropy" in a.message.lower()
        ]
        assert len(entropy_alerts) == 0


# ============================================================================
# Accumulation Tests
# ============================================================================

class TestAccumulation:

    def test_get_iocs_accumulates(self, analyzer, normal_text_file, suspicious_file):
        analyzer.analyze(normal_text_file)
        analyzer.analyze(suspicious_file)
        all_iocs = analyzer.get_iocs()
        # Should have IoCs from both analyses
        assert len(all_iocs) > 2

    def test_results_stored(self, analyzer, normal_text_file):
        analyzer.analyze(normal_text_file)
        assert len(analyzer.get_results()) == 1


# ============================================================================
# Byte Frequency Distribution (BFD) Tests
# ============================================================================

class TestByteFrequencyDistribution:
    """Tests for the new byte frequency distribution analysis step."""

    def test_bfd_normal_text_no_alert(self, analyzer, tmp_path):
        """Plain ASCII text should NOT trigger BFD alerts."""
        p = tmp_path / "clean.txt"
        p.write_text("Hello world. This is perfectly normal content.\n" * 50)
        result = analyzer.analyze(p)
        bfd_alerts = [
            a for a in result.alerts
            if "byte frequency" in a.message.lower()
        ]
        assert len(bfd_alerts) == 0

    def test_bfd_packed_binary_triggers_alert(self, analyzer, tmp_path):
        """A file full of null bytes + non-printable content should trigger."""
        p = tmp_path / "packed.bin"
        # Highly non-uniform: 70% null bytes + 30% 0xFF padding
        p.write_bytes(b"\x00" * 3500 + b"\xff" * 1500)
        result = analyzer.analyze(p)
        bfd_alerts = [
            a for a in result.alerts
            if "byte frequency" in a.message.lower()
        ]
        assert len(bfd_alerts) > 0
        # Should mention null bytes or non-printable
        alert_msg = bfd_alerts[0].message.lower()
        assert "null" in alert_msg or "non-printable" in alert_msg

    def test_bfd_profile_in_metadata(self, analyzer, tmp_path):
        """BFD profile should be stored in metadata."""
        p = tmp_path / "sample.bin"
        import os
        p.write_bytes(os.urandom(2048))
        result = analyzer.analyze(p)
        bfd = result.metadata.get("byte_distribution")
        assert bfd is not None
        assert "uniformity" in bfd
        assert "null_ratio" in bfd
        assert "non_printable_ratio" in bfd
        # Histogram should NOT be in metadata (too bulky)
        assert "histogram" not in bfd

    def test_bfd_skips_tiny_file(self, analyzer, tmp_path):
        """Files smaller than BFD_MIN_FILE_SIZE should be skipped."""
        p = tmp_path / "tiny.bin"
        p.write_bytes(b"\x00" * 100)  # 100 bytes < 512 threshold
        result = analyzer.analyze(p)
        assert result.metadata.get("byte_distribution") is None


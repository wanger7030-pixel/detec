"""
Unit tests for the utils module.

Tests hashing, entropy, string extraction, IoC regex patterns,
timestamp handling, and ID generation.
"""

import os
import tempfile
from pathlib import Path

import pytest

from src.utils import (
    calculate_entropy,
    calculate_file_entropy,
    compute_file_hash,
    compute_file_hashes,
    extract_domains,
    extract_ips,
    extract_strings,
    extract_urls,
    format_file_size,
    generate_alert_id,
    get_file_size,
    now_iso,
    parse_timestamp,
    timestamps_within_window,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def tmp_text_file(tmp_path):
    """Create a temporary file with known text content."""
    p = tmp_path / "test.txt"
    p.write_text("Hello, World! This is a test file.", encoding="utf-8")
    return p


@pytest.fixture
def tmp_binary_file(tmp_path):
    """Create a temporary file with known binary content."""
    p = tmp_path / "binary.bin"
    # Some ASCII strings embedded in null bytes
    content = (
        b"\x00" * 10
        + b"cmd.exe /c whoami"
        + b"\x00" * 5
        + b"192.168.1.100"
        + b"\x00" * 5
        + b"http://evil.com/payload"
        + b"\x00" * 10
    )
    p.write_bytes(content)
    return p


@pytest.fixture
def empty_file(tmp_path):
    """Create an empty temporary file."""
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    return p


# ============================================================================
# File Hashing Tests
# ============================================================================

class TestFileHashing:

    def test_compute_sha256(self, tmp_text_file):
        result = compute_file_hash(tmp_text_file, "sha256")
        assert result is not None
        assert len(result) == 64  # SHA-256 hex digest length

    def test_compute_md5(self, tmp_text_file):
        result = compute_file_hash(tmp_text_file, "md5")
        assert result is not None
        assert len(result) == 32  # MD5 hex digest length

    def test_same_content_same_hash(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text("identical content")
        f2.write_text("identical content")
        assert compute_file_hash(f1) == compute_file_hash(f2)

    def test_different_content_different_hash(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text("content A")
        f2.write_text("content B")
        assert compute_file_hash(f1) != compute_file_hash(f2)

    def test_nonexistent_file(self, tmp_path):
        result = compute_file_hash(tmp_path / "nonexistent.txt")
        assert result is None

    def test_compute_file_hashes(self, tmp_text_file):
        result = compute_file_hashes(tmp_text_file)
        assert "md5" in result
        assert "sha256" in result
        assert result["md5"] is not None
        assert result["sha256"] is not None
        assert len(result["md5"]) == 32
        assert len(result["sha256"]) == 64


# ============================================================================
# Entropy Tests
# ============================================================================

class TestEntropy:

    def test_zero_entropy_uniform(self):
        """All identical bytes -> entropy = 0."""
        data = bytes([0x41] * 1000)
        assert calculate_entropy(data) == 0.0

    def test_max_entropy(self):
        """All 256 distinct bytes -> entropy close to 8.0."""
        data = bytes(range(256)) * 100
        entropy = calculate_entropy(data)
        assert 7.9 < entropy <= 8.0

    def test_empty_data(self):
        assert calculate_entropy(b"") == 0.0

    def test_moderate_entropy(self):
        """Normal text should have moderate entropy (3-5)."""
        data = b"The quick brown fox jumps over the lazy dog."
        entropy = calculate_entropy(data)
        assert 3.0 < entropy < 5.0

    def test_file_entropy(self, tmp_text_file):
        result = calculate_file_entropy(tmp_text_file)
        assert result is not None
        assert 0.0 <= result <= 8.0

    def test_empty_file_entropy(self, empty_file):
        result = calculate_file_entropy(empty_file)
        assert result == 0.0


# ============================================================================
# String Extraction Tests
# ============================================================================

class TestStringExtraction:

    def test_extract_ascii_strings(self, tmp_binary_file):
        strings = extract_strings(tmp_binary_file, min_length=4)
        assert any("cmd.exe" in s for s in strings)

    def test_extract_strings_from_text(self, tmp_text_file):
        strings = extract_strings(tmp_text_file, min_length=4)
        assert len(strings) > 0

    def test_empty_file(self, empty_file):
        strings = extract_strings(empty_file)
        assert strings == []

    def test_min_length_filter(self, tmp_path):
        f = tmp_path / "test.bin"
        f.write_bytes(b"AB\x00CDEF\x00GHIJKLMN\x00")
        # With min_length=4, "AB" (len 2) shouldn't appear
        strings = extract_strings(f, min_length=4)
        assert not any(s == "AB" for s in strings)
        assert any("CDEF" in s or "GHIJ" in s for s in strings)


# ============================================================================
# IoC Extraction Tests
# ============================================================================

class TestIoCExtraction:

    def test_extract_ips(self):
        text = "Connection from 192.168.1.100 to 10.0.0.1 detected"
        ips = extract_ips(text)
        assert "192.168.1.100" in ips
        assert "10.0.0.1" in ips

    def test_extract_no_ips(self):
        text = "No IP addresses here"
        assert extract_ips(text) == []

    def test_invalid_ip_rejected(self):
        text = "Not an IP: 999.999.999.999"
        ips = extract_ips(text)
        assert "999.999.999.999" not in ips

    def test_extract_domains(self):
        text = "Visit example.com and malware.evil.org for more"
        domains = extract_domains(text)
        assert "example.com" in domains
        assert "malware.evil.org" in domains

    def test_extract_urls(self):
        text = "Download from http://evil.com/payload.exe and https://safe.org"
        urls = extract_urls(text)
        assert any("http://evil.com/payload.exe" in u for u in urls)
        assert any("https://safe.org" in u for u in urls)

    def test_extract_urls_empty(self):
        assert extract_urls("no urls here") == []


# ============================================================================
# Timestamp Tests
# ============================================================================

class TestTimestamps:

    def test_now_iso_format(self):
        ts = now_iso()
        assert ts.endswith("Z")
        # Should be parseable
        dt = parse_timestamp(ts)
        assert dt is not None

    def test_parse_iso_format(self):
        dt = parse_timestamp("2025-01-15T12:30:45Z")
        assert dt is not None
        assert dt.year == 2025
        assert dt.hour == 12

    def test_parse_snort_format(self):
        dt = parse_timestamp("01/15-12:30:45.123456")
        assert dt is not None

    def test_parse_invalid(self):
        assert parse_timestamp("not a timestamp") is None

    def test_timestamps_within_window(self):
        ts1 = "2025-01-15T12:00:00Z"
        ts2 = "2025-01-15T12:04:00Z"
        # 4 minutes apart, within 5-minute window
        assert timestamps_within_window(ts1, ts2, 300) is True

    def test_timestamps_outside_window(self):
        ts1 = "2025-01-15T12:00:00Z"
        ts2 = "2025-01-15T12:10:00Z"
        # 10 minutes apart, outside 5-minute window
        assert timestamps_within_window(ts1, ts2, 300) is False

    def test_timestamps_invalid(self):
        assert timestamps_within_window("invalid", "also invalid", 300) is False


# ============================================================================
# ID Generation Tests
# ============================================================================

class TestIDGeneration:

    def test_generate_alert_id(self):
        aid = generate_alert_id("TEST")
        assert aid.startswith("TEST-")
        assert len(aid) == 17  # "TEST-" + 12 hex chars

    def test_unique_ids(self):
        ids = {generate_alert_id() for _ in range(100)}
        assert len(ids) == 100  # All unique


# ============================================================================
# File Size Tests
# ============================================================================

class TestFileSize:

    def test_get_file_size(self, tmp_text_file):
        size = get_file_size(tmp_text_file)
        assert size is not None
        assert size > 0

    def test_get_file_size_nonexistent(self, tmp_path):
        assert get_file_size(tmp_path / "nope.txt") is None

    def test_format_bytes(self):
        assert format_file_size(500) == "500.0 B"

    def test_format_kilobytes(self):
        result = format_file_size(2048)
        assert "KB" in result

    def test_format_megabytes(self):
        result = format_file_size(5 * 1024 * 1024)
        assert "MB" in result

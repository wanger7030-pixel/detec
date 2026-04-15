"""
Utility functions shared across the Integrated Detection System.

Provides common helpers for hashing, string extraction, entropy
calculation, timestamp handling, and logging setup.
"""

import hashlib
import logging
import math
import re
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from . import config


# ============================================================================
# Logging Setup
# ============================================================================

def setup_logging(level: Optional[str] = None) -> logging.Logger:
    """
    Configure project-wide logging.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
               Defaults to config.LOG_LEVEL.

    Returns:
        Root logger for the project.
    """
    log_level = getattr(logging, level or config.LOG_LEVEL, logging.INFO)

    config.ensure_directories()

    # Root logger
    root_logger = logging.getLogger("src")
    root_logger.setLevel(log_level)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(
        config.LOG_FORMAT, datefmt=config.LOG_DATE_FORMAT
    )
    console_handler.setFormatter(console_formatter)

    # File handler
    file_handler = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
    file_handler.setLevel(log_level)
    file_handler.setFormatter(console_formatter)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    return root_logger


# ============================================================================
# File Hashing
# ============================================================================

def compute_file_hash(
    file_path: Path, algorithm: str = "sha256"
) -> Optional[str]:
    """
    Compute cryptographic hash of a file.

    Args:
        file_path: Path to the file.
        algorithm: Hash algorithm ('md5', 'sha256', 'sha1').

    Returns:
        Hex digest string, or None if file is unreadable.
    """
    try:
        hasher = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, ValueError) as e:
        logging.getLogger(__name__).error(
            f"Hash computation failed for {file_path}: {e}"
        )
        return None


def compute_file_hashes(file_path: Path) -> dict:
    """
    Compute both MD5 and SHA-256 hashes for a file.

    Returns:
        Dict with 'md5' and 'sha256' keys.
    """
    return {
        "md5": compute_file_hash(file_path, "md5"),
        "sha256": compute_file_hash(file_path, "sha256"),
    }


# ============================================================================
# Entropy Calculation
# ============================================================================

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of byte data.

    High entropy (close to 8.0) suggests encrypted or compressed content.
    Typical executables have entropy around 5.0-6.5.
    Packed/encrypted malware often exceeds 7.0.

    Args:
        data: Raw byte data.

    Returns:
        Entropy value between 0.0 and 8.0.
    """
    if not data:
        return 0.0

    byte_counts = Counter(data)
    total = len(data)
    entropy = 0.0

    for count in byte_counts.values():
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)

    return entropy


def calculate_file_entropy(file_path: Path) -> Optional[float]:
    """
    Calculate Shannon entropy of an entire file.

    Args:
        file_path: Path to the file.

    Returns:
        Entropy value, or None if file is unreadable.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        return calculate_entropy(data)
    except OSError as e:
        logging.getLogger(__name__).error(
            f"Entropy calculation failed for {file_path}: {e}"
        )
        return None


def compute_byte_frequency_profile(
    file_path: Path,
    min_size: int = None,
) -> Optional[dict]:
    """
    Compute byte frequency distribution profile for malware detection.

    Analyses the distribution of all 256 possible byte values in a file.
    Malware often exhibits distinctive byte distributions compared to
    benign executables (e.g. concentrated opcode usage, NOP sleds,
    repetitive padding, or encrypted payloads).

    References:
        - Saxe & Berlin, "Deep Neural Network Based Malware Detection
          Using Two-Dimensional Binary Visualization", 2015
        - Raff et al., "Malware Detection by Eating a Whole EXE", 2017

    Args:
        file_path: Path to the binary file.
        min_size:  Minimum file size in bytes; files below this
                   threshold are skipped.  Defaults to
                   ``config.BFD_MIN_FILE_SIZE``.

    Returns:
        Dict with keys:
            histogram          – 256-length list of relative frequencies
            uniformity         – chi-squared deviation from uniform
                                 distribution, normalised to [0, 1]
                                 (0 = perfectly uniform, 1 = single byte)
            null_ratio         – proportion of 0x00 bytes
            non_printable_ratio – proportion of bytes outside 0x20-0x7E
        Returns None if file cannot be read or is too small.
    """
    if min_size is None:
        min_size = getattr(config, "BFD_MIN_FILE_SIZE", 512)

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except OSError:
        return None

    total = len(data)
    if total < min_size:
        return None

    # --- 256-bin byte histogram ---
    byte_counts = Counter(data)
    histogram = [byte_counts.get(b, 0) / total for b in range(256)]

    # --- Uniformity: chi-squared deviation from uniform ---
    # Expected frequency under uniform distribution
    expected = 1.0 / 256
    chi_sq = sum((freq - expected) ** 2 for freq in histogram)
    # Normalise: maximum possible chi_sq ≈ (1 - 1/256)^2 + 255*(1/256)^2
    max_chi_sq = (1.0 - expected) ** 2 + 255 * expected ** 2
    uniformity = chi_sq / max_chi_sq if max_chi_sq > 0 else 0.0

    # --- Null byte ratio ---
    null_ratio = byte_counts.get(0, 0) / total

    # --- Non-printable ratio (outside 0x20 – 0x7E) ---
    printable_count = sum(
        byte_counts.get(b, 0) for b in range(0x20, 0x7F)
    )
    non_printable_ratio = 1.0 - (printable_count / total)

    return {
        "histogram": histogram,
        "uniformity": round(uniformity, 4),
        "null_ratio": round(null_ratio, 4),
        "non_printable_ratio": round(non_printable_ratio, 4),
    }


# ============================================================================
# String Extraction
# ============================================================================

def extract_strings(
    file_path: Path,
    min_length: int = None,
    encoding: str = "both"
) -> List[str]:
    """
    Extract human-readable strings from a binary file.

    Similar to the Unix 'strings' command. Extracts both ASCII and
    Unicode (UTF-16LE) strings.

    Args:
        file_path: Path to the binary file.
        min_length: Minimum string length to extract.
                    Defaults to config.STRINGS_MIN_LENGTH.
        encoding: 'ascii', 'unicode', or 'both'.

    Returns:
        List of extracted strings.
    """
    if min_length is None:
        min_length = config.STRINGS_MIN_LENGTH

    results = []

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except OSError as e:
        logging.getLogger(__name__).error(
            f"String extraction failed for {file_path}: {e}"
        )
        return results

    # ASCII strings
    if encoding in ("ascii", "both"):
        pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
        ascii_strings = re.findall(pattern, data)
        results.extend(s.decode("ascii") for s in ascii_strings)

    # Unicode (UTF-16LE) strings
    if encoding in ("unicode", "both"):
        pattern = (
            rb"(?:[\x20-\x7E]\x00){"
            + str(min_length).encode()
            + rb",}"
        )
        unicode_strings = re.findall(pattern, data)
        for s in unicode_strings:
            try:
                decoded = s.decode("utf-16-le")
                if decoded not in results:
                    results.append(decoded)
            except UnicodeDecodeError:
                continue

    return results


# ============================================================================
# IP Address & Domain Extraction
# ============================================================================

# Regex patterns for IoC extraction
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,})\b"
)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"'{}|\\^`\[\]]+", re.IGNORECASE
)


def extract_ips(text: str) -> List[str]:
    """Extract unique IPv4 addresses from text."""
    return list(set(IP_PATTERN.findall(text)))


def extract_domains(text: str) -> List[str]:
    """Extract unique domain names from text."""
    return list(set(DOMAIN_PATTERN.findall(text)))


def extract_urls(text: str) -> List[str]:
    """Extract unique URLs from text."""
    return list(set(URL_PATTERN.findall(text)))


# ============================================================================
# Timestamp Helpers
# ============================================================================

def now_iso() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(ts_string: str) -> Optional[datetime]:
    """
    Try to parse a timestamp string in common formats.

    Returns:
        datetime object, or None if parsing fails.
    """
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y-%H:%M:%S.%f",
        "%m/%d-%H:%M:%S.%f",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_string, fmt)
        except ValueError:
            continue
    return None


def timestamps_within_window(
    ts1: str, ts2: str, window_seconds: int = None
) -> bool:
    """
    Check if two timestamps fall within a given time window.

    Args:
        ts1, ts2: Timestamp strings.
        window_seconds: Maximum number of seconds apart.
                        Defaults to config.CORRELATION_TIME_WINDOW.

    Returns:
        True if within the window, False otherwise.
    """
    if window_seconds is None:
        window_seconds = config.CORRELATION_TIME_WINDOW

    dt1 = parse_timestamp(ts1)
    dt2 = parse_timestamp(ts2)

    if dt1 is None or dt2 is None:
        return False

    return abs((dt1 - dt2).total_seconds()) <= window_seconds


# ============================================================================
# Unique ID Generation
# ============================================================================

def generate_alert_id(prefix: str = "ALERT") -> str:
    """Generate a unique alert identifier."""
    return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"


# ============================================================================
# File Size Helpers
# ============================================================================

def get_file_size(file_path: Path) -> Optional[int]:
    """Get file size in bytes, or None if file doesn't exist."""
    try:
        return file_path.stat().st_size
    except OSError:
        return None


def format_file_size(size_bytes: int) -> str:
    """Format byte count to human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"

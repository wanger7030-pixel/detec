"""
Global configuration for the Integrated Detection System.

Centralises all paths, thresholds, and runtime parameters.
Adjust these settings based on your deployment environment.
"""

import os
from pathlib import Path


# ============================================================================
# Project Paths
# ============================================================================

# Root directory of the project
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Data directories (datasets - not committed to git)
DATA_DIR = PROJECT_ROOT / "data"
PCAP_DIR = DATA_DIR / "pcap"
MALWARE_SAMPLES_DIR = DATA_DIR / "malware_samples"

# Rules directories
RULES_DIR = PROJECT_ROOT / "rules"
YARA_RULES_DIR = RULES_DIR / "yara"
SNORT_RULES_DIR = RULES_DIR / "snort"

# Database
DATABASE_PATH = PROJECT_ROOT / "data" / "detection_system.db"

# Logs
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "system.log"


# ============================================================================
# Snort Configuration
# ============================================================================

SNORT_BINARY = os.environ.get("SNORT_BINARY", "/usr/local/bin/snort")
SNORT_CONFIG = os.environ.get(
    "SNORT_CONFIG", "/usr/local/etc/snort/snort.lua"
)
SNORT_COMMUNITY_RULES = SNORT_RULES_DIR / "community.rules"

# Alert output format
SNORT_ALERT_CSV_FIELDS = [
    "timestamp", "sig_generator", "sig_id", "sig_rev",
    "msg", "proto", "src", "srcport", "dst", "dstport",
    "ethsrc", "ethdst", "ethlen", "tcpflags", "tcpseq",
    "tcpack", "tcplen", "tcpwindow", "ttl", "tos", "id",
    "dgmlen", "iplen", "icmptype", "icmpcode", "icmpid", "icmpseq"
]


# ============================================================================
# YARA Configuration
# ============================================================================

# Maximum file size to scan (in bytes) - skip extremely large files
YARA_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

# Scan timeout per file (seconds)
YARA_SCAN_TIMEOUT = 60


# ============================================================================
# CAPEv2 Configuration
# ============================================================================

CAPE_API_URL = os.environ.get("CAPE_API_URL", "http://localhost:8000/apiv2")
CAPE_API_TOKEN = os.environ.get("CAPE_API_TOKEN", "")

# Analysis settings
CAPE_ANALYSIS_TIMEOUT = 120        # seconds per sample
CAPE_MACHINE_NAME = "win10_sandbox"  # Name of the sandbox VM in CAPEv2
CAPE_POLL_INTERVAL = 10            # seconds between status checks


# ============================================================================
# Correlation Engine Configuration
# ============================================================================

# Correlation dimension weights (must sum to 1.0)
# 5D Weighted Matching: IP, Domain, File Hash, Behavior/TTP
CORRELATION_WEIGHTS = {
    "ip_address":  0.35,   # Network-layer indicator — strongest direct evidence
    "domain":      0.20,   # Domain/URL match — reduced weight (DLL name false positives)
    "file_hash":   0.30,   # File-layer indicator — high-confidence matching
    "behavior":    0.15,   # Behavior/TTP similarity (YARA rule names, ATT&CK TTPs)
}

# Time window is now a MULTIPLICATIVE booster, not an additive dimension.
# If two correlated events are within the time window, score *= TIME_BOOST.
# Rationale: temporal proximity alone is not evidence of correlation,
# but it strengthens existing IoC-based matches.
CORRELATION_TIME_BOOST = 1.3

# Minimum score to flag events as correlated (lowered from 0.5 to 0.30
# so that single-dimension matches like a shared IP are actionable)
CORRELATION_THRESHOLD = 0.30

# Time window for temporal correlation (seconds)
CORRELATION_TIME_WINDOW = 300  # 5 minutes


# ============================================================================
# Static Analysis Configuration
# ============================================================================

# Minimum entropy to flag a file as potentially packed/encrypted
ENTROPY_SUSPICIOUS_THRESHOLD = 7.0

# ---------- Byte Frequency Distribution (BFD) thresholds ----------
# Reference: Saxe & Berlin 2015, Raff et al. 2017
# Byte distribution anomalies complement entropy for detecting malware
# that uses repetitive patterns, NOP sleds, or concentrated opcode sets.
BFD_UNIFORMITY_THRESHOLD = 0.45       # chi-squared score > 0.45 → suspicious
BFD_NULL_BYTE_THRESHOLD = 0.30        # 0x00 ratio > 30% → suspicious padding
BFD_NON_PRINTABLE_THRESHOLD = 0.75    # non-printable ratio > 75% → suspicious
BFD_MIN_FILE_SIZE = 512               # skip BFD for files smaller than 512 bytes

# Minimum length of extracted strings
STRINGS_MIN_LENGTH = 4


# ============================================================================
# Dashboard Configuration
# ============================================================================

DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000
DASHBOARD_DEBUG = True


# ============================================================================
# Logging Configuration
# ============================================================================

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s | %(name)-20s | %(levelname)-7s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


# ============================================================================
# Ensure data directories exist (safe - only creates empty folders)
# ============================================================================

def ensure_directories():
    """Create required directories if they don't exist."""
    for directory in [DATA_DIR, PCAP_DIR, MALWARE_SAMPLES_DIR,
                      RULES_DIR, YARA_RULES_DIR, SNORT_RULES_DIR,
                      LOG_DIR]:
        directory.mkdir(parents=True, exist_ok=True)

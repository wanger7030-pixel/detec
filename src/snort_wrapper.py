"""
Snort Network Traffic Analysis Wrapper Module.

Wraps the Snort IDS to analyse PCAP files using rule-based detection.
Parses Snort alert output into structured data for correlation.
Uses community rules for signature-based detection.
"""

import csv
import io
import json
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .plugin_framework import (
    AnalysisResult, AnalysisSource, Alert, AlertSeverity,
    BaseAnalyzer, IoC, IoCType,
)
from . import config
from .utils import generate_alert_id, now_iso


logger = logging.getLogger(__name__)


class SnortAnalyzer(BaseAnalyzer):
    """
    Snort IDS wrapper for network traffic analysis.

    Runs Snort against PCAP files and parses the resulting alerts
    into structured Alert objects with extracted IoCs.
    """

    def __init__(
        self,
        snort_binary: Optional[str] = None,
        snort_config: Optional[str] = None,
    ):
        super().__init__(name="SnortAnalyzer", source=AnalysisSource.SNORT)
        self.snort_binary = snort_binary or config.SNORT_BINARY
        self.snort_config = snort_config or config.SNORT_CONFIG

    def is_available(self) -> bool:
        """Check if Snort is installed and accessible."""
        try:
            result = subprocess.run(
                [self.snort_binary, "-V"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def analyze(self, input_data: Any) -> AnalysisResult:
        """
        Analyse a PCAP file with Snort.

        Args:
            input_data: Path to the PCAP file (str or Path).

        Returns:
            AnalysisResult with network alerts and IoCs.
        """
        pcap_path = Path(input_data)
        self.logger.info(f"Starting Snort analysis: {pcap_path}")

        if not pcap_path.exists():
            return AnalysisResult(
                analyzer_name=self.name,
                source=self.source,
                success=False,
                metadata={"error": f"PCAP file not found: {pcap_path}"},
            )

        # Check availability
        if not self.is_available():
            return AnalysisResult(
                analyzer_name=self.name,
                source=self.source,
                success=False,
                metadata={"error": "Snort binary not found or not working"},
            )

        # Run Snort
        try:
            raw_alerts = self._run_snort(pcap_path)
        except Exception as e:
            self.logger.error(f"Snort execution failed: {e}")
            return AnalysisResult(
                analyzer_name=self.name,
                source=self.source,
                success=False,
                metadata={"error": str(e)},
            )

        # Parse alerts
        alerts, iocs = self._parse_alerts(raw_alerts)

        result = AnalysisResult(
            analyzer_name=self.name,
            source=self.source,
            success=True,
            alerts=alerts,
            iocs=iocs,
            raw_output=raw_alerts,
            metadata={
                "pcap_file": str(pcap_path),
                "total_alerts": len(alerts),
                "total_iocs": len(iocs),
            },
        )
        self._results.append(result)

        self.logger.info(
            f"Snort analysis complete: {len(alerts)} alerts, "
            f"{len(iocs)} IoCs"
        )
        return result

    def get_iocs(self) -> List[IoC]:
        """Return all IoCs from all Snort analyses."""
        all_iocs = []
        for result in self._results:
            all_iocs.extend(result.iocs)
        return all_iocs

    def _run_snort(self, pcap_path: Path) -> str:
        """
        Execute Snort on a PCAP file and capture alert output.

        Uses Snort's alert_fast output for simplicity in parsing.
        Runs in read-only mode (no network modification).

        Returns:
            Raw alert text from Snort.
        """
        # Create a temporary directory for Snort output
        with tempfile.TemporaryDirectory(prefix="snort_") as tmp_dir:
            alert_file = os.path.join(tmp_dir, "alert_fast.txt")

            # Snort 3 command: read pcap, use config, output alerts
            cmd = [
                self.snort_binary,
                "-c", self.snort_config,
                "-r", str(pcap_path),
                "-l", tmp_dir,
                "-A", "alert_fast",
                "--warn-all",
                "-q",  # Quiet mode - only output alerts
            ]

            self.logger.debug(f"Running Snort command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            if result.returncode not in (0, 1):
                # returncode 1 can mean alerts were generated
                self.logger.warning(
                    f"Snort stderr: {result.stderr[:500]}"
                )

            # Read the alert file
            alert_path = Path(alert_file)
            if alert_path.exists():
                return alert_path.read_text(encoding="utf-8", errors="replace")

            # Fallback: check for other alert files in tmp_dir
            for f in Path(tmp_dir).glob("alert*"):
                return f.read_text(encoding="utf-8", errors="replace")

            # No alerts generated
            return ""

    def _parse_alerts(self, raw_output: str) -> tuple:
        """
        Parse Snort alert_fast output into structured Alert objects.

        Snort alert_fast format example:
        01/02-03:04:05.678901 [**] [1:1000001:1] Malicious traffic [**]
        [Classification: ...] [Priority: 1] {TCP} 192.168.1.100:12345 ->
        10.0.0.1:80

        Returns:
            Tuple of (list of Alerts, list of IoCs).
        """
        alerts = []
        iocs = []
        seen_ips = set()

        if not raw_output.strip():
            return alerts, iocs

        # Regex for Snort alert_fast format
        alert_pattern = re.compile(
            r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
            r"\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+"
            r"(.+?)\s+\[\*\*\]"
            r"(?:\s+\[Classification:\s*(.+?)\])?"
            r"(?:\s+\[Priority:\s*(\d+)\])?"
            r"\s+\{(\w+)\}\s+"
            r"([\d.]+):?(\d*)\s*->\s*([\d.]+):?(\d*)"
        )

        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            match = alert_pattern.match(line)
            if not match:
                # Try simpler parsing for non-standard formats
                alert = self._parse_simple_alert(line)
                if alert:
                    alerts.append(alert)
                continue

            (timestamp, sig_id, message, classification,
             priority, protocol, src_ip, src_port,
             dst_ip, dst_port) = match.groups()

            # Determine severity from priority
            severity = self._priority_to_severity(priority)

            # Create alert
            alert = Alert(
                alert_id=generate_alert_id("SNORT"),
                source=self.source,
                severity=severity,
                message=message.strip(),
                timestamp=timestamp,
                details={
                    "signature_id": sig_id,
                    "classification": classification or "Unknown",
                    "priority": int(priority) if priority else 3,
                    "protocol": protocol,
                    "src_ip": src_ip,
                    "src_port": int(src_port) if src_port else None,
                    "dst_ip": dst_ip,
                    "dst_port": int(dst_port) if dst_port else None,
                    "raw_line": line,
                },
            )
            alerts.append(alert)

            # Extract IoCs
            for ip in [src_ip, dst_ip]:
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    ioc = IoC(
                        ioc_type=IoCType.IP_ADDRESS,
                        value=ip,
                        source=self.source,
                        context=(
                            f"Snort alert: {message.strip()} "
                            f"[{sig_id}]"
                        ),
                    )
                    iocs.append(ioc)
                    alert.iocs.append(ioc)

        return alerts, iocs

    def _parse_simple_alert(self, line: str) -> Optional[Alert]:
        """Fallback parser for non-standard Snort alert lines."""
        from .utils import extract_ips

        ips = extract_ips(line)
        if not ips:
            return None

        return Alert(
            alert_id=generate_alert_id("SNORT"),
            source=self.source,
            severity=AlertSeverity.LOW,
            message=line[:200],
            timestamp=now_iso(),
            details={"raw_line": line, "extracted_ips": ips},
            iocs=[
                IoC(
                    ioc_type=IoCType.IP_ADDRESS,
                    value=ip,
                    source=self.source,
                    context="Extracted from Snort alert",
                )
                for ip in ips
            ],
        )

    @staticmethod
    def _priority_to_severity(priority: Optional[str]) -> AlertSeverity:
        """Map Snort priority to AlertSeverity."""
        if priority is None:
            return AlertSeverity.MEDIUM
        p = int(priority)
        if p == 1:
            return AlertSeverity.CRITICAL
        elif p == 2:
            return AlertSeverity.HIGH
        elif p == 3:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW

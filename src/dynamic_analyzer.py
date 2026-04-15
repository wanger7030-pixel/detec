"""
CAPEv2 Dynamic Malware Analysis Wrapper Module.

Interfaces with the CAPEv2 REST API to submit malware samples
for automated sandbox execution and behavioural analysis.
Collects runtime behaviour: file operations, registry changes,
network connections, and API calls.
"""

import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from .plugin_framework import (
    AnalysisResult, AnalysisSource, Alert, AlertSeverity,
    BaseAnalyzer, IoC, IoCType,
)
from . import config
from .utils import compute_file_hashes, generate_alert_id, now_iso


logger = logging.getLogger(__name__)


class CapeAnalyzer(BaseAnalyzer):
    """
    CAPEv2 sandbox wrapper for dynamic malware analysis.

    Submits samples via CAPEv2 REST API, polls for completion,
    then parses the JSON report for behavioural indicators.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_token: Optional[str] = None,
    ):
        super().__init__(
            name="CapeAnalyzer", source=AnalysisSource.DYNAMIC_CAPE
        )
        self.api_url = (api_url or config.CAPE_API_URL).rstrip("/")
        self.api_token = api_token or config.CAPE_API_TOKEN
        self._session = requests.Session()
        if self.api_token:
            self._session.headers["Authorization"] = (
                f"Token {self.api_token}"
            )

    def is_available(self) -> bool:
        """Check if CAPEv2 API is reachable."""
        try:
            resp = self._session.get(
                f"{self.api_url}/cuckoo/status/",
                timeout=10,
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def analyze(self, input_data: Any) -> AnalysisResult:
        """
        Submit a sample to CAPEv2 for dynamic analysis.

        Args:
            input_data: Path to the malware sample (str or Path).

        Returns:
            AnalysisResult with behavioural alerts and IoCs.
        """
        sample_path = Path(input_data)
        self.logger.info(f"Starting CAPEv2 analysis: {sample_path}")

        if not sample_path.exists():
            return AnalysisResult(
                analyzer_name=self.name,
                source=self.source,
                success=False,
                metadata={"error": f"Sample not found: {sample_path}"},
            )

        if not self.is_available():
            return AnalysisResult(
                analyzer_name=self.name,
                source=self.source,
                success=False,
                metadata={
                    "error": "CAPEv2 API not reachable",
                    "api_url": self.api_url,
                },
            )

        # Compute file hashes before submission
        hashes = compute_file_hashes(sample_path)

        # Step 1: Submit sample
        task_id = self._submit_sample(sample_path)
        if task_id is None:
            return AnalysisResult(
                analyzer_name=self.name,
                source=self.source,
                success=False,
                metadata={"error": "Failed to submit sample to CAPEv2"},
            )

        self.logger.info(f"Sample submitted, task ID: {task_id}")

        # Step 2: Wait for analysis to complete
        if not self._wait_for_completion(task_id):
            return AnalysisResult(
                analyzer_name=self.name,
                source=self.source,
                success=False,
                metadata={
                    "error": "Analysis timed out or failed",
                    "task_id": task_id,
                },
            )

        # Step 3: Retrieve and parse the report
        report = self._get_report(task_id)
        if report is None:
            return AnalysisResult(
                analyzer_name=self.name,
                source=self.source,
                success=False,
                metadata={
                    "error": "Failed to retrieve report",
                    "task_id": task_id,
                },
            )

        # Step 4: Parse report into alerts and IoCs
        alerts, iocs = self._parse_report(report, sample_path, hashes)

        # Add file hash IoCs
        if hashes["md5"]:
            iocs.append(IoC(
                ioc_type=IoCType.FILE_HASH_MD5,
                value=hashes["md5"],
                source=self.source,
                context=f"MD5 of dynamically analysed sample",
            ))
        if hashes["sha256"]:
            iocs.append(IoC(
                ioc_type=IoCType.FILE_HASH_SHA256,
                value=hashes["sha256"],
                source=self.source,
                context=f"SHA256 of dynamically analysed sample",
            ))

        result = AnalysisResult(
            analyzer_name=self.name,
            source=self.source,
            success=True,
            alerts=alerts,
            iocs=iocs,
            metadata={
                "task_id": task_id,
                "sample": str(sample_path),
                "file_hashes": hashes,
                "score": report.get("info", {}).get("score", 0),
                "total_alerts": len(alerts),
                "total_iocs": len(iocs),
            },
        )
        self._results.append(result)

        self.logger.info(
            f"CAPEv2 analysis complete: {len(alerts)} alerts, "
            f"{len(iocs)} IoCs"
        )
        return result

    def get_iocs(self) -> List[IoC]:
        """Return all IoCs from all CAPEv2 analyses."""
        all_iocs = []
        for result in self._results:
            all_iocs.extend(result.iocs)
        return all_iocs

    # ========================================================================
    # CAPEv2 API Interaction Methods
    # ========================================================================

    def _submit_sample(self, sample_path: Path) -> Optional[int]:
        """
        Submit a file to CAPEv2 for analysis.

        Returns:
            Task ID if successful, None otherwise.
        """
        try:
            with open(sample_path, "rb") as f:
                resp = self._session.post(
                    f"{self.api_url}/tasks/create/file/",
                    files={"file": (sample_path.name, f)},
                    data={
                        "machine": config.CAPE_MACHINE_NAME,
                        "timeout": config.CAPE_ANALYSIS_TIMEOUT,
                    },
                    timeout=60,
                )

            if resp.status_code == 200:
                data = resp.json()
                return data.get("data", {}).get("task_ids", [None])[0]
            else:
                self.logger.error(
                    f"Submit failed: HTTP {resp.status_code} - "
                    f"{resp.text[:200]}"
                )
                return None

        except requests.RequestException as e:
            self.logger.error(f"Submit request failed: {e}")
            return None

    def _wait_for_completion(
        self, task_id: int, max_wait: int = 600
    ) -> bool:
        """
        Poll CAPEv2 until analysis is complete.

        Args:
            task_id: The CAPEv2 task ID.
            max_wait: Maximum wait time in seconds.

        Returns:
            True if analysis completed, False if timed out or failed.
        """
        elapsed = 0
        while elapsed < max_wait:
            try:
                resp = self._session.get(
                    f"{self.api_url}/tasks/view/{task_id}/",
                    timeout=10,
                )
                if resp.status_code == 200:
                    status = (
                        resp.json()
                        .get("data", {})
                        .get("status", "")
                    )
                    if status == "reported":
                        return True
                    elif status in ("failed_analysis", "failed_processing"):
                        self.logger.error(
                            f"Task {task_id} failed: {status}"
                        )
                        return False
            except requests.RequestException:
                pass

            time.sleep(config.CAPE_POLL_INTERVAL)
            elapsed += config.CAPE_POLL_INTERVAL
            self.logger.debug(
                f"Waiting for task {task_id}... ({elapsed}s elapsed)"
            )

        self.logger.error(f"Task {task_id} timed out after {max_wait}s")
        return False

    def _get_report(self, task_id: int) -> Optional[Dict]:
        """
        Retrieve the JSON report for a completed analysis.

        Returns:
            Report dict if successful, None otherwise.
        """
        try:
            resp = self._session.get(
                f"{self.api_url}/tasks/get/report/{task_id}/",
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.json()
            else:
                self.logger.error(
                    f"Report retrieval failed: HTTP {resp.status_code}"
                )
                return None
        except requests.RequestException as e:
            self.logger.error(f"Report request failed: {e}")
            return None

    # ========================================================================
    # Report Parsing
    # ========================================================================

    def _parse_report(
        self, report: Dict, sample_path: Path, hashes: Dict
    ) -> tuple:
        """
        Parse a CAPEv2 JSON report into alerts and IoCs.

        Extracts:
        - Behavioural signatures and their severity
        - Network IoCs (IPs, domains, URLs)
        - File system activity
        - Registry modifications
        """
        alerts = []
        iocs = []

        # --- Parse signatures ---
        for sig in report.get("signatures", []):
            severity = self._score_to_severity(sig.get("severity", 1))
            alert = Alert(
                alert_id=generate_alert_id("CAPE"),
                source=self.source,
                severity=severity,
                message=sig.get("description", sig.get("name", "Unknown")),
                timestamp=now_iso(),
                details={
                    "signature_name": sig.get("name"),
                    "families": sig.get("families", []),
                    "references": sig.get("references", []),
                    "marks": sig.get("marks", [])[:10],
                    "sample": str(sample_path),
                },
            )
            alerts.append(alert)

        # --- Parse network activity ---
        network = report.get("network", {})

        # DNS requests
        for dns in network.get("dns", []):
            domain = dns.get("request", "")
            if domain:
                iocs.append(IoC(
                    ioc_type=IoCType.DOMAIN,
                    value=domain,
                    source=self.source,
                    context=f"DNS lookup during dynamic analysis",
                ))

        # HTTP/HTTPS requests
        for http in network.get("http", []):
            url = http.get("uri", "")
            host = http.get("host", "")
            if url:
                iocs.append(IoC(
                    ioc_type=IoCType.URL,
                    value=url,
                    source=self.source,
                    context=f"HTTP request during dynamic analysis",
                ))
            if host:
                iocs.append(IoC(
                    ioc_type=IoCType.DOMAIN,
                    value=host,
                    source=self.source,
                    context=f"HTTP host during dynamic analysis",
                ))

        # TCP/UDP connections
        for conn_type in ("tcp", "udp"):
            for conn in network.get(conn_type, []):
                dst_ip = conn.get("dst", "")
                if dst_ip:
                    iocs.append(IoC(
                        ioc_type=IoCType.IP_ADDRESS,
                        value=dst_ip,
                        source=self.source,
                        context=(
                            f"{conn_type.upper()} connection "
                            f"to port {conn.get('dport', '?')}"
                        ),
                    ))

        # --- Parse dropped files ---
        for dropped in report.get("dropped", []):
            filepath = dropped.get("filepath", "")
            if filepath:
                iocs.append(IoC(
                    ioc_type=IoCType.FILE_PATH,
                    value=filepath,
                    source=self.source,
                    context="File dropped during dynamic analysis",
                ))

            md5 = dropped.get("md5", "")
            if md5:
                iocs.append(IoC(
                    ioc_type=IoCType.FILE_HASH_MD5,
                    value=md5,
                    source=self.source,
                    context=(
                        f"Hash of dropped file: "
                        f"{dropped.get('name', 'unknown')}"
                    ),
                ))

        # --- Parse registry activity ---
        behavior = report.get("behavior", {})
        for proc in behavior.get("processes", []):
            for call in proc.get("calls", [])[:100]:
                api_name = call.get("api", "")
                if "RegSetValue" in api_name or "RegCreateKey" in api_name:
                    for arg in call.get("arguments", []):
                        if arg.get("name") == "FullName":
                            iocs.append(IoC(
                                ioc_type=IoCType.REGISTRY_KEY,
                                value=arg.get("value", ""),
                                source=self.source,
                                context="Registry modification during analysis",
                            ))
                            break

        # If high-severity overall, add a summary alert
        score = report.get("info", {}).get("score", 0)
        if score >= 7:
            alerts.append(Alert(
                alert_id=generate_alert_id("CAPE"),
                source=self.source,
                severity=AlertSeverity.CRITICAL,
                message=(
                    f"High-risk sample (score: {score}/10): "
                    f"{sample_path.name}"
                ),
                timestamp=now_iso(),
                details={
                    "score": score,
                    "sample": str(sample_path),
                    "hashes": hashes,
                    "network_iocs": len([
                        i for i in iocs
                        if i.ioc_type in (
                            IoCType.IP_ADDRESS, IoCType.DOMAIN, IoCType.URL
                        )
                    ]),
                },
            ))

        return alerts, iocs

    @staticmethod
    def _score_to_severity(score: int) -> AlertSeverity:
        """Map CAPEv2 signature severity score to AlertSeverity."""
        if score >= 4:
            return AlertSeverity.CRITICAL
        elif score >= 3:
            return AlertSeverity.HIGH
        elif score >= 2:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW

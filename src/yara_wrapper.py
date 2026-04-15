"""
YARA Malware Detection Wrapper Module.

Wraps the YARA engine to scan files against custom detection rules.
Performs pattern matching to identify specific malware families
and suspicious code patterns.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .plugin_framework import (
    AnalysisResult, AnalysisSource, Alert, AlertSeverity,
    BaseAnalyzer, IoC, IoCType,
)
from . import config
from .utils import compute_file_hashes, generate_alert_id, now_iso


logger = logging.getLogger(__name__)


class YaraAnalyzer(BaseAnalyzer):
    """
    YARA rule matching engine for malware detection.

    Loads YARA rules from the rules directory and scans files
    for pattern matches, producing alerts with matched rule
    information and file hashes.
    """

    def __init__(self, rules_dir: Optional[Path] = None):
        super().__init__(name="YaraAnalyzer", source=AnalysisSource.YARA)
        self.rules_dir = rules_dir or config.YARA_RULES_DIR
        self._compiled_rules = None

    def is_available(self) -> bool:
        """Check if yara-python is installed."""
        try:
            import yara
            return True
        except ImportError:
            return False

    def _load_rules(self):
        """
        Compile all YARA rules from the rules directory.

        Loads all .yar and .yara files, compiles them together
        for efficient scanning.
        """
        import yara

        if self._compiled_rules is not None:
            return

        rules_dir = Path(self.rules_dir)
        if not rules_dir.exists():
            self.logger.warning(f"YARA rules directory not found: {rules_dir}")
            self._compiled_rules = None
            return

        # Collect all rule files
        rule_files = {}
        for ext in ("*.yar", "*.yara"):
            for rule_file in rules_dir.glob(ext):
                namespace = rule_file.stem
                rule_files[namespace] = str(rule_file)

        if not rule_files:
            self.logger.warning(
                f"No YARA rules found in {rules_dir}"
            )
            self._compiled_rules = None
            return

        try:
            self._compiled_rules = yara.compile(filepaths=rule_files)
            self.logger.info(
                f"Compiled {len(rule_files)} YARA rule files"
            )
        except yara.SyntaxError as e:
            self.logger.error(f"YARA rule compilation error: {e}")
            self._compiled_rules = None

    def analyze(self, input_data: Any) -> AnalysisResult:
        """
        Scan a file or directory with YARA rules.

        Args:
            input_data: Path to file or directory (str or Path).

        Returns:
            AnalysisResult with matched rules, alerts, and IoCs.
        """
        target_path = Path(input_data)
        self.logger.info(f"Starting YARA scan: {target_path}")

        if not self.is_available():
            return AnalysisResult(
                analyzer_name=self.name,
                source=self.source,
                success=False,
                metadata={"error": "yara-python not installed"},
            )

        self._load_rules()
        if self._compiled_rules is None:
            return AnalysisResult(
                analyzer_name=self.name,
                source=self.source,
                success=False,
                metadata={"error": "No YARA rules loaded"},
            )

        if target_path.is_file():
            return self._scan_file(target_path)
        elif target_path.is_dir():
            return self._scan_directory(target_path)
        else:
            return AnalysisResult(
                analyzer_name=self.name,
                source=self.source,
                success=False,
                metadata={"error": f"Path not found: {target_path}"},
            )

    def _scan_file(self, file_path: Path) -> AnalysisResult:
        """Scan a single file with YARA rules."""
        import yara

        alerts = []
        iocs = []

        # Compute file hashes
        hashes = compute_file_hashes(file_path)

        # Add hash IoCs
        if hashes["md5"]:
            iocs.append(IoC(
                ioc_type=IoCType.FILE_HASH_MD5,
                value=hashes["md5"],
                source=self.source,
                context=f"MD5 of YARA-scanned file {file_path.name}",
            ))
        if hashes["sha256"]:
            iocs.append(IoC(
                ioc_type=IoCType.FILE_HASH_SHA256,
                value=hashes["sha256"],
                source=self.source,
                context=f"SHA256 of YARA-scanned file {file_path.name}",
            ))

        # Run YARA scan
        try:
            matches = self._compiled_rules.match(
                str(file_path),
                timeout=config.YARA_SCAN_TIMEOUT,
            )
        except yara.TimeoutError:
            self.logger.warning(f"YARA scan timeout for {file_path}")
            return AnalysisResult(
                analyzer_name=self.name,
                source=self.source,
                success=False,
                metadata={"error": "Scan timeout", "file": str(file_path)},
            )
        except yara.Error as e:
            self.logger.error(f"YARA scan error for {file_path}: {e}")
            return AnalysisResult(
                analyzer_name=self.name,
                source=self.source,
                success=False,
                metadata={"error": str(e), "file": str(file_path)},
            )

        # Process matches
        for match in matches:
            # Determine severity based on rule tags
            severity = self._tags_to_severity(match.tags)

            # Build match details
            match_strings = []
            for string_match in match.strings:
                for instance in string_match.instances:
                    match_strings.append({
                        "identifier": string_match.identifier,
                        "offset": instance.offset,
                        "matched_data": instance.matched_data.hex()[:100],
                    })

            alert = Alert(
                alert_id=generate_alert_id("YARA"),
                source=self.source,
                severity=severity,
                message=(
                    f"YARA rule matched: {match.rule} "
                    f"(namespace: {match.namespace})"
                ),
                timestamp=now_iso(),
                details={
                    "rule_name": match.rule,
                    "namespace": match.namespace,
                    "tags": match.tags,
                    "meta": match.meta,
                    "strings_matched": match_strings[:20],
                    "file_path": str(file_path),
                    "file_hashes": hashes,
                },
                iocs=iocs.copy(),
            )
            alerts.append(alert)

            self.logger.info(
                f"YARA match: {match.rule} on {file_path.name}"
            )

        result = AnalysisResult(
            analyzer_name=self.name,
            source=self.source,
            success=True,
            alerts=alerts,
            iocs=iocs,
            metadata={
                "file": str(file_path),
                "file_hashes": hashes,
                "rules_matched": len(alerts),
                "total_iocs": len(iocs),
            },
        )
        self._results.append(result)
        return result

    def _scan_directory(self, dir_path: Path) -> AnalysisResult:
        """Scan all files in a directory with YARA rules."""
        all_alerts = []
        all_iocs = []
        files_scanned = 0
        files_matched = 0

        for file_path in dir_path.rglob("*"):
            if not file_path.is_file():
                continue

            # Skip files that are too large
            try:
                if file_path.stat().st_size > config.YARA_MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            file_result = self._scan_file(file_path)
            files_scanned += 1

            if file_result.alerts:
                files_matched += 1
                all_alerts.extend(file_result.alerts)
                all_iocs.extend(file_result.iocs)

        result = AnalysisResult(
            analyzer_name=self.name,
            source=self.source,
            success=True,
            alerts=all_alerts,
            iocs=all_iocs,
            metadata={
                "directory": str(dir_path),
                "files_scanned": files_scanned,
                "files_matched": files_matched,
                "total_alerts": len(all_alerts),
            },
        )
        # Don't append again (individual files already appended)
        return result

    def get_iocs(self) -> List[IoC]:
        """Return all IoCs from all YARA scans."""
        all_iocs = []
        for result in self._results:
            all_iocs.extend(result.iocs)
        return all_iocs

    @staticmethod
    def _tags_to_severity(tags: list) -> AlertSeverity:
        """Map YARA rule tags to alert severity."""
        tag_set = set(t.lower() for t in tags)

        if tag_set & {"critical", "apt", "ransomware", "rootkit"}:
            return AlertSeverity.CRITICAL
        elif tag_set & {"malware", "trojan", "exploit", "backdoor"}:
            return AlertSeverity.HIGH
        elif tag_set & {"suspicious", "packed", "dropper"}:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW

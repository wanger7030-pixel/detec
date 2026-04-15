"""
Main Orchestrator for the Integrated Detection System.

Central controller that schedules analysis modules, collects
results, runs correlation, stores data, and generates unified
threat reports.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

from . import config
from .plugin_framework import AnalysisResult, BaseAnalyzer, PluginLoader
from .static_analyzer import StaticAnalyzer
from .snort_wrapper import SnortAnalyzer
from .yara_wrapper import YaraAnalyzer
from .dynamic_analyzer import CapeAnalyzer
from .correlation_engine import CorrelationEngine
from .database import Database
from .utils import setup_logging, now_iso


logger = logging.getLogger(__name__)


class Orchestrator:
    """
    Main orchestrator that coordinates the entire analysis pipeline.

    Pipeline:
    1. Initialise all analyzers
    2. Run network analysis (Snort) on PCAP files
    3. Run static analysis on malware samples
    4. Run YARA rule scanning on malware samples
    5. Run dynamic analysis (CAPEv2) on malware samples
    6. Correlate all results
    7. Store everything in the database
    8. Generate unified threat report
    """

    def __init__(self, db: Optional[Database] = None):
        config.ensure_directories()
        self.db = db or Database()
        self.analyzers: Dict[str, BaseAnalyzer] = {}
        self.results: List[AnalysisResult] = []
        self.correlation_engine = CorrelationEngine()

        # Register built-in analyzers
        self._register_analyzers()

    def _register_analyzers(self):
        """Register all built-in analysis modules."""
        self.analyzers["static"] = StaticAnalyzer()
        self.analyzers["snort"] = SnortAnalyzer()
        self.analyzers["yara"] = YaraAnalyzer()
        self.analyzers["cape"] = CapeAnalyzer()

        # Log availability
        for name, analyzer in self.analyzers.items():
            available = analyzer.is_available()
            status = "available" if available else "NOT available"
            logger.info(f"Analyzer [{name}]: {status}")

    def run_full_analysis(
        self,
        pcap_files: Optional[List[Path]] = None,
        sample_files: Optional[List[Path]] = None,
        sample_dirs: Optional[List[Path]] = None,
        skip_dynamic: bool = False,
    ) -> Dict:
        """
        Run the complete analysis pipeline.

        Args:
            pcap_files: List of PCAP files for network analysis.
            sample_files: List of individual malware samples.
            sample_dirs: List of directories containing samples.
            skip_dynamic: Skip CAPEv2 dynamic analysis (if unavailable).

        Returns:
            Dict with full analysis and correlation report.
        """
        logger.info("=" * 60)
        logger.info("Starting full analysis pipeline")
        logger.info("=" * 60)

        self.results.clear()
        self.correlation_engine.clear()

        # --- Phase 1: Network Analysis (Snort) ---
        if pcap_files:
            self._run_network_analysis(pcap_files)

        # --- Phase 2: Static Analysis ---
        all_samples = self._collect_samples(sample_files, sample_dirs)
        if all_samples:
            self._run_static_analysis(all_samples)
            self._run_yara_analysis(all_samples)

            # --- Phase 3: Dynamic Analysis (CAPEv2) ---
            if not skip_dynamic:
                self._run_dynamic_analysis(all_samples)

        # --- Phase 4: Correlation ---
        correlation_results = self._run_correlation()

        # --- Phase 5: Store results ---
        self._store_results(correlation_results)

        # --- Phase 6: Generate report ---
        report = self._generate_report(correlation_results)

        logger.info("=" * 60)
        logger.info(
            f"Pipeline complete: {len(self.results)} analysis results, "
            f"{len(correlation_results)} correlations"
        )
        logger.info("=" * 60)

        return report

    # ====================================================================
    # Analysis Phase Methods
    # ====================================================================

    def _run_network_analysis(self, pcap_files: List[Path]):
        """Run Snort on all PCAP files."""
        snort = self.analyzers["snort"]

        if not snort.is_available():
            logger.warning("Snort not available, skipping network analysis")
            return

        for pcap in pcap_files:
            logger.info(f"Analysing PCAP: {pcap}")
            result = snort.analyze(pcap)
            self.results.append(result)
            logger.info(
                f"  → {len(result.alerts)} alerts, "
                f"{len(result.iocs)} IoCs"
            )

    def _run_static_analysis(self, samples: List[Path]):
        """Run static analysis on all sample files."""
        static = self.analyzers["static"]

        for sample in samples:
            logger.info(f"Static analysis: {sample.name}")
            result = static.analyze(sample)
            self.results.append(result)

    def _run_yara_analysis(self, samples: List[Path]):
        """Run YARA rules on all sample files."""
        yara = self.analyzers["yara"]

        if not yara.is_available():
            logger.warning("YARA not available, skipping rule scanning")
            return

        for sample in samples:
            logger.info(f"YARA scan: {sample.name}")
            result = yara.analyze(sample)
            self.results.append(result)

    def _run_dynamic_analysis(self, samples: List[Path]):
        """Run CAPEv2 dynamic analysis on sample files."""
        cape = self.analyzers["cape"]

        if not cape.is_available():
            logger.warning("CAPEv2 not available, skipping dynamic analysis")
            return

        for sample in samples:
            logger.info(f"Dynamic analysis (CAPEv2): {sample.name}")
            result = cape.analyze(sample)
            self.results.append(result)

    def _run_correlation(self) -> list:
        """Run the correlation engine on all collected alerts."""
        logger.info("Running correlation engine...")
        self.correlation_engine.add_analysis_results(self.results)
        return self.correlation_engine.correlate()

    # ====================================================================
    # Storage
    # ====================================================================

    def _store_results(self, correlation_results):
        """Persist all results to the database."""
        logger.info("Storing results in database...")

        # Store analysis results (alerts + IoCs)
        for result in self.results:
            self.db.store_analysis_result(result)

        # Store correlations
        for corr in correlation_results:
            for match in corr.matches:
                self.db.insert_correlation({
                    "alert_id_1": match.alert_id_1,
                    "alert_id_2": match.alert_id_2,
                    "correlation_type": match.correlation_type,
                    "score": corr.total_score,
                    "matched_ioc": match.matched_value,
                    "details": match.details,
                })

        logger.info("All results stored successfully")

    # ====================================================================
    # Report Generation
    # ====================================================================

    def _generate_report(self, correlation_results) -> Dict:
        """Generate a unified threat analysis report."""
        stats = self.db.get_stats()

        report = {
            "report_timestamp": now_iso(),
            "summary": {
                "total_analyses": len(self.results),
                "successful_analyses": sum(
                    1 for r in self.results if r.success
                ),
                "total_alerts": stats["total_alerts"],
                "total_iocs": stats["total_iocs"],
                "total_correlations": stats["total_correlations"],
                "alerts_by_source": stats["alerts_by_source"],
                "alerts_by_severity": stats["alerts_by_severity"],
            },
            "correlations": [c.to_dict() for c in correlation_results],
            "analysis_results": [r.to_dict() for r in self.results],
        }

        return report

    # ====================================================================
    # Helpers
    # ====================================================================

    @staticmethod
    def _collect_samples(
        sample_files: Optional[List[Path]],
        sample_dirs: Optional[List[Path]],
    ) -> List[Path]:
        """Collect all sample file paths from files and directories."""
        samples = []

        if sample_files:
            for f in sample_files:
                if Path(f).exists():
                    samples.append(Path(f))

        if sample_dirs:
            for d in sample_dirs:
                dir_path = Path(d)
                if dir_path.is_dir():
                    for f in dir_path.rglob("*"):
                        if f.is_file():
                            samples.append(f)

        return samples


# ============================================================================
# CLI Entry Point
# ============================================================================

def main():
    """Command-line interface for the orchestrator."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Integrated Malware & Network Intrusion Detection System"
    )
    parser.add_argument(
        "--pcap", nargs="*", type=Path,
        help="PCAP files for network analysis"
    )
    parser.add_argument(
        "--samples", nargs="*", type=Path,
        help="Malware sample files"
    )
    parser.add_argument(
        "--sample-dir", nargs="*", type=Path,
        help="Directories containing malware samples"
    )
    parser.add_argument(
        "--skip-dynamic", action="store_true",
        help="Skip CAPEv2 dynamic analysis"
    )
    parser.add_argument(
        "--output", type=Path, default=None,
        help="Output report JSON file"
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level"
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level)

    # Run analysis
    orchestrator = Orchestrator()
    report = orchestrator.run_full_analysis(
        pcap_files=args.pcap,
        sample_files=args.samples,
        sample_dirs=args.sample_dir,
        skip_dynamic=args.skip_dynamic,
    )

    # Output report
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logger.info(f"Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

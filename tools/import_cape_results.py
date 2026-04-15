"""
Import CAPEv2 Dynamic Analysis Results into the Detection System.

Downloads JSON reports and PCAP files from the CAPEv2 VM,
parses them using the existing CapeAnalyzer._parse_report(),
stores alerts and IoCs in the local SQLite database,
then runs the correlation engine.
"""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src import config
from src.database import Database
from src.dynamic_analyzer import CapeAnalyzer
from src.snort_wrapper import SnortAnalyzer
from src.correlation_engine import CorrelationEngine
from src.plugin_framework import AnalysisResult, AnalysisSource, Alert, AlertSeverity, IoC, IoCType
from src.utils import compute_file_hashes, generate_alert_id, now_iso, setup_logging

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CAPE_HOST = os.environ.get("CAPE_SSH_HOST", "cape@localhost")
CAPE_API_URL = os.environ.get("CAPE_API_URL", "http://localhost:8000/apiv2")

REPORTS_DIR = PROJECT_ROOT / "data" / "cape_reports"
PCAPS_DIR = PROJECT_ROOT / "data" / "pcap"
SAMPLES_DIR = Path(os.environ.get("CAPE_SAMPLES_DIR", str(PROJECT_ROOT / "data" / "malware_samples_bazaar")))

TASK_ID_START = 882
TASK_ID_END = 981

setup_logging()
logger = logging.getLogger("import_cape")


# ---------------------------------------------------------------------------
# Step 1: Download reports from CAPEv2 API
# ---------------------------------------------------------------------------
def download_reports():
    """Download JSON reports for all reported tasks via CAPEv2 REST API."""
    import requests

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    downloaded = 0
    skipped = 0
    failed = 0

    logger.info("=== Step 1: Downloading CAPEv2 reports ===")

    for task_id in range(TASK_ID_START, TASK_ID_END + 1):
        report_file = REPORTS_DIR / f"report_{task_id}.json"

        # Skip if already downloaded
        if report_file.exists() and report_file.stat().st_size > 100:
            skipped += 1
            continue

        try:
            resp = requests.get(
                f"{CAPE_API_URL}/tasks/get/report/{task_id}/",
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                with open(report_file, "w", encoding="utf-8") as f:
                    json.dump(data, f)
                downloaded += 1
                if downloaded <= 3 or downloaded % 10 == 0:
                    score = data.get("info", {}).get("score", "?")
                    sigs = len(data.get("signatures", []))
                    logger.info(f"  Task {task_id}: score={score}, sigs={sigs}")
            else:
                failed += 1
                if failed <= 5:
                    logger.warning(f"  Task {task_id}: HTTP {resp.status_code}")
        except Exception as e:
            failed += 1
            if failed <= 5:
                logger.error(f"  Task {task_id}: {e}")

    logger.info(
        f"  Reports: {downloaded} downloaded, {skipped} cached, {failed} failed"
    )
    return downloaded + skipped


# ---------------------------------------------------------------------------
# Step 2: Download PCAPs via SCP
# ---------------------------------------------------------------------------
def download_pcaps():
    """Download PCAP files from CAPEv2 storage via SCP."""
    PCAPS_DIR.mkdir(parents=True, exist_ok=True)
    downloaded = 0
    skipped = 0

    logger.info("=== Step 2: Downloading PCAP files ===")

    for task_id in range(TASK_ID_START, TASK_ID_END + 1):
        pcap_file = PCAPS_DIR / f"task_{task_id}.pcap"

        if pcap_file.exists() and pcap_file.stat().st_size > 0:
            skipped += 1
            continue

        remote_path = f"/opt/CAPEv2/storage/analyses/{task_id}/dump.pcap"
        try:
            result = subprocess.run(
                ["scp", "-q", f"{CAPE_HOST}:{remote_path}", str(pcap_file)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and pcap_file.exists():
                downloaded += 1
            else:
                # Remove empty/invalid file
                if pcap_file.exists():
                    pcap_file.unlink()
        except Exception:
            if pcap_file.exists():
                pcap_file.unlink()

    logger.info(f"  PCAPs: {downloaded} downloaded, {skipped} cached")
    return downloaded + skipped


# ---------------------------------------------------------------------------
# Step 3: Parse reports and import into database
# ---------------------------------------------------------------------------
def import_dynamic_results(db: Database):
    """Parse all CAPEv2 JSON reports and store alerts/IoCs in the database."""
    logger.info("=== Step 3: Importing dynamic analysis results ===")

    analyzer = CapeAnalyzer(api_url=CAPE_API_URL)
    total_alerts = 0
    total_iocs = 0
    processed = 0

    report_files = sorted(REPORTS_DIR.glob("report_*.json"))
    logger.info(f"  Found {len(report_files)} report files")

    for report_file in report_files:
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                report = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"  Skipping {report_file.name}: {e}")
            continue

        # Extract task_id from filename
        task_id = int(report_file.stem.split("_")[1])

        # Find the matching sample file
        target_name = report.get("target", {}).get("file", {}).get("name", "")
        sample_path = None
        if target_name:
            candidate = SAMPLES_DIR / target_name
            if candidate.exists():
                sample_path = candidate

        # Fallback: use any sample name from the report
        if sample_path is None:
            sample_path = SAMPLES_DIR / f"task_{task_id}.exe"

        # Compute hashes if sample exists
        if sample_path.exists():
            hashes = compute_file_hashes(sample_path)
        else:
            # Use hashes from the report itself
            target_file = report.get("target", {}).get("file", {})
            hashes = {
                "md5": target_file.get("md5", ""),
                "sha1": target_file.get("sha1", ""),
                "sha256": target_file.get("sha256", ""),
            }

        # Parse the report using CapeAnalyzer's existing method
        alerts, iocs = analyzer._parse_report(report, sample_path, hashes)

        # Add file hash IoCs
        if hashes.get("md5"):
            iocs.append(IoC(
                ioc_type=IoCType.FILE_HASH_MD5,
                value=hashes["md5"],
                source=AnalysisSource.DYNAMIC_CAPE,
                context="MD5 of dynamically analysed sample",
            ))
        if hashes.get("sha256"):
            iocs.append(IoC(
                ioc_type=IoCType.FILE_HASH_SHA256,
                value=hashes["sha256"],
                source=AnalysisSource.DYNAMIC_CAPE,
                context="SHA256 of dynamically analysed sample",
            ))

        # Create AnalysisResult and store it
        result = AnalysisResult(
            analyzer_name="CAPEv2",
            source=AnalysisSource.DYNAMIC_CAPE,
            success=True,
            alerts=alerts,
            iocs=iocs,
            metadata={
                "task_id": task_id,
                "sample": str(sample_path),
                "file_hashes": hashes,
                "score": report.get("info", {}).get("score", 0),
            },
        )
        db.store_analysis_result(result)

        total_alerts += len(alerts)
        total_iocs += len(iocs)
        processed += 1

    logger.info(
        f"  Imported: {processed} reports, "
        f"{total_alerts} alerts, {total_iocs} IoCs"
    )
    return processed, total_alerts, total_iocs


# ---------------------------------------------------------------------------
# Step 4: Run Snort on PCAP files (if available)
# ---------------------------------------------------------------------------
def run_snort_analysis(db: Database):
    """Run Snort on downloaded PCAP files."""
    logger.info("=== Step 4: Running Snort on PCAP files ===")

    snort = SnortAnalyzer()
    if not snort.is_available():
        logger.warning("  Snort is not available, skipping network analysis")
        return 0, 0

    pcap_files = sorted(PCAPS_DIR.glob("task_*.pcap"))
    # Filter out empty PCAPs
    pcap_files = [p for p in pcap_files if p.stat().st_size > 100]
    logger.info(f"  Found {len(pcap_files)} PCAP files")

    total_alerts = 0
    total_iocs = 0

    for pcap_file in pcap_files:
        try:
            result = snort.analyze(pcap_file)
            if result.success:
                db.store_analysis_result(result)
                total_alerts += len(result.alerts)
                total_iocs += len(result.iocs)
        except Exception as e:
            logger.warning(f"  Snort failed on {pcap_file.name}: {e}")

    logger.info(f"  Snort: {total_alerts} alerts, {total_iocs} IoCs")
    return total_alerts, total_iocs


# ---------------------------------------------------------------------------
# Step 5: Run correlation engine
# ---------------------------------------------------------------------------
def run_correlation(db: Database):
    """Run the correlation engine across all data sources."""
    logger.info("=== Step 5: Running correlation engine ===")

    engine = CorrelationEngine()

    # Load all alerts from the database
    all_alerts_data = db.get_alerts(limit=10000)
    logger.info(f"  Loaded {len(all_alerts_data)} alerts from database")

    # Convert DB rows back to Alert objects
    alerts = []
    for row in all_alerts_data:
        try:
            details = row.get("details", "{}")
            if isinstance(details, str):
                details = json.loads(details) if details else {}

            iocs_data = details.get("iocs", [])
            alert_iocs = []
            for ioc_data in iocs_data:
                if isinstance(ioc_data, dict):
                    alert_iocs.append(IoC(
                        ioc_type=IoCType(ioc_data.get("type", "other")),
                        value=ioc_data.get("value", ""),
                        source=ioc_data.get("source", "unknown"),
                    ))

            # Convert source string to AnalysisSource enum
            source_str = row.get("source", "custom")
            try:
                source_enum = AnalysisSource(source_str)
            except ValueError:
                source_enum = AnalysisSource.CUSTOM

            alert = Alert(
                alert_id=row.get("alert_id", ""),
                source=source_enum,
                severity=AlertSeverity(row.get("severity", "medium")),
                message=row.get("message", ""),
                timestamp=row.get("timestamp", ""),
                details=details,
                iocs=alert_iocs,
            )
            alerts.append(alert)
        except Exception as e:
            logger.debug(f"  Skipping alert: {e}")
            continue

    engine.add_alerts(alerts)
    correlations = engine.correlate()

    # Store correlation results
    stored = 0
    for corr in correlations:
        try:
            db.insert_correlation(corr.to_dict())
            stored += 1
        except Exception as e:
            logger.debug(f"  Correlation store failed: {e}")

    logger.info(
        f"  Correlations: {len(correlations)} found, {stored} stored"
    )
    return len(correlations)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    logger.info("=" * 60)
    logger.info("CAPEv2 Results Import Pipeline")
    logger.info("=" * 60)

    # Step 1: Download reports
    num_reports = download_reports()

    # Step 2: Download PCAPs
    num_pcaps = download_pcaps()

    # Step 3: Import dynamic results
    db = Database()
    processed, dyn_alerts, dyn_iocs = import_dynamic_results(db)

    # Step 4: Run Snort
    snort_alerts, snort_iocs = run_snort_analysis(db)

    # Step 5: Run correlation
    num_corr = run_correlation(db)

    # Summary
    stats = db.get_stats()
    logger.info("=" * 60)
    logger.info("=== Import Summary ===")
    logger.info(f"  Reports downloaded:  {num_reports}")
    logger.info(f"  PCAPs downloaded:    {num_pcaps}")
    logger.info(f"  Dynamic alerts:      {dyn_alerts}")
    logger.info(f"  Dynamic IoCs:        {dyn_iocs}")
    logger.info(f"  Snort alerts:        {snort_alerts}")
    logger.info(f"  Snort IoCs:          {snort_iocs}")
    logger.info(f"  Correlations:        {num_corr}")
    logger.info(f"  DB total alerts:     {stats.get('total_alerts', '?')}")
    logger.info(f"  DB total IoCs:       {stats.get('total_iocs', '?')}")
    logger.info(f"  DB total samples:    {stats.get('total_samples', '?')}")
    logger.info("=" * 60)

    db.close()


if __name__ == "__main__":
    main()

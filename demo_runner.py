"""
End-to-End Integration Demo Runner.

Executes the complete detection pipeline safely on the local machine:
  1. Generate synthetic test data (benign files mimicking malware traits)
  2. Run Static Analysis + YARA Scanning (SAFE - read-only)
  3. Inject simulated Snort + CAPEv2 alerts (no real tools needed)
  4. Run the Correlation Engine
  5. Store everything in SQLite
  6. Launch the Dashboard

Usage:
    python demo_runner.py              # Full demo
    python demo_runner.py --no-dash    # Skip dashboard launch
    python demo_runner.py --reset      # Clear DB before running
"""

import json
import re
import sys
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src import config
from src.database import Database
from src.plugin_framework import (
    Alert, AlertSeverity, AnalysisResult, AnalysisSource,
    IoC, IoCType,
)
from src.utils import (
    compute_file_hashes, calculate_file_entropy,
    generate_alert_id, now_iso,
)
from src.static_analyzer import StaticAnalyzer
from src.correlation_engine import CorrelationEngine


# ============================================================================
# Helper: Try importing optional modules
# ============================================================================

_yara_available = False
try:
    from src.yara_wrapper import YaraAnalyzer
    _yara_available = True
except ImportError:
    print("[WARN] yara-python not available, skipping YARA scan")


# ============================================================================
# Phase 1: Generate Test Data
# ============================================================================

def phase1_generate_data():
    """Generate synthetic test data if not already present."""
    from tools.generate_test_data import (
        create_all_samples, generate_snort_alerts,
        generate_all_cape_reports, SAMPLES_DIR,
    )

    # Check if data already exists
    if SAMPLES_DIR.exists() and any(SAMPLES_DIR.rglob("*.exe")):
        samples = list(SAMPLES_DIR.rglob("*.exe"))
        print(f"  [~] Using existing {len(samples)} samples")
    else:
        samples = create_all_samples(samples_per_family=3)

    # Always regenerate simulated alerts with fresh timestamps
    snort_file = generate_snort_alerts(count=25)
    cape_file = generate_all_cape_reports(samples)

    return samples, snort_file, cape_file


# ============================================================================
# Phase 2: Static Analysis (SAFE - read-only)
# ============================================================================

def phase2_static_analysis(samples, db):
    """Run static analysis on all sample files."""
    print(f"\n  Running static analysis on {len(samples)} files...")

    analyzer = StaticAnalyzer()
    results = []

    for sample in samples:
        result = analyzer.analyze(sample)
        results.append(result)

        # Store sample info in DB
        hashes = compute_file_hashes(sample)
        entropy = calculate_file_entropy(sample)
        db.insert_sample({
            "file_name": sample.name,
            "file_path": str(sample),
            "md5": hashes.get("md5", ""),
            "sha256": hashes.get("sha256", ""),
            "file_size": sample.stat().st_size,
            "entropy": entropy or 0.0,
            "analysis_source": "static",
        })

        # Store analysis result
        db.store_analysis_result(result)

        status = "OK" if result.success else "FAIL"
        alert_count = len(result.alerts)
        ioc_count = len(result.iocs)
        print(f"    {status} {sample.name}: "
              f"{alert_count} alerts, {ioc_count} IoCs")

    return results


# ============================================================================
# Phase 3: YARA Scanning (SAFE - pattern matching only)
# ============================================================================

def phase3_yara_scan(samples, db):
    """Run YARA rules against all sample files."""
    if not _yara_available:
        print("  [SKIP] yara-python not installed")
        return []

    rules_dir = config.YARA_RULES_DIR
    if not rules_dir.exists() or not list(rules_dir.glob("*.yar")):
        print("  [SKIP] No YARA rules found")
        return []

    print(f"  Scanning {len(samples)} files with YARA rules...")

    analyzer = YaraAnalyzer()
    results = []

    for sample in samples:
        result = analyzer.analyze(sample)
        results.append(result)
        db.store_analysis_result(result)

        matched = len(result.alerts)
        if matched > 0:
            print(f"    [!] {sample.name}: {matched} rule matches")

    unmatched = sum(1 for r in results if len(r.alerts) == 0)
    matched = len(results) - unmatched
    print(f"  YARA complete: {matched} files matched, "
          f"{unmatched} clean")

    return results


# ============================================================================
# Phase 4: Inject Simulated Snort Alerts
# ============================================================================

SNORT_PRIORITY_MAP = {
    "1": AlertSeverity.CRITICAL,
    "2": AlertSeverity.HIGH,
    "3": AlertSeverity.MEDIUM,
}

ALERT_FAST_PATTERN = re.compile(
    r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+"
    r"(.+?)\s+\[\*\*\]\s+"
    r"\[Priority:\s*(\d+)\]\s+"
    r"\{(\w+)\}\s+"
    r"([\d.]+):(\d+)\s+->\s+([\d.]+):(\d+)"
)


def phase4_inject_snort_alerts(snort_file, db):
    """Parse simulated Snort alerts and inject into DB."""
    if not snort_file.exists():
        print("  [SKIP] No Snort alert file found")
        return []

    print(f"  Parsing simulated Snort alerts...")

    alerts = []
    text = snort_file.read_text(encoding="utf-8")

    for match in ALERT_FAST_PATTERN.finditer(text):
        ts_raw, sig, msg, priority, proto, src_ip, src_port, dst_ip, dst_port = match.groups()

        # Build timestamp with year
        ts_str = f"2025/{ts_raw}"
        try:
            dt = datetime.strptime(ts_str, "%Y/%m/%d-%H:%M:%S.%f")
            timestamp = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            timestamp = now_iso()

        severity = SNORT_PRIORITY_MAP.get(priority, AlertSeverity.MEDIUM)

        iocs = [
            IoC(IoCType.IP_ADDRESS, src_ip, AnalysisSource.SNORT,
                context=f"Source IP, port {src_port}"),
            IoC(IoCType.IP_ADDRESS, dst_ip, AnalysisSource.SNORT,
                context=f"Destination IP, port {dst_port}"),
        ]

        alert = Alert(
            alert_id=generate_alert_id("SNORT"),
            source=AnalysisSource.SNORT,
            severity=severity,
            message=msg.strip(),
            timestamp=timestamp,
            details={
                "src_ip": src_ip,
                "src_port": int(src_port),
                "dst_ip": dst_ip,
                "dst_port": int(dst_port),
                "protocol": proto,
                "signature": sig,
            },
            iocs=iocs,
        )
        alerts.append(alert)
        db.insert_alert(alert)

    print(f"  Injected {len(alerts)} Snort alerts")
    return alerts


# ============================================================================
# Phase 5: Inject Simulated CAPEv2 Results
# ============================================================================

def phase5_inject_cape_results(cape_file, db):
    """Parse simulated CAPEv2 reports and inject into DB."""
    if not cape_file.exists():
        print("  [SKIP] No CAPEv2 report file found")
        return []

    print(f"  Processing simulated CAPEv2 reports...")

    raw = json.loads(cape_file.read_text(encoding="utf-8"))
    alerts = []

    for filename, report in raw.items():
        sigs = report.get("signatures", [])
        network = report.get("network", {})
        info = report.get("info", {})
        behavior = report.get("behavior", {}).get("summary", {})

        # Create IoCs from network indicators
        iocs = []
        for host in network.get("hosts", []):
            iocs.append(IoC(
                IoCType.IP_ADDRESS, host["ip"],
                AnalysisSource.DYNAMIC_CAPE,
                context="CAPEv2 network connection",
            ))
        for dns in network.get("dns", []):
            iocs.append(IoC(
                IoCType.DOMAIN, dns["request"],
                AnalysisSource.DYNAMIC_CAPE,
                context="CAPEv2 DNS query",
            ))
        for http in network.get("http", []):
            iocs.append(IoC(
                IoCType.URL, http["uri"],
                AnalysisSource.DYNAMIC_CAPE,
                context="CAPEv2 HTTP request",
            ))

        # File hashes as IoCs
        target = report.get("target", {}).get("file", {})
        if target.get("sha256"):
            iocs.append(IoC(
                IoCType.FILE_HASH_SHA256, target["sha256"],
                AnalysisSource.DYNAMIC_CAPE,
                context=f"Sample: {filename}",
            ))

        # Registry IoCs
        for reg in behavior.get("registry_keys_modified", []):
            iocs.append(IoC(
                IoCType.REGISTRY_KEY, reg,
                AnalysisSource.DYNAMIC_CAPE,
                context="CAPEv2 registry modification",
            ))

        # Create alert for each signature
        for sig in sigs:
            severity = {
                4: AlertSeverity.CRITICAL,
                3: AlertSeverity.HIGH,
                2: AlertSeverity.MEDIUM,
            }.get(sig.get("severity", 2), AlertSeverity.MEDIUM)

            alert = Alert(
                alert_id=generate_alert_id("CAPE"),
                source=AnalysisSource.DYNAMIC_CAPE,
                severity=severity,
                message=f"[CAPEv2] {sig['name']}: {sig['description']}",
                timestamp=now_iso(),
                details={
                    "sample": filename,
                    "score": info.get("score", 0),
                    "signature": sig["name"],
                    "files_created": behavior.get("files_created", []),
                },
                iocs=iocs,
            )
            alerts.append(alert)
            db.insert_alert(alert)

    print(f"  Injected {len(alerts)} CAPEv2 alerts "
          f"from {len(raw)} reports")
    return alerts


# ============================================================================
# Phase 6: Correlation
# ============================================================================

def phase6_correlate(db, all_alerts):
    """Run the correlation engine on all collected alerts."""
    print(f"  Correlating {len(all_alerts)} alerts across sources...")

    engine = CorrelationEngine(threshold=0.3)
    engine.add_alerts(all_alerts)
    results = engine.correlate()

    # Store correlations in DB
    for report in results:
        for match in report.matches:
            db.insert_correlation({
                "alert_id_1": report.alert_id_1,
                "alert_id_2": report.alert_id_2,
                "correlation_type": match.correlation_type,
                "score": report.total_score,
                "matched_ioc": match.matched_value,
                "details": json.dumps(match.details),
            })

    correlated = sum(1 for r in results if r.is_correlated)
    print(f"  Found {correlated} correlated event pairs "
          f"(threshold: {engine.threshold})")

    return results


# ============================================================================
# Phase 7: Dashboard Launch
# ============================================================================

def phase7_launch_dashboard(db):
    """Launch the Flask dashboard."""
    # Patch the dashboard app to use our DB
    sys.path.insert(0, str(PROJECT_ROOT / "dashboard"))

    from dashboard.app import app

    # Override DB path in the app
    app.config["DB_PATH"] = str(db.db_path)

    print(f"\n  Dashboard: http://localhost:{config.DASHBOARD_PORT}")
    print(f"  Press Ctrl+C to stop\n")

    try:
        webbrowser.open(f"http://localhost:{config.DASHBOARD_PORT}")
    except Exception:
        pass

    app.run(
        host="127.0.0.1",
        port=config.DASHBOARD_PORT,
        debug=False,
    )


# ============================================================================
# Main
# ============================================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Integrated Detection System - Demo Runner"
    )
    parser.add_argument("--no-dash", action="store_true",
                        help="Skip dashboard launch")
    parser.add_argument("--reset", action="store_true",
                        help="Clear database before running")
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  Integrated Detection System - Full Demo")
    print("=" * 60)

    # Ensure directories
    config.ensure_directories()

    # Database
    db_path = config.DATABASE_PATH
    if args.reset and db_path.exists():
        db_path.unlink()
        print(f"  [!] Database reset: {db_path}")

    db = Database(db_path=db_path)

    # Phase 1: Data Generation
    print("\n[Phase 1/7] Generating test data...")
    samples, snort_file, cape_file = phase1_generate_data()

    # Phase 2: Static Analysis
    print("\n[Phase 2/7] Running static analysis...")
    static_results = phase2_static_analysis(samples, db)

    # Phase 3: YARA Scan
    print("\n[Phase 3/7] Running YARA scan...")
    yara_results = phase3_yara_scan(samples, db)

    # Phase 4: Simulated Snort Alerts
    print("\n[Phase 4/7] Processing network alerts (Snort)...")
    snort_alerts = phase4_inject_snort_alerts(snort_file, db)

    # Phase 5: Simulated CAPEv2 Results
    print("\n[Phase 5/7] Processing dynamic analysis (CAPEv2)...")
    cape_alerts = phase5_inject_cape_results(cape_file, db)

    # Collect all alerts for correlation
    all_alerts = snort_alerts + cape_alerts
    for result in static_results + yara_results:
        all_alerts.extend(result.alerts)

    # Phase 6: Correlation
    print("\n[Phase 6/7] Running correlation engine...")
    correlation_results = phase6_correlate(db, all_alerts)

    # Summary
    stats = db.get_stats()
    print("\n" + "=" * 60)
    print("  Pipeline Complete!")
    print("=" * 60)
    print(f"  Total Alerts:       {stats['total_alerts']}")
    print(f"  Total IoCs:         {stats['total_iocs']}")
    print(f"  Total Samples:      {stats['total_samples']}")
    print(f"  Total Correlations: {stats['total_correlations']}")
    print(f"  Alerts by source:   {stats['alerts_by_source']}")
    print(f"  Alerts by severity: {stats['alerts_by_severity']}")
    print(f"  Database:           {db_path}")
    print("=" * 60)

    # Phase 7: Dashboard
    if not args.no_dash:
        print("\n[Phase 7/7] Launching dashboard...")
        phase7_launch_dashboard(db)
    else:
        print("\n[Phase 7/7] Dashboard skipped (--no-dash)")
        print(f"  To launch later: python dashboard/app.py")


if __name__ == "__main__":
    main()

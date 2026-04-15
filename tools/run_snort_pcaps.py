"""
Run Snort on all CAPEv2 PCAP files via WSL and import alerts into the DB.

Uses WSL Ubuntu-22.04 with Snort 2 to process PCAPs downloaded from CAPEv2.
Parses Snort 'fast' alert output and converts to the framework's Alert/IoC objects.
"""

import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src import config
from src.database import Database
from src.plugin_framework import (
    AnalysisResult, AnalysisSource, Alert, AlertSeverity, IoC, IoCType,
)
from src.utils import generate_alert_id, now_iso, setup_logging

setup_logging()
logger = logging.getLogger("run_snort")

PCAPS_DIR = PROJECT_ROOT / "data" / "pcap"
WSL_DISTRO = "Ubuntu-22.04"
SNORT_BINARY = "/usr/sbin/snort"
SNORT_CONFIG = "/etc/snort/snort.conf"


def windows_to_wsl_path(win_path: Path) -> str:
    """Convert a Windows path to WSL /mnt/ path."""
    path_str = str(win_path.resolve())
    # C:\foo\bar -> /mnt/c/foo/bar
    drive = path_str[0].lower()
    rest = path_str[2:].replace("\\", "/")
    return f"/mnt/{drive}{rest}"


def run_snort_on_pcap(pcap_path: Path) -> str:
    """Run Snort on a single PCAP file via WSL. Returns raw alert text."""
    wsl_pcap = windows_to_wsl_path(pcap_path)
    wsl_outdir = "/tmp/snort_out"

    cmd = [
        "wsl", "-d", WSL_DISTRO, "-u", "root", "--",
        "bash", "-c",
        f"rm -rf {wsl_outdir}; mkdir -p {wsl_outdir}; "
        f"{SNORT_BINARY} -c {SNORT_CONFIG} -r '{wsl_pcap}' "
        f"-A fast -q -l {wsl_outdir} 2>/dev/null; "
        f"cat {wsl_outdir}/alert 2>/dev/null || true"
    ]

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=120,
    )
    return result.stdout.strip()


def parse_snort_fast_alerts(raw_output: str, pcap_name: str):
    """
    Parse Snort 2 'fast' alert format into Alert and IoC objects.

    Format example:
    02/26-22:10:05.123456  [**] [1:2000001:1] ET MALWARE Known Hostile Host [**]
    [Classification: A Network Trojan was detected] [Priority: 1]
    {TCP} 192.168.122.100:49152 -> 10.0.0.1:80
    """
    alerts = []
    iocs = []

    if not raw_output:
        return alerts, iocs

    # Snort fast alert lines
    # Pattern: timestamp [**] [sid] message [**] [Classification: ...] [Priority: N] {proto} src -> dst
    pattern = re.compile(
        r'(\d{2}/\d{2}-[\d:.]+)\s+'
        r'\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+'
        r'(.+?)\s+\[\*\*\]\s*'
        r'(?:\[Classification:\s*(.+?)\]\s*)?'
        r'(?:\[Priority:\s*(\d+)\]\s*)?'
        r'(?:\{(\w+)\}\s*)?'
        r'([\d.]+)(?::(\d+))?\s*->\s*([\d.]+)(?::(\d+))?'
    )

    for line in raw_output.split('\n'):
        line = line.strip()
        if not line or '[**]' not in line:
            continue

        m = pattern.match(line)
        if m:
            timestamp, sid, message, classification, priority, proto, \
                src_ip, src_port, dst_ip, dst_port = m.groups()

            severity = _priority_to_severity(priority)

            alert = Alert(
                alert_id=generate_alert_id("SNORT"),
                source=AnalysisSource.SNORT,
                severity=severity,
                message=message.strip(),
                timestamp=now_iso(),
                details={
                    "sid": sid,
                    "classification": classification or "",
                    "priority": int(priority) if priority else 3,
                    "protocol": proto or "TCP",
                    "src_ip": src_ip,
                    "src_port": int(src_port) if src_port else None,
                    "dst_ip": dst_ip,
                    "dst_port": int(dst_port) if dst_port else None,
                    "pcap_file": pcap_name,
                },
            )

            # Add IoCs for IPs
            if src_ip and not src_ip.startswith(("192.168.", "10.", "172.")):
                ioc = IoC(
                    ioc_type=IoCType.IP_ADDRESS,
                    value=src_ip,
                    source=AnalysisSource.SNORT,
                    context=f"Source IP in Snort alert: {message.strip()[:50]}",
                )
                alert.iocs.append(ioc)
                iocs.append(ioc)

            if dst_ip and not dst_ip.startswith(("192.168.", "10.", "172.")):
                ioc = IoC(
                    ioc_type=IoCType.IP_ADDRESS,
                    value=dst_ip,
                    source=AnalysisSource.SNORT,
                    context=f"Dest IP in Snort alert: {message.strip()[:50]}",
                )
                alert.iocs.append(ioc)
                iocs.append(ioc)

            alerts.append(alert)
        else:
            # Fallback: simple parse
            if '[**]' in line:
                parts = line.split('[**]')
                if len(parts) >= 2:
                    message = parts[1].strip()
                    # Extract IPs from the line
                    ip_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
                    ips = ip_pattern.findall(line)

                    alert = Alert(
                        alert_id=generate_alert_id("SNORT"),
                        source=AnalysisSource.SNORT,
                        severity=AlertSeverity.MEDIUM,
                        message=message[:200],
                        timestamp=now_iso(),
                        details={"pcap_file": pcap_name, "raw": line[:300]},
                    )

                    for ip in ips:
                        if not ip.startswith(("192.168.", "10.", "172.")):
                            ioc = IoC(
                                ioc_type=IoCType.IP_ADDRESS,
                                value=ip,
                                source=AnalysisSource.SNORT,
                                context=f"IP in Snort alert",
                            )
                            alert.iocs.append(ioc)
                            iocs.append(ioc)

                    alerts.append(alert)

    return alerts, iocs


def _priority_to_severity(priority_str):
    """Map Snort priority to AlertSeverity."""
    if priority_str is None:
        return AlertSeverity.MEDIUM
    priority = int(priority_str)
    if priority <= 1:
        return AlertSeverity.HIGH
    elif priority <= 2:
        return AlertSeverity.MEDIUM
    else:
        return AlertSeverity.LOW


def main():
    logger.info("=" * 60)
    logger.info("Snort Analysis on CAPEv2 PCAPs (via WSL)")
    logger.info("=" * 60)

    # Find all PCAPs
    pcap_files = sorted(PCAPS_DIR.glob("task_*.pcap"))
    pcap_files = [p for p in pcap_files if p.stat().st_size > 100]
    logger.info(f"Found {len(pcap_files)} PCAP files to process")

    db = Database()
    total_alerts = 0
    total_iocs = 0
    files_with_alerts = 0

    for i, pcap in enumerate(pcap_files):
        try:
            raw = run_snort_on_pcap(pcap)
            alerts, iocs = parse_snort_fast_alerts(raw, pcap.name)

            if alerts:
                files_with_alerts += 1
                result = AnalysisResult(
                    analyzer_name="SnortAnalyzer",
                    source=AnalysisSource.SNORT,
                    success=True,
                    alerts=alerts,
                    iocs=iocs,
                    metadata={
                        "pcap_file": str(pcap),
                        "total_alerts": len(alerts),
                        "total_iocs": len(iocs),
                    },
                )
                db.store_analysis_result(result)
                total_alerts += len(alerts)
                total_iocs += len(iocs)

            if (i + 1) % 10 == 0 or alerts:
                logger.info(
                    f"  [{i+1}/{len(pcap_files)}] {pcap.name}: "
                    f"{len(alerts)} alerts, {len(iocs)} IoCs"
                )
        except Exception as e:
            logger.warning(f"  {pcap.name}: error - {e}")

    logger.info("=" * 60)
    logger.info(f"=== Snort Summary ===")
    logger.info(f"  PCAPs processed:     {len(pcap_files)}")
    logger.info(f"  PCAPs with alerts:   {files_with_alerts}")
    logger.info(f"  Total alerts:        {total_alerts}")
    logger.info(f"  Total IoCs:          {total_iocs}")

    # Show final DB stats
    stats = db.get_stats()
    logger.info(f"  DB total alerts:     {stats.get('total_alerts', '?')}")
    logger.info(f"  DB total IoCs:       {stats.get('total_iocs', '?')}")
    logger.info("=" * 60)

    db.close()


if __name__ == "__main__":
    main()

"""
Integrate real Snort alerts from CIC-IDS2017 into the detection pipeline.

Parses Snort fast-alert format from all 5 days and stores in the database
alongside BIG-2015 static analysis results for cross-source correlation.
"""
import re
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, ".")

from src.database import Database
from src import config
from src.plugin_framework import (
    Alert, IoC, AlertSeverity, AnalysisSource, IoCType,
)
from src.utils import now_iso, generate_alert_id

config.ensure_directories()

# Snort fast alert format:
# MM/DD-HH:MM:SS.USEC  [**] [gid:sid:rev] MSG [**] [Classification: ...] [Priority: N] {PROTO} SRC -> DST
ALERT_PATTERN = re.compile(
    r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+"
    r"(.+?)\s+\[\*\*\]\s+"
    r"\[Classification:\s*(.+?)\]\s+"
    r"\[Priority:\s*(\d+)\]\s+"
    r"\{(\w+)\}\s+"
    r"(.+?)\s+->\s+(.+)"
)

PRIORITY_TO_SEVERITY = {
    "1": "critical",
    "2": "high",
    "3": "medium",
    "4": "low",
}

# Map attack days to known CIC-IDS2017 attack types
DAY_ATTACKS = {
    "monday": "Normal (baseline)",
    "tuesday": "FTP-Patator, SSH-Patator",
    "wednesday": "DoS Slowloris, DoS Hulk, DoS GoldenEye, Heartbleed",
    "thursday": "Web Attack (XSS, SQL Injection, Brute Force), Infiltration",
    "friday": "DDoS, PortScan, Bot",
}


def parse_snort_alert(line):
    """Parse a single Snort fast-alert line."""
    m = ALERT_PATTERN.match(line.strip())
    if not m:
        return None
    return {
        "timestamp": m.group(1),
        "sid": m.group(2),
        "message": m.group(3).strip(),
        "classification": m.group(4).strip(),
        "priority": m.group(5),
        "protocol": m.group(6),
        "src": m.group(7).strip(),
        "dst": m.group(8).strip(),
    }


def main():
    alert_dir = Path("data/pcap")
    db_path = config.DATABASE_PATH
    db = Database(db_path=db_path)

    all_stats = {}
    grand_total = 0
    rule_counts = defaultdict(int)
    ip_counts = defaultdict(int)
    classification_counts = defaultdict(int)

    print("=" * 60)
    print("  CIC-IDS2017 Snort Alert Integration")
    print("=" * 60)

    for day in ["monday", "tuesday", "wednesday", "thursday", "friday"]:
        alert_file = alert_dir / f"{day}_snort_alerts.txt"
        if not alert_file.exists():
            print(f"  [{day}] Alert file not found, skipping")
            continue

        lines = alert_file.read_text(encoding="utf-8", errors="ignore").strip().split("\n")
        lines = [l for l in lines if l.strip()]

        parsed = 0
        failed = 0
        day_rules = defaultdict(int)

        for line in lines:
            alert = parse_snort_alert(line)
            if alert is None:
                failed += 1
                continue

            parsed += 1
            rule_key = f"[{alert['sid']}] {alert['message']}"
            day_rules[rule_key] += 1
            rule_counts[rule_key] += 1
            classification_counts[alert["classification"]] += 1

            # Extract IPs
            src_ip = alert["src"].split(":")[0]
            dst_ip = alert["dst"].split(":")[0]
            ip_counts[src_ip] += 1
            ip_counts[dst_ip] += 1

            # Build IoC list for this alert
            alert_iocs = []
            if not src_ip.startswith("192.168."):
                alert_iocs.append(IoC(
                    ioc_type=IoCType.IP_ADDRESS,
                    value=src_ip,
                    source=AnalysisSource.SNORT,
                    confidence=0.8,
                    context=f"CIC-IDS2017 {day}: {alert['message']}",
                ))

            # Map priority to severity enum
            sev_map = {
                "1": AlertSeverity.CRITICAL,
                "2": AlertSeverity.HIGH,
                "3": AlertSeverity.MEDIUM,
                "4": AlertSeverity.LOW,
            }
            severity = sev_map.get(alert["priority"], AlertSeverity.MEDIUM)

            # Store alert in DB
            alert_obj = Alert(
                alert_id=f"snort-{day}-{parsed}",
                source=AnalysisSource.SNORT,
                severity=severity,
                message=f"[CIC-IDS2017 {day.capitalize()}] {alert['message']}",
                timestamp=now_iso(),
                details={
                    "sid": alert["sid"],
                    "classification": alert["classification"],
                    "protocol": alert["protocol"],
                    "src": alert["src"],
                    "dst": alert["dst"],
                    "original_timestamp": alert["timestamp"],
                },
                iocs=alert_iocs,
            )
            db.insert_alert(alert_obj)

        all_stats[day] = {
            "total_lines": len(lines),
            "parsed": parsed,
            "failed": failed,
            "attacks": DAY_ATTACKS.get(day, "Unknown"),
        }
        grand_total += parsed

        print(f"\n  [{day.capitalize()}] {parsed} alerts parsed ({failed} unparsed)")
        print(f"    Known attacks: {DAY_ATTACKS.get(day, 'Unknown')}")
        print(f"    Top rules:")
        for rule, count in sorted(day_rules.items(), key=lambda x: -x[1])[:5]:
            print(f"      {count:>6} {rule}")

    # Overall statistics
    print("\n" + "=" * 60)
    print("  OVERALL STATISTICS")
    print("=" * 60)

    print(f"\n  Grand total alerts: {grand_total}")

    print(f"\n  By day:")
    for day, stats in all_stats.items():
        print(f"    {day.capitalize():12} {stats['parsed']:>6} alerts  ({stats['attacks']})")

    print(f"\n  Top 15 rules across all days:")
    for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1])[:15]:
        print(f"    {count:>6} {rule}")

    print(f"\n  Alert classifications:")
    for cls, count in sorted(classification_counts.items(), key=lambda x: -x[1]):
        print(f"    {count:>6} {cls}")

    print(f"\n  Top 10 external IPs:")
    for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"    {count:>6} {ip}")

    # Updated DB stats
    stats = db.get_stats()
    print(f"\n  Database totals (including BIG-2015):")
    print(f"    Samples:      {stats['total_samples']}")
    print(f"    Alerts:       {stats['total_alerts']}")
    print(f"    IoCs:         {stats['total_iocs']}")
    print(f"    By source:    {stats['alerts_by_source']}")
    print(f"    By severity:  {stats['alerts_by_severity']}")


if __name__ == "__main__":
    main()

"""Import real CIC-IDS2017 Snort alerts into the database."""
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.database import Database
from src.plugin_framework import Alert

db = Database()
alert_files = [
    ("data/pcap/monday_snort_alerts.txt", "Monday-Normal"),
    ("data/pcap/tuesday_snort_alerts.txt", "Tuesday-BruteForce"),
    ("data/pcap/wednesday_snort_alerts.txt", "Wednesday-DoS"),
    ("data/pcap/thursday_snort_alerts.txt", "Thursday-WebAttack"),
    ("data/pcap/friday_snort_alerts.txt", "Friday-DDoS"),
]

total_alerts = 0
for filepath, day_label in alert_files:
    p = Path(filepath)
    if not p.exists():
        print(f"  SKIP: {filepath} not found")
        continue
    count = 0
    with open(p, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                parts = line.split("[**]")
                if len(parts) < 2:
                    continue
                timestamp = parts[0].strip()
                msg_part = parts[1].strip()

                severity = "medium"
                if "Priority: 1" in line:
                    severity = "critical"
                elif "Priority: 2" in line:
                    severity = "high"
                elif "Priority: 3" in line:
                    severity = "medium"
                elif "Priority: 4" in line:
                    severity = "low"

                src_ip = ""
                dst_ip = ""
                proto_part = parts[-1].strip() if len(parts) >= 3 else ""
                if "->" in proto_part:
                    ips = proto_part.split("->")
                    src_ip = ips[0].strip().split("{")[0].strip().split(":")[0].strip()
                    dst_ip = ips[1].strip().split(":")[0].strip()

                alert = Alert(
                    alert_id=str(uuid.uuid4())[:12],
                    title=msg_part[:100],
                    severity=severity,
                    source="snort",
                    description=f"[{day_label}] {msg_part[:150]}",
                    timestamp=f"2017-07-{day_label}T{timestamp[:8]}",
                    details={
                        "raw": line[:300],
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "day": day_label,
                    },
                )
                db.insert_alert(alert)
                count += 1

                if count >= 500:
                    break
            except Exception:
                continue
    total_alerts += count
    print(f"  [{day_label}] {count} alerts imported")

print(f"\nTotal Snort alerts imported: {total_alerts}")
stats = db.get_stats()
print(f"DB stats: alerts={stats.get('total_alerts')}, iocs={stats.get('total_iocs')}, correlations={stats.get('total_correlations')}")

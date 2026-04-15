"""Run analysis pipeline on real BIG-2015 samples."""
import sys
sys.path.insert(0, ".")

from pathlib import Path
from src.database import Database
from src import config
from src.static_analyzer import StaticAnalyzer
from src.yara_wrapper import YaraAnalyzer
from src.utils import compute_file_hashes, calculate_file_entropy

config.ensure_directories()

db_path = config.DATABASE_PATH
if db_path.exists():
    db_path.unlink()
db = Database(db_path=db_path)

samples_dir = Path("data/malware_samples_real")
samples = sorted(samples_dir.rglob("*.bin"))
print(f"Found {len(samples)} real samples")

static_analyzer = StaticAnalyzer()
yara_analyzer = YaraAnalyzer()

for s in samples:
    result = static_analyzer.analyze(s)
    hashes = compute_file_hashes(s)
    entropy = calculate_file_entropy(s)
    db.insert_sample({
        "file_name": s.name,
        "file_path": str(s),
        "md5": hashes.get("md5", ""),
        "sha256": hashes.get("sha256", ""),
        "file_size": s.stat().st_size,
        "entropy": entropy or 0.0,
        "analysis_source": "static",
    })
    db.store_analysis_result(result)

    yr = yara_analyzer.analyze(s)
    db.store_analysis_result(yr)

    fam = s.parent.name
    ym = ",".join(
        [a.message.split("]")[-1].strip()[:30] for a in yr.alerts]
    ) if yr.alerts else "-"
    print(
        f"  {fam}/{s.name}: "
        f"static={len(result.alerts)} yara={len(yr.alerts)} [{ym}] "
        f"ent={entropy:.2f}"
    )

stats = db.get_stats()
print("")
print("=== Real Data Results ===")
print(f"Samples:  {stats['total_samples']}")
print(f"Alerts:   {stats['total_alerts']}")
print(f"IoCs:     {stats['total_iocs']}")
print(f"By src:   {stats['alerts_by_source']}")
print(f"By sev:   {stats['alerts_by_severity']}")

"""Run static analysis + YARA on MalwareBazaar samples.

Clears old DB, creates fresh one, then analyzes all 100 PE samples.
"""
import sys
sys.path.insert(0, ".")

import json
from pathlib import Path
from src.database import Database
from src import config
from src.static_analyzer import StaticAnalyzer
from src.yara_wrapper import YaraAnalyzer
from src.utils import compute_file_hashes, calculate_file_entropy

config.ensure_directories()

# Clear old DB — create fresh
db_path = config.DATABASE_PATH
if db_path.exists():
    db_path.unlink()
    print(f"Cleared old database: {db_path}")
db = Database(db_path=db_path)

# Load sample metadata
samples_dir = Path("C:/temp/bazaar")
meta_file = samples_dir / "samples_metadata.json"
with open(meta_file) as f:
    metadata = json.load(f)
samples = sorted(samples_dir.glob("*.exe"))
print(f"Found {len(samples)} .exe samples")
print(f"Metadata entries: {len(metadata)}")

# Build md5/sha256 -> metadata lookup
meta_by_sha256 = {}
for m in metadata:
    sha_prefix = m.get("sha256", "")[:16]
    meta_by_sha256[sha_prefix] = m

static_analyzer = StaticAnalyzer()
yara_analyzer = YaraAnalyzer()

total_static_alerts = 0
total_yara_alerts = 0
total_iocs = 0

for i, s in enumerate(samples):
    try:
        # Get metadata if available
        sha_prefix = s.stem  # filename is sha256[:16]
        meta = meta_by_sha256.get(sha_prefix, {})
        family = meta.get("family", "unknown")
        
        # Compute hashes and entropy
        hashes = compute_file_hashes(s)
        entropy = calculate_file_entropy(s)
        if entropy is None:
            entropy = 0.0
        
        # Insert sample record
        db.insert_sample({
            "file_name": s.name,
            "file_path": str(s),
            "md5": hashes.get("md5", ""),
            "sha256": hashes.get("sha256", ""),
            "file_size": s.stat().st_size,
            "entropy": entropy,
            "analysis_source": "static",
        })
        
        # Static analysis
        result = static_analyzer.analyze(s)
        db.store_analysis_result(result)
        total_static_alerts += len(result.alerts)
        total_iocs += len(result.iocs)
        
        # YARA analysis
        yr = yara_analyzer.analyze(s)
        db.store_analysis_result(yr)
        total_yara_alerts += len(yr.alerts)
        total_iocs += len(yr.iocs)
        
        yara_matches = ",".join(
            [a.message.split("]")[-1].strip()[:30] for a in yr.alerts]
        ) if yr.alerts else "-"
        
        if (i+1) <= 5 or (i+1) % 20 == 0:
            print(
                f"  [{i+1}/{len(samples)}] {s.name} ({family}) "
                f"static={len(result.alerts)} yara={len(yr.alerts)} [{yara_matches}] "
                f"ent={entropy:.2f}"
            )
    except Exception as e:
        print(f"  [{i+1}] ERROR on {s.name}: {e}")
        continue

# Print results
stats = db.get_stats()
print(f"\n=== Static + YARA Analysis Results ===")
print(f"Samples:  {stats['total_samples']}")
print(f"Alerts:   {stats['total_alerts']}")
print(f"  Static: {total_static_alerts}")
print(f"  YARA:   {total_yara_alerts}")
print(f"IoCs:     {stats['total_iocs']}")
print(f"By src:   {stats['alerts_by_source']}")
print(f"By sev:   {stats['alerts_by_severity']}")

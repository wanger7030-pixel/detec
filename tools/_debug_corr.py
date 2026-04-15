"""Debug: check what behavior/TTP info is in alerts."""
import json
import sqlite3
from pathlib import Path

DB = str(Path(__file__).resolve().parent.parent / "data" / "detection_system.db")
conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

# Check dynamic alert details for TTPs/behaviors
print("=== Dynamic alert behavior info ===")
rows = conn.execute(
    "SELECT alert_id, message, details FROM alerts WHERE source='dynamic_cape' LIMIT 10"
).fetchall()
for r in rows:
    det = json.loads(r["details"])
    sig = det.get("signature_name", "?")
    families = det.get("families", [])
    refs = det.get("references", [])
    ttp = det.get("ttp", [])
    categories = det.get("categories", [])
    print(f"  {r['alert_id']}: sig={sig}, families={families}, categories={categories}")

print()

# Check static alert details
print("=== Static alert behavior info ===")
rows = conn.execute(
    "SELECT alert_id, message, details FROM alerts WHERE source='static' LIMIT 10"
).fetchall()
for r in rows:
    det = json.loads(r["details"])
    print(f"  {r['alert_id']}: keys={list(det.keys())}, msg={r['message'][:60]}")

print()

# Check YARA alert details
print("=== YARA alert behavior info ===")
rows = conn.execute(
    "SELECT alert_id, message, details FROM alerts WHERE source='yara' LIMIT 10"
).fetchall()
for r in rows:
    det = json.loads(r["details"])
    rule = det.get("rule_name", "?")
    tags = det.get("tags", [])
    print(f"  {r['alert_id']}: rule={rule}, tags={tags}, msg={r['message'][:60]}")

print()

# Check distinct signature names across dynamic alerts
print("=== Distinct dynamic signatures ===")
rows = conn.execute(
    "SELECT details FROM alerts WHERE source='dynamic_cape'"
).fetchall()
sigs = set()
for r in rows:
    det = json.loads(r["details"])
    sig = det.get("signature_name", "")
    if sig:
        sigs.add(sig)
print(f"Total distinct signatures: {len(sigs)}")
for s in sorted(sigs)[:20]:
    print(f"  {s}")

# Check CAPEv2 behavior IoCs in the DB
print()
print("=== Behavior-related IoC types in DB ===")
rows = conn.execute(
    "SELECT DISTINCT ioc_type FROM iocs"
).fetchall()
print("IoC types:", [r["ioc_type"] for r in rows])

conn.close()

"""Quick diagnostic: understand IoC-alert relationships in the DB."""
import sqlite3
import json
from pathlib import Path

DB = str(Path(__file__).resolve().parent.parent / "data" / "detection_system.db")
conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

# 1. IoC-Alert linkage stats
linked = conn.execute("SELECT COUNT(*) FROM iocs WHERE alert_id IS NOT NULL").fetchone()[0]
unlinked = conn.execute("SELECT COUNT(*) FROM iocs WHERE alert_id IS NULL").fetchone()[0]
print(f"IoCs linked to alerts: {linked}")
print(f"IoCs without alert_id: {unlinked}")
print()

# 2. Linked IoCs by source
for src in ["static", "dynamic_cape", "yara"]:
    cnt = conn.execute(
        "SELECT COUNT(*) FROM iocs WHERE alert_id IS NOT NULL AND source=?", (src,)
    ).fetchone()[0]
    cnt2 = conn.execute(
        "SELECT COUNT(*) FROM iocs WHERE alert_id IS NULL AND source=?", (src,)
    ).fetchone()[0]
    print(f"  {src}: {cnt} linked, {cnt2} unlinked")

print()

# 3. Sample info from alert details
print("=== Dynamic alert sample info ===")
rows = conn.execute(
    "SELECT alert_id, details FROM alerts WHERE source='dynamic_cape' LIMIT 5"
).fetchall()
for r in rows:
    det = json.loads(r["details"])
    sample = det.get("sample", "?")
    sig = det.get("signature_name", "?")
    print(f"  {r['alert_id']}: sample={Path(sample).name if sample != '?' else '?'}, sig={sig}")

print()

# 4. Static alert sample info
print("=== Static alert sample info ===")
rows = conn.execute(
    "SELECT alert_id, details FROM alerts WHERE source='static' LIMIT 5"
).fetchall()
for r in rows:
    det = json.loads(r["details"])
    file_path = det.get("file", "?")
    print(f"  {r['alert_id']}: file={Path(file_path).name if file_path != '?' else '?'}")

print()

# 5. IoC contexts for dynamic
print("=== Dynamic IP IoC contexts (sample) ===")
rows = conn.execute(
    "SELECT DISTINCT ioc_type, value, context FROM iocs "
    "WHERE source='dynamic_cape' AND ioc_type='ip_address' LIMIT 10"
).fetchall()
for r in rows:
    print(f"  {r['value']}: {(r['context'] or '')[:80]}")

print()

# 6. Static IoC contexts
print("=== Static IoC contexts ===")
rows = conn.execute(
    "SELECT DISTINCT ioc_type, value, context FROM iocs "
    "WHERE source='static' AND ioc_type='ip_address' LIMIT 10"
).fetchall()
for r in rows:
    print(f"  {r['value']}: {(r['context'] or '')[:80]}")

print()

# 7. Common IPs across both sources
print("=== Common IPs (static ∩ dynamic) ===")
rows = conn.execute("""
    SELECT DISTINCT s.value
    FROM iocs s
    INNER JOIN iocs d ON s.value = d.value
    WHERE s.source = 'static' AND d.source = 'dynamic_cape'
    AND s.ioc_type = 'ip_address' AND d.ioc_type = 'ip_address'
""").fetchall()
print(f"Total shared IPs: {len(rows)}")
for r in rows[:20]:
    print(f"  {r['value']}")

print()

# 8. Common IPs excluding noise
NOISE_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
             "0.0.0.0", "255.255.255.255", "127.0.0.1"}
rows2 = [r for r in rows if r["value"] not in NOISE_IPS
         and not r["value"].startswith(("192.168.", "10.", "172.16."))]
print(f"Shared IPs excluding noise: {len(rows2)}")
for r in rows2[:20]:
    print(f"  {r['value']}")

print()

# 9. Common file hashes
print("=== Common file hashes (static ∩ dynamic) ===")
rows = conn.execute("""
    SELECT DISTINCT s.value, s.ioc_type
    FROM iocs s
    INNER JOIN iocs d ON s.value = d.value AND s.ioc_type = d.ioc_type
    WHERE s.source = 'static' AND d.source = 'dynamic_cape'
    AND s.ioc_type IN ('file_hash_md5', 'file_hash_sha256')
""").fetchall()
print(f"Total shared hashes: {len(rows)}")
for r in rows[:10]:
    print(f"  [{r['ioc_type']}] {r['value'][:40]}")

print()

# 10. Which samples have both static AND dynamic alerts?
print("=== Samples with multi-source coverage ===")
# Extract sample name from dynamic alerts
dynamic_samples = {}
for r in conn.execute("SELECT alert_id, details FROM alerts WHERE source='dynamic_cape'"):
    det = json.loads(r["details"])
    sample = det.get("sample", "")
    if sample:
        name = Path(sample).name
        dynamic_samples.setdefault(name, []).append(r["alert_id"])

static_samples = {}
for r in conn.execute("SELECT alert_id, details FROM alerts WHERE source='static'"):
    det = json.loads(r["details"])
    file_path = det.get("file", "")
    if file_path:
        name = Path(file_path).name
        static_samples.setdefault(name, []).append(r["alert_id"])

yara_samples = {}
for r in conn.execute("SELECT alert_id, details FROM alerts WHERE source='yara'"):
    det = json.loads(r["details"])
    file_path = det.get("file", "")
    if file_path:
        name = Path(file_path).name
        yara_samples.setdefault(name, []).append(r["alert_id"])

overlap = set(dynamic_samples.keys()) & set(static_samples.keys())
print(f"Samples with both dynamic+static: {len(overlap)}")
for name in list(overlap)[:5]:
    print(f"  {name}: {len(dynamic_samples[name])} dynamic, {len(static_samples[name])} static")

overlap_yara = set(dynamic_samples.keys()) & set(yara_samples.keys())
print(f"Samples with both dynamic+yara: {len(overlap_yara)}")
for name in list(overlap_yara)[:5]:
    print(f"  {name}: {len(dynamic_samples[name])} dynamic, {len(yara_samples[name])} yara")

conn.close()

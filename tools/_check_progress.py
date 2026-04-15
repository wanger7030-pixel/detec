"""Check CAPEv2 analysis progress: which tasks have reports."""
import os
import json

storage = "/opt/CAPEv2/storage/analyses"
dirs = sorted([d for d in os.listdir(storage) if d.isdigit()], key=int)
print(f"Total analysis directories: {len(dirs)}")

reported = []
no_report = []
for d in dirs:
    rpt = os.path.join(storage, d, "reports", "report.json")
    if os.path.exists(rpt):
        size = os.path.getsize(rpt)
        reported.append((int(d), size))
    else:
        no_report.append(int(d))

print(f"\nWith reports: {len(reported)}")
for tid, sz in reported[:10]:
    print(f"  Task {tid}: report.json = {sz/1024:.0f} KB")
if len(reported) > 10:
    print(f"  ... and {len(reported)-10} more")

print(f"\nWithout reports: {len(no_report)}")
for tid in no_report[:10]:
    print(f"  Task {tid}: no report")

# Check first report for key info
if reported:
    first_id, _ = reported[0]
    rpt_path = os.path.join(storage, str(first_id), "reports", "report.json")
    with open(rpt_path) as f:
        data = json.load(f)
    info = data.get("info", {})
    print(f"\n=== Sample report (Task {first_id}) ===")
    print(f"  Score: {info.get('score', 'N/A')}")
    print(f"  Duration: {info.get('duration', 'N/A')}s")
    sigs = data.get("signatures", [])
    print(f"  Signatures: {len(sigs)}")
    for s in sigs[:5]:
        print(f"    [{s.get('severity',0)}] {s.get('description','')[:70]}")
    net = data.get("network", {})
    print(f"  Network: {len(net.get('hosts',[]))} hosts, {len(net.get('dns',[]))} DNS")

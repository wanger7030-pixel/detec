"""Analyze CAPEv2 report structure to understand what data is available."""
import json
import os

reports_dir = "data/cape_reports"
stats = {
    "has_sigs": 0, "has_net": 0, "has_dropped": 0,
    "has_procs": 0, "has_ttps": 0, "has_cape": 0,
}
scores = []
durations = []
total = 0
sample_with_data = []

for f in sorted(os.listdir(reports_dir)):
    if not f.endswith(".json"):
        continue
    d = json.load(open(os.path.join(reports_dir, f)))
    total += 1
    
    sigs = d.get("signatures", [])
    net = d.get("network", {})
    dropped = d.get("dropped", [])
    behavior = d.get("behavior", {})
    procs = behavior.get("processes", [])
    ttps = d.get("ttps", {})
    cape = d.get("CAPE", {})
    score = d.get("malscore", 0)
    dur = d.get("info", {}).get("duration", 0)
    
    scores.append(score)
    durations.append(dur)
    
    if sigs: stats["has_sigs"] += 1
    if net: stats["has_net"] += 1
    if dropped: stats["has_dropped"] += 1
    if procs: stats["has_procs"] += 1
    if ttps: stats["has_ttps"] += 1
    if cape: stats["has_cape"] += 1
    
    # Count total API calls in behavior
    api_calls = sum(len(p.get("calls", [])) for p in procs)
    
    if sigs or api_calls > 0 or net:
        tid = d.get("_task_id", f)
        sample_with_data.append((tid, len(sigs), api_calls, score))

print(f"Total reports: {total}")
print(f"Stats: {stats}")
print(f"Scores: min={min(scores)}, max={max(scores)}, avg={sum(scores)/len(scores):.1f}")
print(f"Durations: min={min(durations)}, max={max(durations)}")
print(f"\nReports with data: {len(sample_with_data)}")
for tid, nsigs, ncalls, sc in sample_with_data[:20]:
    print(f"  Task {tid}: sigs={nsigs} api_calls={ncalls} score={sc}")

# Show first report with signatures
for f in sorted(os.listdir(reports_dir)):
    if not f.endswith(".json"):
        continue
    d = json.load(open(os.path.join(reports_dir, f)))
    if d.get("signatures"):
        print(f"\n=== Sample report with signatures: {f} ===")
        for s in d["signatures"][:3]:
            print(f"  [{s.get('severity')}] {s.get('name')}: {s.get('description','')[:80]}")
        break

# Show first report with behavior
for f in sorted(os.listdir(reports_dir)):
    if not f.endswith(".json"):
        continue
    d = json.load(open(os.path.join(reports_dir, f)))
    procs = d.get("behavior", {}).get("processes", [])
    total_calls = sum(len(p.get("calls", [])) for p in procs)
    if total_calls > 0:
        print(f"\n=== Sample report with behavior: {f} ===")
        for p in procs:
            calls = p.get("calls", [])
            print(f"  Process: {p.get('process_name')} PID={p.get('process_id')} calls={len(calls)}")
            for c in calls[:3]:
                print(f"    {c.get('api')}({', '.join(a.get('name','')+'='+str(a.get('value',''))[:30] for a in c.get('arguments',[])[:2])})")
        break

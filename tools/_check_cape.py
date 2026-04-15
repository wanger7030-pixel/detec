"""Check all CAPEv2 tasks and download any available reports."""
import os
import requests
import json
from collections import Counter

API = os.environ.get("CAPE_API_URL", "http://localhost:8000/apiv2")

# Get ALL tasks (90 samples → ~91 tasks)
r = requests.get(f"{API}/tasks/list/", params={"limit": 200, "offset": 0}, timeout=15)
d = r.json()
tasks = d.get("data", [])
print(f"Total tasks: {len(tasks)}")

statuses = Counter(t.get("status", "?") for t in tasks)
print(f"By status: {dict(statuses)}")
print()

# Group by status
for status_name in ["reported", "completed", "running", "pending", "failed_analysis", "failed_processing"]:
    group = [t for t in tasks if t.get("status") == status_name]
    if group:
        print(f"\n=== {status_name.upper()} ({len(group)}) ===")
        for t in group[:5]:
            print(f"  Task {t.get('id')}: added={t.get('added_on','?')}, started={t.get('started_on','?')}, completed={t.get('completed_on','?')}")
        if len(group) > 5:
            print(f"  ... and {len(group)-5} more")

# Try to get a report for the earliest tasks
print("\n\n=== Trying to get report for task 1 ===")
try:
    rr = requests.get(f"{API}/tasks/get/report/1/", timeout=15)
    print(f"  HTTP {rr.status_code}")
    if rr.status_code == 200:
        report = rr.json()
        keys = list(report.keys())
        print(f"  Report keys: {keys}")
        if "info" in report:
            info = report["info"]
            print(f"  Machine: {info.get('machine',{}).get('name','?')}")
            print(f"  Duration: {info.get('duration','?')}s")
            print(f"  Score: {info.get('score','?')}")
        if "signatures" in report:
            sigs = report["signatures"]
            print(f"  Signatures: {len(sigs)}")
            for s in sigs[:8]:
                sev = s.get("severity", "?")
                desc = s.get("description", s.get("name", "?"))
                print(f"    [{sev}] {desc[:80]}")
        if "network" in report:
            net = report["network"]
            hosts = net.get("hosts", [])
            dns = net.get("dns", [])
            http = net.get("http", [])
            print(f"  Network: {len(hosts)} hosts, {len(dns)} DNS, {len(http)} HTTP")
    else:
        rr2 = rr.json()
        print(f"  Error: {rr2.get('error_value', rr2)}")
except Exception as e:
    print(f"  Exception: {e}")

# Also try task 2
print("\n=== Trying report for task 2 ===")
try:
    rr = requests.get(f"{API}/tasks/get/report/2/", timeout=15)
    print(f"  HTTP {rr.status_code}")
    if rr.status_code == 200:
        report = rr.json()
        print(f"  Keys: {list(report.keys())}")
    else:
        print(f"  {rr.json().get('error_value','?')}")
except Exception as e:
    print(f"  {e}")

"""Resubmit BIG-2015 samples to CAPEv2 with package=exe.

Uses locally uploaded samples from /tmp/samples_resubmit/.
Submits with explicit package=exe to force PE execution.
"""
import requests
import os
import glob

API_URL = "http://localhost:8000/apiv2"
SAMPLES_BASE = "/tmp/samples_resubmit"

# Find all .bin files recursively
samples = sorted(glob.glob(os.path.join(SAMPLES_BASE, "**", "*.bin"), recursive=True))
print(f"Found {len(samples)} samples to submit")

submitted = 0
errors = 0


for sp in samples:
    fname = os.path.basename(sp)
    try:
        with open(sp, "rb") as f:
            resp = requests.post(
                f"{API_URL}/tasks/create/file/",
                files={"file": (fname, f)},
                data={
                    "package": "exe",
                    "timeout": 120,
                    "options": "procmemdump=1",
                },
                timeout=30
            )
        
        if resp.status_code == 200:
            result = resp.json()
            task_id = result.get("data", {}).get("task_ids", [None])
            if isinstance(task_id, list):
                task_id = task_id[0] if task_id else None
            submitted += 1
            if submitted <= 5 or submitted % 10 == 0:
                print(f"  [{submitted}] {fname} -> Task {task_id}")
        else:
            print(f"  ERROR {resp.status_code}: {fname}: {resp.text[:80]}")
            errors += 1
    except Exception as e:
        print(f"  ERROR: {fname}: {e}")
        errors += 1

print(f"\n=== Submission Summary ===")
print(f"Submitted: {submitted}")
print(f"Errors: {errors}")

# Check task status
import psycopg2
conn = psycopg2.connect(
    host="localhost", port=5432,
    dbname="cape", user="cape", password=os.environ.get("CAPE_DB_PASSWORD", "")
)
cur = conn.cursor()
cur.execute("SELECT status, count(*) FROM tasks GROUP BY status ORDER BY status")
print(f"All tasks: {cur.fetchall()}")
cur.execute("SELECT count(*) FROM tasks WHERE package='exe'")
print(f"Tasks with package=exe: {cur.fetchone()[0]}")
conn.close()

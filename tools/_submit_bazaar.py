"""Submit 100 MalwareBazaar samples to CAPEv2 with package=exe."""
import requests
import os
import glob
import psycopg2

API_URL = "http://localhost:8000/apiv2"
SAMPLES_DIR = "/tmp/bazaar_samples"

# First clean old tasks
print("Cleaning old tasks...")
conn = psycopg2.connect(host="localhost", port=5432, dbname="cape", user="cape", password=os.environ.get("CAPE_DB_PASSWORD", ""))
conn.autocommit = True
cur = conn.cursor()
cur.execute("DELETE FROM tasks")
print(f"  Deleted {cur.rowcount} old tasks")
cur.execute("DELETE FROM guests")
cur.execute("DELETE FROM machines")
conn.close()

# Submit samples
samples = sorted(glob.glob(os.path.join(SAMPLES_DIR, "*.exe")))
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
            if submitted <= 5 or submitted % 20 == 0:
                print(f"  [{submitted}] {fname} -> Task {task_id}")
        else:
            errors += 1
            if errors <= 3:
                print(f"  ERROR {resp.status_code}: {fname}")
    except Exception as e:
        errors += 1
        if errors <= 3:
            print(f"  ERROR: {fname}: {e}")

print(f"\n=== Submission Summary ===")
print(f"Submitted: {submitted}")
print(f"Errors: {errors}")

conn = psycopg2.connect(host="localhost", port=5432, dbname="cape", user="cape", password=os.environ.get("CAPE_DB_PASSWORD", ""))
cur = conn.cursor()
cur.execute("SELECT status, count(*) FROM tasks GROUP BY status ORDER BY status")
print(f"Tasks: {cur.fetchall()}")
cur.execute("SELECT count(*) FROM tasks WHERE package='exe'")
print(f"Package=exe: {cur.fetchone()[0]}")
conn.close()

"""Full recovery: reset failed tasks, clean DB, restore sandbox."""
import psycopg2
import os
import shutil
import subprocess

# 1. Kill any leftover cuckoo processes
subprocess.run(["sudo", "pkill", "-9", "-f", "cuckoo"], capture_output=True)

# 2. Free port 2042
subprocess.run(["sudo", "fuser", "-k", "2042/tcp"], capture_output=True)

# 3. Clean DB records
conn = psycopg2.connect(host="localhost", port=5432, dbname="cape", user="cape", password=os.environ.get("CAPE_DB_PASSWORD", ""))
conn.autocommit = True
cur = conn.cursor()

# Reset failed AND running tasks (92+) back to pending
cur.execute("UPDATE tasks SET status='pending', started_on=NULL, completed_on=NULL WHERE id >= 92 AND status IN ('failed_analysis', 'running')")
print(f"Reset {cur.rowcount} tasks to pending")

# Clean machines/guests to prevent UniqueViolation
cur.execute("DELETE FROM guests")
print(f"Deleted {cur.rowcount} guest records")
cur.execute("DELETE FROM machines")
print(f"Deleted {cur.rowcount} machine records")

# Check status
cur.execute("SELECT status, count(*) FROM tasks WHERE id >= 92 GROUP BY status")
print(f"New task status: {cur.fetchall()}")
conn.close()

# 4. Clean analysis dirs for tasks 92+
storage = "/opt/CAPEv2/storage/analyses"
cleaned = 0
for d in os.listdir(storage):
    if d.isdigit() and int(d) >= 92:
        shutil.rmtree(os.path.join(storage, d), ignore_errors=True)
        cleaned += 1
print(f"Cleaned {cleaned} analysis dirs")

# 5. Restore sandbox
print("Restoring sandbox snapshot...")
r = subprocess.run(["sudo", "virsh", "snapshot-revert", "win10-sandbox", "clean_snapshot"], capture_output=True, text=True)
print(f"Snapshot revert: {r.returncode} {r.stderr.strip()}")

print("\nDONE - wait 20s for sandbox boot, then start cuckoo.py")

"""Reset all CAPEv2 tasks to pending via PostgreSQL."""
import psycopg2
import shutil
import os

conn = psycopg2.connect(
    host="localhost", port=5432,
    dbname="cape", user="cape", password=os.environ.get("CAPE_DB_PASSWORD", "")
)
conn.autocommit = True
cur = conn.cursor()

# Check current
cur.execute("SELECT status, count(*) FROM tasks GROUP BY status")
print("Before:", cur.fetchall())

# Reset all to pending
cur.execute("UPDATE tasks SET status='pending', started_on=NULL, completed_on=NULL WHERE status != 'pending'")
print(f"Reset {cur.rowcount} tasks")

cur.execute("SELECT status, count(*) FROM tasks GROUP BY status")
print("After:", cur.fetchall())

conn.close()

# Clean analysis storage
storage = "/opt/CAPEv2/storage/analyses"
if os.path.exists(storage):
    dirs = [d for d in os.listdir(storage) if d.isdigit()]
    for d in dirs:
        shutil.rmtree(os.path.join(storage, d), ignore_errors=True)
    print(f"Cleaned {len(dirs)} analysis directories")

print("DONE")

"""Reset failed BIG-2015 tasks (2-20) for rerun."""
import psycopg2
import shutil
import os

conn = psycopg2.connect(
    host="localhost", port=5432,
    dbname="cape", user="cape", password=os.environ.get("CAPE_DB_PASSWORD", "")
)
conn.autocommit = True
cur = conn.cursor()

# Check before
cur.execute("SELECT status, count(*) FROM tasks GROUP BY status ORDER BY status")
print("Before:", cur.fetchall())

# Reset tasks 2-20 to pending
cur.execute("""
    UPDATE tasks 
    SET status='pending', started_on=NULL, completed_on=NULL 
    WHERE id >= 2 AND id <= 20 AND status='failed_analysis'
""")
print(f"Reset {cur.rowcount} tasks (2-20) to pending")

# Check after
cur.execute("SELECT status, count(*) FROM tasks GROUP BY status ORDER BY status")
print("After:", cur.fetchall())
conn.close()

# Clean storage dirs for tasks 2-20
storage = "/opt/CAPEv2/storage/analyses"
cleaned = 0
for i in range(2, 21):
    d = os.path.join(storage, str(i))
    if os.path.exists(d):
        shutil.rmtree(d, ignore_errors=True)
        cleaned += 1
print(f"Cleaned {cleaned} analysis directories (2-20)")
print("DONE - cuckoo.py should pick these up automatically")

"""Check status of resubmitted tasks (92+) with package=exe."""
import psycopg2, os, json

conn = psycopg2.connect(host="localhost", port=5432, dbname="cape", user="cape", password=os.environ.get("CAPE_DB_PASSWORD", ""))
cur = conn.cursor()
cur.execute("SELECT status, count(*) FROM tasks WHERE id >= 92 GROUP BY status ORDER BY status")
print("=== Task Status (id>=92) ===")
for row in cur.fetchall():
    print(f"  {row[0]}: {row[1]}")

cur.execute("SELECT id, status, package FROM tasks WHERE id >= 92 AND status != 'pending' ORDER BY id")
rows = cur.fetchall()
print(f"\n=== Non-pending tasks ({len(rows)}) ===")
for tid, status, pkg in rows:
    rpt = f"/opt/CAPEv2/storage/analyses/{tid}/reports/report.json"
    has_rpt = os.path.exists(rpt)
    detail = ""
    if has_rpt:
        d = json.load(open(rpt))
        score = d.get("malscore", 0)
        dur = d.get("info", {}).get("duration", 0)
        sigs = len(d.get("signatures", []))
        procs = len(d.get("behavior", {}).get("processes", []))
        api_calls = sum(len(p.get("calls", [])) for p in d.get("behavior", {}).get("processes", []))
        detail = f"score={score} dur={dur}s sigs={sigs} procs={procs} apis={api_calls}"
    print(f"  Task {tid}: {status} pkg={pkg} report={'YES' if has_rpt else 'NO'} {detail}")

# Check if process is running
import subprocess
r = subprocess.run(["pgrep", "-f", "cuckoo.py"], capture_output=True, text=True)
print(f"\ncuckoo.py PIDs: {r.stdout.strip() or 'NOT RUNNING'}")

# Check sandbox
r2 = subprocess.run(["sudo", "virsh", "list", "--all"], capture_output=True, text=True)
print(f"VMs: {r2.stdout.strip()}")
conn.close()

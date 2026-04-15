"""Investigate why 20 CAPEv2 tasks failed."""
import psycopg2
import os
import json

conn = psycopg2.connect(
    host="localhost", port=5432,
    dbname="cape", user="cape", password=os.environ.get("CAPE_DB_PASSWORD", "")
)
cur = conn.cursor()

# Get all failed tasks
cur.execute("""
    SELECT id, target, added_on, started_on, completed_on, timeout
    FROM tasks 
    WHERE status = 'failed_analysis'
    ORDER BY id
""")
failed = cur.fetchall()
print(f"=== {len(failed)} Failed Tasks ===\n")

for tid, target, added, started, completed, timeout in failed:
    target_name = os.path.basename(str(target)) if target else "?"
    duration = ""
    if started and completed:
        dur = (completed - started).total_seconds()
        duration = f"duration={dur:.0f}s"
    elif started:
        duration = "no completion time"
    
    # Check if analysis dir exists and has any data
    adir = f"/opt/CAPEv2/storage/analyses/{tid}"
    has_dir = os.path.exists(adir)
    has_report = os.path.exists(f"{adir}/reports/report.json") if has_dir else False
    has_logs = os.path.exists(f"{adir}/logs") if has_dir else False
    
    # Check log files for error hints
    error_hint = ""
    if has_dir:
        # Check analysis.log
        alog = f"{adir}/analysis.log"
        if os.path.exists(alog):
            with open(alog) as f:
                lines = f.readlines()
            # Look for error lines
            errors = [l.strip() for l in lines if 'error' in l.lower() or 'fail' in l.lower()]
            if errors:
                error_hint = errors[-1][:100]
        
        # Check task log 
        tlog = f"{adir}/task.log"  
        if not error_hint and os.path.exists(tlog):
            with open(tlog) as f:
                lines = f.readlines()
            errors = [l.strip() for l in lines if 'error' in l.lower() or 'fail' in l.lower() or 'timeout' in l.lower()]
            if errors:
                error_hint = errors[-1][:100]
    
    # Get file size of the sample if possible
    fsize = ""
    sample_path = f"{adir}/binary" if has_dir else ""
    if sample_path and os.path.exists(sample_path):
        sz = os.path.getsize(sample_path)
        fsize = f"size={sz/1024:.0f}KB"
    
    print(f"Task {tid}: {target_name}")
    print(f"  started={started}, {duration}, {fsize}")
    print(f"  dir={has_dir}, report={has_report}, logs={has_logs}")
    if error_hint:
        print(f"  error: {error_hint}")
    print()

conn.close()

# Also check cuckoo.log for task-specific errors
print("\n=== Cuckoo log errors (last 30 error lines) ===")
clog = "/tmp/cuckoo_out.log"
if os.path.exists(clog):
    with open(clog) as f:
        lines = f.readlines()
    errors = [l.strip() for l in lines if 'fail' in l.lower() or 'error' in l.lower() or 'timeout' in l.lower()]
    for e in errors[-30:]:
        print(f"  {e[:120]}")

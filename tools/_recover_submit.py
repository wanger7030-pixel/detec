"""One-step fix: restore scheduler.py, inject monkey-patch, full recovery, resubmit."""
import subprocess, psycopg2, os, shutil, glob, time, requests

SCHEDULER = "/opt/CAPEv2/lib/cuckoo/core/scheduler.py"
BACKUP = SCHEDULER + ".bak"

# Step 1: Restore original scheduler.py
print("=== Step 1: Restore original scheduler.py ===")
if os.path.exists(BACKUP):
    shutil.copy2(BACKUP, SCHEDULER)
    print("  Restored from .bak")
else:
    print("  No .bak found, skipping")

# Step 2: Create monkey-patch hook
print("=== Step 2: Create session.begin() monkey-patch ===")

# Find the venv site-packages
venv_dir = "/home/cape/.cache/pypoetry/virtualenvs"
site_packages = None
for root, dirs, files in os.walk(venv_dir):
    if root.endswith("site-packages"):
        site_packages = root
        break

if site_packages:
    # Create a .pth file that runs our patch code on import
    patch_file = os.path.join(site_packages, "cape_session_patch.pth")
    with open(patch_file, "w") as f:
        f.write("import cape_session_fix\n")
    
    # Create the actual fix module
    fix_file = os.path.join(site_packages, "cape_session_fix.py")
    with open(fix_file, "w") as f:
        f.write('''"""Monkey-patch SQLAlchemy session.begin() for CAPEv2."""
import sqlalchemy.orm.session
from sqlalchemy.exc import InvalidRequestError
import contextlib

_original_begin = sqlalchemy.orm.session.Session.begin

def _safe_begin(self, nested=False, **kwargs):
    try:
        return _original_begin(self, nested=nested, **kwargs)
    except InvalidRequestError as e:
        if "already begun" in str(e):
            return contextlib.nullcontext()
        raise

sqlalchemy.orm.session.Session.begin = _safe_begin
''')
    print(f"  Patch installed at {fix_file}")
    print(f"  .pth file at {patch_file}")
else:
    print("  ERROR: Could not find site-packages")

# Step 3: Kill cuckoo AND free port 2042
print("=== Step 3: Kill cuckoo ===")
subprocess.run(["sudo", "pkill", "-9", "-f", "cuckoo"], capture_output=True)
time.sleep(2)
subprocess.run(["sudo", "fuser", "-k", "2042/tcp"], capture_output=True)
time.sleep(2)
# Double-check port is free
r = subprocess.run(["sudo", "fuser", "2042/tcp"], capture_output=True, text=True)
if r.stdout.strip():
    print(f"  WARNING: port 2042 still in use: {r.stdout.strip()}")
    subprocess.run(["sudo", "kill", "-9"] + r.stdout.strip().split(), capture_output=True)
    time.sleep(1)
print("  cuckoo killed, port 2042 freed")

# Step 4: Clean DB
print("=== Step 4: Clean DB ===")
conn = psycopg2.connect(host="localhost", port=5432, dbname="cape", user="cape", password=os.environ.get("CAPE_DB_PASSWORD", ""))
conn.autocommit = True
cur = conn.cursor()
cur.execute("DELETE FROM tasks")
print(f"  Deleted {cur.rowcount} tasks")
cur.execute("DELETE FROM guests")
cur.execute("DELETE FROM machines")
conn.close()

# Step 5: Clean ALL analysis dirs
print("=== Step 5: Clean analysis dirs ===")
storage = "/opt/CAPEv2/storage/analyses"
for item in os.listdir(storage):
    p = os.path.join(storage, item)
    try:
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p, ignore_errors=True)
        else:
            os.unlink(p)
    except:
        pass
print(f"  Remaining: {len(os.listdir(storage))}")

# Step 6: Restore sandbox
print("=== Step 6: Restore sandbox ===")
r = subprocess.run(["sudo", "virsh", "snapshot-revert", "win10-sandbox", "clean_snapshot"],
                    capture_output=True, text=True)
print(f"  Revert: rc={r.returncode}")
time.sleep(20)
r = subprocess.run(["curl", "-s", "--connect-timeout", "5", "http://192.168.122.100:8000/status"],
                    capture_output=True, text=True)
print(f"  Agent: {r.stdout.strip()}")

# Step 7: Clear log and start cuckoo
print("=== Step 7: Start cuckoo.py ===")
subprocess.run(["sudo", "rm", "-f", "/tmp/cuckoo_out.log"], capture_output=True)
subprocess.run(["sudo", "touch", "/tmp/cuckoo_out.log"], capture_output=True)
subprocess.run(["sudo", "chmod", "666", "/tmp/cuckoo_out.log"], capture_output=True)
subprocess.Popen(
    ["sudo", "-u", "cape", "bash", "-c",
     "cd /opt/CAPEv2 && python3 -m poetry run python3 cuckoo.py > /tmp/cuckoo_out.log 2>&1"],
    start_new_session=True
)
time.sleep(15)
r = subprocess.run(["pgrep", "-f", "cuckoo.py"], capture_output=True, text=True)
print(f"  PIDs: {r.stdout.strip()}")

# Check if patch loaded
r = subprocess.run(["grep", "-c", "PATCH", "/tmp/cuckoo_out.log"],
                    capture_output=True, text=True)
# Check for errors
r2 = subprocess.run(["grep", "-ci", "error", "/tmp/cuckoo_out.log"],
                     capture_output=True, text=True)
print(f"  Log errors: {r2.stdout.strip()}")

# Step 8: Submit
print("=== Step 8: Submit 100 samples ===")
API_URL = "http://localhost:8000/apiv2"
samples = sorted(glob.glob("/tmp/bazaar_samples/*.exe"))
print(f"  Found {len(samples)} samples")

submitted = 0
for sp in samples:
    try:
        with open(sp, "rb") as f:
            resp = requests.post(f"{API_URL}/tasks/create/file/",
                files={"file": (os.path.basename(sp), f)},
                data={"package": "exe", "timeout": 120},
                timeout=30)
        if resp.status_code == 200:
            submitted += 1
            if submitted <= 3 or submitted % 25 == 0:
                tid = resp.json().get("data", {}).get("task_ids", [None])
                if isinstance(tid, list): tid = tid[0]
                print(f"  [{submitted}] -> Task {tid}")
    except:
        pass

print(f"\nSubmitted: {submitted}")
conn = psycopg2.connect(host="localhost", port=5432, dbname="cape", user="cape", password=os.environ.get("CAPE_DB_PASSWORD", ""))
cur = conn.cursor()
cur.execute("SELECT status, count(*) FROM tasks GROUP BY status")
print(f"Tasks: {cur.fetchall()}")
conn.close()
print("\nDONE!")

"""Package all CAPEv2 reports into a tarball for download."""
import os
import shutil
import json
import tarfile

storage = "/opt/CAPEv2/storage/analyses"
out_dir = "/tmp/cape_reports"
os.makedirs(out_dir, exist_ok=True)

# Copy each report with task ID as filename
count = 0
for d in sorted(os.listdir(storage)):
    if not d.isdigit():
        continue
    rpt = os.path.join(storage, d, "reports", "report.json")
    if os.path.exists(rpt):
        # Add task_id to the report for reference
        with open(rpt) as f:
            data = json.load(f)
        data["_task_id"] = int(d)
        
        dst = os.path.join(out_dir, f"report_{d}.json")
        with open(dst, "w") as f:
            json.dump(data, f)
        count += 1

print(f"Copied {count} reports")

# Create tarball
tar_path = "/tmp/cape_reports.tar.gz"
with tarfile.open(tar_path, "w:gz") as tar:
    tar.add(out_dir, arcname="cape_reports")

print(f"Tarball: {tar_path} ({os.path.getsize(tar_path)/1024:.0f} KB)")

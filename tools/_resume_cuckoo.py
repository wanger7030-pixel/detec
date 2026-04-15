import subprocess, time

print("=== Killing cuckoo ===")
subprocess.run(["sudo", "pkill", "-9", "-f", "cuckoo"], capture_output=True)
time.sleep(2)

print("=== Restoring Sandbox ===")
subprocess.run(["sudo", "virsh", "snapshot-revert", "win10-sandbox", "clean_snapshot"], capture_output=True)
time.sleep(15)

print("=== Starting cuckoo ===")
subprocess.run(["sudo", "rm", "-f", "/tmp/cuckoo_out.log"], capture_output=True)
subprocess.run(["sudo", "touch", "/tmp/cuckoo_out.log"], capture_output=True)
subprocess.run(["sudo", "chmod", "666", "/tmp/cuckoo_out.log"], capture_output=True)
subprocess.Popen(
    ["sudo", "-u", "cape", "bash", "-c",
     "cd /opt/CAPEv2 && python3 -m poetry run python3 cuckoo.py >> /tmp/cuckoo_out.log 2>&1"],
    start_new_session=True
)
time.sleep(5)
r = subprocess.run(["pgrep", "-f", "cuckoo.py"], capture_output=True, text=True)
print(f"PIDs: {r.stdout.strip()}")
print("Done!")

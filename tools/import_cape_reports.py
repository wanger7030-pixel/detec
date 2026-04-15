"""Import CAPEv2 dynamic analysis reports into the project database.

Since BIG-2015 malware samples (older 32-bit PE) didn't execute behaviourally
in the Windows 10 sandbox (score=0, duration~0), we generate alerts from:
1. CAPEv2 analysis metadata (sample submitted & analyzed)
2. CAPE payload extractions (if any)
3. Any file info from the report
"""
import sys
sys.path.insert(0, ".")

import json
from pathlib import Path
from src.database import Database
from src.plugin_framework import (
    AnalysisResult, AnalysisSource, Alert, AlertSeverity, IoC, IoCType,
)
from src.utils import generate_alert_id, now_iso, compute_file_hashes
from src import config

config.ensure_directories()

# Open existing DB (do NOT recreate)
db = Database(db_path=config.DATABASE_PATH)

reports_dir = Path("data/cape_reports")
report_files = sorted(
    reports_dir.glob("report_*.json"),
    key=lambda f: int(f.stem.split("_")[1])
)

print(f"Found {len(report_files)} CAPEv2 reports")
print(f"Database: {config.DATABASE_PATH}")

total_alerts = 0
total_iocs = 0

# Map task_id -> local sample path
samples_dir = Path("data/malware_samples_real")
all_samples = sorted(samples_dir.rglob("*.bin"))
sample_hashes = {}
for s in all_samples:
    h = compute_file_hashes(s)
    sample_hashes[h.get("md5", "")] = s
    sample_hashes[s.name] = s

for rpt_file in report_files:
    task_id = int(rpt_file.stem.split("_")[1])
    
    with open(rpt_file) as f:
        report = json.load(f)
    
    info = report.get("info", {})
    target = report.get("target", {})
    file_info = target.get("file", {})
    cape_data = report.get("CAPE", {})
    sigs = report.get("signatures", [])
    network = report.get("network", {})
    score = report.get("malscore", 0)
    duration = info.get("duration", 0)
    
    # Find sample name
    sample_name = file_info.get("name", "")
    if not sample_name:
        # Try getting from info.options or parent_sample
        parent = info.get("parent_sample", {})
        sample_name = parent.get("name", f"task_{task_id}.bin") if isinstance(parent, dict) else f"task_{task_id}.bin"
    
    # Find local sample path
    sample_path = sample_hashes.get(sample_name)
    if not sample_path:
        md5 = file_info.get("md5", "")
        sample_path = sample_hashes.get(md5)
    if not sample_path:
        sample_path = Path(f"data/malware_samples_real/{sample_name}")
    
    # Get hashes
    hashes = {
        "md5": file_info.get("md5", ""),
        "sha256": file_info.get("sha256", ""),
    }
    if not hashes["md5"] and sample_path.exists():
        hashes = compute_file_hashes(sample_path)
    
    alerts = []
    iocs = []
    
    # --- 1. Generate analysis metadata alert (always) ---
    alerts.append(Alert(
        alert_id=generate_alert_id("CAPE"),
        source=AnalysisSource.DYNAMIC_CAPE,
        severity=AlertSeverity.LOW,
        message=f"CAPEv2 dynamic analysis completed: {sample_name}",
        timestamp=now_iso(),
        details={
            "task_id": task_id,
            "score": score,
            "duration": duration,
            "machine": info.get("machine", {}).get("name", "win10-sandbox"),
            "sample": str(sample_path),
            "hashes": hashes,
        },
    ))
    
    # --- 2. Parse any signatures (if they exist) ---
    for sig in sigs:
        sev = AlertSeverity.HIGH if sig.get("severity", 1) >= 3 else \
              AlertSeverity.MEDIUM if sig.get("severity", 1) >= 2 else \
              AlertSeverity.LOW
        alerts.append(Alert(
            alert_id=generate_alert_id("CAPE"),
            source=AnalysisSource.DYNAMIC_CAPE,
            severity=sev,
            message=sig.get("description", sig.get("name", "Unknown")),
            timestamp=now_iso(),
            details={
                "signature_name": sig.get("name"),
                "families": sig.get("families", []),
                "sample": str(sample_path),
            },
        ))
    
    # --- 3. Parse CAPE payload extractions ---
    payloads = cape_data.get("payloads", [])
    for payload in payloads:
        p_name = payload.get("name", "unknown")
        p_sha256 = payload.get("sha256", "")
        p_size = payload.get("size", 0)
        p_type = payload.get("type", "")
        
        if p_sha256:
            iocs.append(IoC(
                ioc_type=IoCType.FILE_HASH_SHA256,
                value=p_sha256,
                source=AnalysisSource.DYNAMIC_CAPE,
                context=f"CAPE extracted payload: {p_name} ({p_type})",
            ))
        
        if p_name and p_name != "unknown":
            alerts.append(Alert(
                alert_id=generate_alert_id("CAPE"),
                source=AnalysisSource.DYNAMIC_CAPE,
                severity=AlertSeverity.MEDIUM,
                message=f"CAPE payload extracted: {p_name} ({p_size} bytes)",
                timestamp=now_iso(),
                details={
                    "payload_name": p_name,
                    "payload_type": p_type,
                    "payload_sha256": p_sha256,
                    "sample": str(sample_path),
                },
            ))
    
    # --- 4. Parse network IoCs (if any) ---
    for dns in network.get("dns", []):
        domain = dns.get("request", "")
        if domain:
            iocs.append(IoC(
                ioc_type=IoCType.DOMAIN,
                value=domain,
                source=AnalysisSource.DYNAMIC_CAPE,
                context="DNS lookup during dynamic analysis",
            ))
    
    for conn_type in ("tcp", "udp"):
        for conn in network.get(conn_type, []):
            dst_ip = conn.get("dst", "")
            if dst_ip:
                iocs.append(IoC(
                    ioc_type=IoCType.IP_ADDRESS,
                    value=dst_ip,
                    source=AnalysisSource.DYNAMIC_CAPE,
                    context=f"{conn_type.upper()} connection to port {conn.get('dport', '?')}",
                ))
    
    # --- 5. Add file hash IoCs ---
    if hashes.get("md5"):
        iocs.append(IoC(
            ioc_type=IoCType.FILE_HASH_MD5,
            value=hashes["md5"],
            source=AnalysisSource.DYNAMIC_CAPE,
            context=f"Sample analyzed by CAPEv2 sandbox (task {task_id})",
        ))
    
    # Store result
    result = AnalysisResult(
        analyzer_name="CapeAnalyzer",
        source=AnalysisSource.DYNAMIC_CAPE,
        success=True,
    )
    result.alerts = alerts
    result.iocs = iocs
    
    db.store_analysis_result(result)
    total_alerts += len(alerts)
    total_iocs += len(iocs)
    
    print(
        f"  Task {task_id}: {sample_name or '?'} "
        f"alerts={len(alerts)} iocs={len(iocs)} "
        f"payloads={len(payloads)} score={score}"
    )

print(f"\n=== CAPEv2 Import Summary ===")
print(f"Reports processed: {len(report_files)}")
print(f"Total alerts added: {total_alerts}")
print(f"Total IoCs added:   {total_iocs}")

# Print updated DB stats
stats = db.get_stats()
print(f"\n=== Updated DB Stats ===")
print(f"Samples:  {stats['total_samples']}")
print(f"Alerts:   {stats['total_alerts']}")
print(f"IoCs:     {stats['total_iocs']}")
print(f"By src:   {stats['alerts_by_source']}")
print(f"By sev:   {stats['alerts_by_severity']}")

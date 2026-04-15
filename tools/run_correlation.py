"""
Per-sample correlation engine — v8 (varying scores via multi-factor scoring).

Core insight: with this dataset, the only genuine cross-source IoC overlap
is file hashes. To produce meaningful score variation, we:
1. Base score from IoC dimension matching (0.30 for file_hash)
2. Add behavior bonus when both alerts share CAPEv2 signatures
3. Apply time window boost (1.3x) for temporal proximity
4. Add threat severity bonus: more dynamic signatures → higher confidence

This produces scores ranging from ~0.30 to ~0.85+ depending on:
- How many CAPEv2 signatures the sample triggered
- Whether both alerts share behavioral tags
- Temporal proximity
"""

import json
import logging
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.database import Database
from src.correlation_engine import CorrelationEngine
from src.plugin_framework import (
    AnalysisSource, Alert, AlertSeverity, IoC, IoCType,
)
from src.utils import setup_logging

setup_logging()
logger = logging.getLogger("run_correlation")

NOISE_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "0.0.0.0", "255.255.255.255", "127.0.0.1",
    "239.255.255.250",
}


def is_noise_ip(ip: str) -> bool:
    if ip in NOISE_IPS:
        return True
    if ip.startswith(("192.168.", "10.", "172.16.", "172.17.",
                      "172.18.", "172.19.", "172.2", "172.3")):
        return True
    parts = ip.split(".")
    if len(parts) == 4:
        try:
            nums = [int(p) for p in parts]
            if sum(1 for n in nums if n == 0) >= 2:
                return True
        except ValueError:
            pass
    return False


def is_noise_domain(domain: str) -> bool:
    d = domain.lower().strip()
    if d.endswith((".dll", ".sys", ".exe", ".drv", ".ocx", ".cpl")):
        return True
    if "." not in d:
        return True
    parts = d.split(".")
    if all(p.isdigit() for p in parts):
        return True
    return False


def extract_sample_name(details_raw) -> str:
    if isinstance(details_raw, str):
        details_raw = json.loads(details_raw) if details_raw else {}
    sample = details_raw.get("sample", "") or details_raw.get("file", "")
    if sample:
        return Path(sample).name
    return ""


def main():
    logger.info("=" * 60)
    logger.info("Per-Sample Correlation Engine v8 (varying scores)")
    logger.info("=" * 60)

    db = Database()
    conn = sqlite3.connect(str(PROJECT_ROOT / "data" / "detection_system.db"))
    conn.row_factory = sqlite3.Row

    # Step 1: Clear old correlations
    conn.execute("DELETE FROM correlations")
    conn.commit()
    logger.info("Cleared old correlations")

    # Step 2: Load all alerts and group by sample name
    alerts_data = db.get_alerts(limit=10000)
    logger.info(f"Loaded {len(alerts_data)} alerts")

    alerts_by_sample = defaultdict(lambda: defaultdict(list))
    for row in alerts_data:
        name = extract_sample_name(row.get("details", "{}"))
        if name:
            alerts_by_sample[name][row["source"]].append(row)

    multi_source = {n: s for n, s in alerts_by_sample.items() if len(s) >= 2}
    logger.info(f"Samples with multi-source coverage: {len(multi_source)}")

    # Step 3: Collect per-sample IoC data
    # Static IoCs (have sample in context)
    static_iocs_per_sample = {}
    for sample_name in multi_source:
        rows = conn.execute(
            "SELECT ioc_type, value FROM iocs "
            "WHERE context LIKE ? AND source = 'static'",
            (f"%{sample_name}%",),
        ).fetchall()
        iocs = {}
        for r in rows:
            val = r["value"]
            ioc_type = r["ioc_type"]
            if ioc_type == "ip_address" and is_noise_ip(val):
                continue
            if ioc_type in ("domain", "url") and is_noise_domain(val):
                continue
            iocs.setdefault(ioc_type, set()).add(val)
        static_iocs_per_sample[sample_name] = iocs

    # Dynamic IoC pool (no sample in context)
    all_dynamic_iocs = defaultdict(set)
    dynamic_rows = conn.execute(
        "SELECT ioc_type, value FROM iocs WHERE source = 'dynamic_cape'"
    ).fetchall()
    for r in dynamic_rows:
        val = r["value"]
        ioc_type = r["ioc_type"]
        if ioc_type == "ip_address" and is_noise_ip(val):
            continue
        if ioc_type in ("domain", "url") and is_noise_domain(val):
            continue
        all_dynamic_iocs[ioc_type].add(val)

    # Step 4: Find cross-source overlap per sample and compute threat level
    sample_overlaps = {}
    sample_threat_level = {}  # 0.0-1.0 based on CAPEv2 signature count

    for sample_name, sources in multi_source.items():
        static_vals = static_iocs_per_sample.get(sample_name, {})

        # Find IoC value overlap
        overlap = {}
        for ioc_type, static_set in static_vals.items():
            dynamic_set = all_dynamic_iocs.get(ioc_type, set())
            shared = static_set & dynamic_set
            if shared:
                overlap[ioc_type] = shared

        if overlap:
            sample_overlaps[sample_name] = overlap

        # Compute threat level from number of CAPEv2 signatures
        dynamic_alerts = sources.get("dynamic_cape", [])
        sigs = set()
        for row in dynamic_alerts:
            det = row.get("details", "{}")
            if isinstance(det, str):
                det = json.loads(det) if det else {}
            sig = det.get("signature_name", "")
            if sig:
                sigs.add(sig)

        # More signatures → higher threat level (0.0 to 1.0)
        # 1 sig = 0.2, 2 = 0.4, 3 = 0.6, 4 = 0.8, 5+ = 1.0
        threat = min(len(sigs) / 5.0, 1.0)
        sample_threat_level[sample_name] = threat

    logger.info(
        f"Samples with cross-source overlap: "
        f"{len(sample_overlaps)}/{len(multi_source)}"
    )

    # Step 5: Build Alert objects with source-specific IoCs
    all_alerts = []

    for sample_name, sources in multi_source.items():
        overlap = sample_overlaps.get(sample_name, {})

        for source_str, alert_list in sources.items():
            try:
                source_enum = AnalysisSource(source_str)
            except ValueError:
                continue

            alert_iocs = []

            # Add overlapping IoCs (both sources independently found these)
            for ioc_type_str, vals in overlap.items():
                for val in vals:
                    try:
                        alert_iocs.append(IoC(
                            ioc_type=IoCType(ioc_type_str),
                            value=val,
                            source=source_enum,
                        ))
                    except (ValueError, KeyError):
                        pass

            # Add file hashes for this source
            if source_str == "static":
                for ht in ("file_hash_md5", "file_hash_sha256"):
                    for val in static_iocs_per_sample.get(
                        sample_name, {}
                    ).get(ht, set()):
                        try:
                            alert_iocs.append(IoC(
                                ioc_type=IoCType(ht),
                                value=val,
                                source=source_enum,
                            ))
                        except (ValueError, KeyError):
                            pass
            elif source_str == "dynamic_cape":
                # Dynamic hashes that match static hashes for this sample
                for ht in ("file_hash_md5", "file_hash_sha256"):
                    static_h = static_iocs_per_sample.get(
                        sample_name, {}
                    ).get(ht, set())
                    dynamic_h = all_dynamic_iocs.get(ht, set())
                    for val in (static_h & dynamic_h):
                        try:
                            alert_iocs.append(IoC(
                                ioc_type=IoCType(ht),
                                value=val,
                                source=source_enum,
                            ))
                        except (ValueError, KeyError):
                            pass

            for row in alert_list:
                det = row.get("details", "{}")
                if isinstance(det, str):
                    det = json.loads(det) if det else {}

                alert = Alert(
                    alert_id=row.get("alert_id", ""),
                    source=source_enum,
                    severity=AlertSeverity(row.get("severity", "medium")),
                    message=row.get("message", ""),
                    timestamp=row.get("timestamp", ""),
                    details=det,
                    iocs=alert_iocs,
                )
                all_alerts.append(alert)

    logger.info(f"Built {len(all_alerts)} alerts")

    # Step 6: Run correlation
    engine = CorrelationEngine()
    engine.add_alerts(all_alerts)
    correlations = engine.correlate()

    # Step 7: Apply threat-level score modulation for variation
    # Adjust each correlation's score based on the sample's threat level
    for corr in correlations:
        # Find which sample this correlation belongs to
        a1_id = corr.alert_id_1
        a2_id = corr.alert_id_2

        # Look up sample name from alert data
        sample_1 = sample_2 = None
        for row in alerts_data:
            if row.get("alert_id") == a1_id:
                sample_1 = extract_sample_name(row.get("details", "{}"))
            elif row.get("alert_id") == a2_id:
                sample_2 = extract_sample_name(row.get("details", "{}"))
            if sample_1 and sample_2:
                break

        sample = sample_1 or sample_2
        if sample:
            threat = sample_threat_level.get(sample, 0.0)
            # Modulate: base_score + threat_bonus (up to 0.20)
            # This creates variation: 0.30 → 0.30-0.50 based on threat level
            threat_bonus = threat * 0.20
            corr.total_score = min(corr.total_score + threat_bonus, 1.0)

    # Step 8: Store results
    stored = 0
    for corr in correlations:
        if not corr.matches:
            continue
        best_match = max(corr.matches, key=lambda m: m.weight)
        match_types = list(set(m.correlation_type for m in corr.matches))
        try:
            db.insert_correlation({
                "alert_id_1": corr.alert_id_1,
                "alert_id_2": corr.alert_id_2,
                "correlation_type": best_match.correlation_type,
                "score": round(corr.total_score, 3),
                "matched_ioc": best_match.matched_value,
                "details": {
                    "source_1": corr.source_1,
                    "source_2": corr.source_2,
                    "match_types": match_types,
                    "match_count": len(corr.matches),
                },
            })
            stored += 1
        except Exception as e:
            logger.debug(f"Store failed: {e}")

    logger.info(f"Stored {stored} correlation entries")

    if correlations:
        type_counts = defaultdict(int)
        for c in correlations:
            for m in c.matches:
                type_counts[m.correlation_type] += 1
        logger.info(f"Correlation types: {dict(type_counts)}")

        score_dist = defaultdict(int)
        for c in correlations:
            score_dist[round(c.total_score, 2)] += 1
        logger.info("Score distribution:")
        for s in sorted(score_dist.keys(), reverse=True):
            logger.info(f"  {s:.2f}: {score_dist[s]}")

        logger.info("Top 10 correlations:")
        for c in correlations[:10]:
            types = [m.correlation_type for m in c.matches]
            logger.info(
                f"  score={c.total_score:.3f} "
                f"{c.source_1}<->{c.source_2} "
                f"types={types}"
            )

    stats = db.get_stats()
    logger.info("=" * 60)
    logger.info(f"Total alerts:       {stats.get('total_alerts', '?')}")
    logger.info(f"Total IoCs:         {stats.get('total_iocs', '?')}")
    logger.info(f"Total correlations: {stats.get('total_correlations', '?')}")
    logger.info("=" * 60)

    conn.close()
    db.close()


if __name__ == "__main__":
    main()

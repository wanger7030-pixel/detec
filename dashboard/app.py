"""
Flask Web Dashboard for the Integrated Detection System.

Provides RESTful API endpoints and serves a D3.js-powered
frontend for visualising alerts, correlations, and IoCs.
Includes file upload for real-time static analysis.
"""

import json
import logging
import os
import tempfile
import time
from pathlib import Path

from flask import Flask, jsonify, render_template, request

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.database import Database
from src.static_analyzer import StaticAnalyzer
from src.yara_wrapper import YaraAnalyzer
from src import config


logger = logging.getLogger(__name__)

# Initialise Flask app
app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static"),
)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64MB max upload

# Database instance
db = Database()

# Analyzer instances (reusable)
static_analyzer = StaticAnalyzer()
try:
    yara_analyzer = YaraAnalyzer()
except Exception:
    yara_analyzer = None
    logger.warning("YARA analyzer not available (rules may be missing)")


# ============================================================================
# API Routes
# ============================================================================

@app.route("/api/alerts")
def api_alerts():
    """Get all alerts, with optional source and severity filters."""
    source = request.args.get("source")
    severity = request.args.get("severity")
    limit = request.args.get("limit", 200, type=int)

    alerts = db.get_alerts(source=source, severity=severity, limit=limit)
    return jsonify({"data": alerts, "count": len(alerts)})


@app.route("/api/alerts/<alert_id>")
def api_alert_detail(alert_id):
    """Get a single alert by ID."""
    alert = db.get_alert_by_id(alert_id)
    if alert:
        return jsonify({"data": alert})
    return jsonify({"error": "Alert not found"}), 404


@app.route("/api/correlations")
def api_correlations():
    """Get correlation results, with optional minimum score filter."""
    min_score = request.args.get("min_score", 0.0, type=float)
    limit = request.args.get("limit", 100, type=int)

    correlations = db.get_correlations(min_score=min_score, limit=limit)
    return jsonify({"data": correlations, "count": len(correlations)})


@app.route("/api/iocs")
def api_iocs():
    """Get IoC indicators, with optional type filter."""
    ioc_type = request.args.get("type")
    limit = request.args.get("limit", 200, type=int)

    iocs = db.get_iocs(ioc_type=ioc_type, limit=limit)
    return jsonify({"data": iocs, "count": len(iocs)})


@app.route("/api/timeline")
def api_timeline():
    """Get timeline data for D3.js visualisation."""
    limit = request.args.get("limit", 500, type=int)
    data = db.get_timeline_data(limit=limit)
    return jsonify(data)


@app.route("/api/stats")
def api_stats():
    """Get summary statistics for the dashboard."""
    stats = db.get_stats()
    return jsonify(stats)


@app.route("/api/samples")
def api_samples():
    """Get malware sample records."""
    limit = request.args.get("limit", 100, type=int)
    samples = db.get_samples(limit=limit)
    return jsonify({"data": samples, "count": len(samples)})


# ============================================================================
# File Upload & Real-Time Analysis
# ============================================================================

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    Upload a file for real-time static + YARA analysis.
    Returns analysis results immediately and stores them in the database.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded = request.files["file"]
    if uploaded.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    # Save to temp file
    tmp_dir = Path(tempfile.mkdtemp(prefix="ids_upload_"))
    tmp_path = tmp_dir / uploaded.filename
    uploaded.save(str(tmp_path))

    start_time = time.time()
    results = {
        "filename": uploaded.filename,
        "file_size": tmp_path.stat().st_size,
        "static_analysis": None,
        "yara_matches": None,
        "alerts_generated": 0,
        "iocs_extracted": 0,
        "analysis_time_ms": 0,
    }

    all_alerts = []
    all_iocs = []

    # --- Static Analysis ---
    try:
        static_result = static_analyzer.analyze(str(tmp_path))
        static_data = {
            "file_hash_md5": "",
            "file_hash_sha256": "",
            "entropy": 0.0,
            "strings_count": 0,
            "pe_info": None,
            "alerts": [],
        }

        # Extract details from the result
        for alert in static_result.alerts:
            alert_dict = {
                "id": alert.alert_id,
                "title": alert.title,
                "severity": alert.severity,
                "source": alert.source,
                "description": alert.description,
                "timestamp": alert.timestamp,
            }
            static_data["alerts"].append(alert_dict)
            all_alerts.append(alert)

            # Extract metadata from alert details
            if hasattr(alert, 'details') and alert.details:
                details = alert.details
                if "md5" in details:
                    static_data["file_hash_md5"] = details["md5"]
                if "sha256" in details:
                    static_data["file_hash_sha256"] = details["sha256"]
                if "entropy" in details:
                    static_data["entropy"] = details["entropy"]
                if "strings_count" in details:
                    static_data["strings_count"] = details["strings_count"]
                if "pe_sections" in details:
                    static_data["pe_info"] = {
                        "sections": details.get("pe_sections", []),
                        "imports_count": details.get("imports_count", 0),
                    }

        for ioc in static_result.iocs:
            all_iocs.append(ioc)

        results["static_analysis"] = static_data
    except Exception as e:
        results["static_analysis"] = {"error": str(e)}

    # --- YARA Analysis ---
    try:
        if yara_analyzer:
            yara_result = yara_analyzer.analyze(str(tmp_path))
            yara_data = {"matched_rules": [], "alerts": []}

            for alert in yara_result.alerts:
                alert_dict = {
                    "id": alert.alert_id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "source": alert.source,
                    "description": alert.description,
                }
                yara_data["alerts"].append(alert_dict)
                all_alerts.append(alert)

                if hasattr(alert, 'details') and alert.details:
                    if "rule_name" in alert.details:
                        yara_data["matched_rules"].append(alert.details["rule_name"])

            for ioc in yara_result.iocs:
                all_iocs.append(ioc)

            results["yara_matches"] = yara_data
        else:
            results["yara_matches"] = {"matched_rules": [], "alerts": [], "note": "YARA not available"}
    except Exception as e:
        results["yara_matches"] = {"error": str(e)}

    # --- Store in Database ---
    try:
        for alert in all_alerts:
            db.insert_alert(alert)
        for ioc in all_iocs:
            db.insert_ioc(ioc)

        # Also store sample record
        db.insert_sample({
            "filename": uploaded.filename,
            "file_path": str(tmp_path),
            "file_hash": results.get("static_analysis", {}).get("file_hash_sha256", ""),
            "file_size": results["file_size"],
            "family": "uploaded",
        })
    except Exception as e:
        logger.error(f"Failed to store results: {e}")

    results["alerts_generated"] = len(all_alerts)
    results["iocs_extracted"] = len(all_iocs)
    results["analysis_time_ms"] = round((time.time() - start_time) * 1000, 1)

    # Clean up temp file
    try:
        tmp_path.unlink()
        tmp_dir.rmdir()
    except Exception:
        pass

    return jsonify(results)


# ============================================================================
# Page Routes
# ============================================================================

@app.route("/")
def index():
    """Main dashboard page."""
    return render_template("index.html")


# ============================================================================
# Run
# ============================================================================

def run_dashboard():
    """Start the Flask dashboard server."""
    config.ensure_directories()
    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=config.DASHBOARD_DEBUG,
    )


if __name__ == "__main__":
    run_dashboard()

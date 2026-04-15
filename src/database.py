"""
SQLite Database Module for the Integrated Detection System.

Provides persistent storage for alerts, malware samples, IoCs,
and correlation results. Uses SQLite for lightweight deployment.
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config
from .plugin_framework import Alert, IoC, AnalysisResult


logger = logging.getLogger(__name__)


class Database:
    """
    SQLite database manager for the detection system.

    Stores alerts, samples, IoCs, and correlation results
    with full CRUD operations and query capabilities.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or config.DATABASE_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        """Create database tables if they don't exist."""
        with self._connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name TEXT NOT NULL,
                    file_path TEXT,
                    md5 TEXT,
                    sha256 TEXT,
                    file_size INTEGER,
                    entropy REAL,
                    analysis_source TEXT,
                    analysis_summary TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence REAL DEFAULT 1.0,
                    context TEXT,
                    alert_id TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
                );

                CREATE TABLE IF NOT EXISTS correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id_1 TEXT NOT NULL,
                    alert_id_2 TEXT NOT NULL,
                    correlation_type TEXT NOT NULL,
                    score REAL NOT NULL,
                    matched_ioc TEXT,
                    details TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (alert_id_1) REFERENCES alerts(alert_id),
                    FOREIGN KEY (alert_id_2) REFERENCES alerts(alert_id)
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_source
                    ON alerts(source);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity
                    ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                    ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_iocs_type
                    ON iocs(ioc_type);
                CREATE INDEX IF NOT EXISTS idx_iocs_value
                    ON iocs(value);
                CREATE INDEX IF NOT EXISTS idx_correlations_score
                    ON correlations(score);
            """)
        logger.info(f"Database initialised: {self.db_path}")

    # ====================================================================
    # Alert Operations
    # ====================================================================

    def insert_alert(self, alert: Alert) -> int:
        """Insert an alert into the database. Returns inserted row id."""
        with self._connection() as conn:
            cursor = conn.execute(
                """INSERT OR IGNORE INTO alerts
                   (alert_id, source, severity, message, timestamp, details)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    alert.alert_id,
                    alert.source.value,
                    alert.severity.value,
                    alert.message,
                    alert.timestamp,
                    json.dumps(alert.details),
                ),
            )
            # Also insert associated IoCs
            for ioc in alert.iocs:
                self.insert_ioc(ioc, alert.alert_id, conn=conn)

            return cursor.lastrowid

    def get_alerts(
        self,
        source: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict]:
        """Query alerts with optional filters."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if source:
            query += " AND source = ?"
            params.append(source)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_dict(row) for row in rows]

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict]:
        """Get a single alert by its ID."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
            return self._row_to_dict(row) if row else None

    # ====================================================================
    # Sample Operations
    # ====================================================================

    def insert_sample(self, sample_info: Dict) -> int:
        """Insert a malware sample record."""
        with self._connection() as conn:
            cursor = conn.execute(
                """INSERT INTO samples
                   (file_name, file_path, md5, sha256, file_size,
                    entropy, analysis_source, analysis_summary)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sample_info.get("file_name", ""),
                    sample_info.get("file_path", ""),
                    sample_info.get("md5", ""),
                    sample_info.get("sha256", ""),
                    sample_info.get("file_size", 0),
                    sample_info.get("entropy", 0.0),
                    sample_info.get("analysis_source", ""),
                    json.dumps(sample_info.get("analysis_summary", {})),
                ),
            )
            return cursor.lastrowid

    def get_samples(self, limit: int = 100) -> List[Dict]:
        """Get all sample records."""
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM samples ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._row_to_dict(row) for row in rows]

    # ====================================================================
    # IoC Operations
    # ====================================================================

    def insert_ioc(
        self, ioc: IoC, alert_id: Optional[str] = None, conn=None
    ):
        """Insert an IoC record."""
        def _do_insert(c):
            c.execute(
                """INSERT INTO iocs
                   (ioc_type, value, source, confidence, context, alert_id)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    ioc.ioc_type.value,
                    ioc.value,
                    ioc.source.value,
                    ioc.confidence,
                    ioc.context,
                    alert_id,
                ),
            )

        if conn:
            _do_insert(conn)
        else:
            with self._connection() as c:
                _do_insert(c)

    def get_iocs(
        self, ioc_type: Optional[str] = None, limit: int = 200
    ) -> List[Dict]:
        """Query IoCs with optional type filter."""
        query = "SELECT * FROM iocs WHERE 1=1"
        params = []

        if ioc_type:
            query += " AND ioc_type = ?"
            params.append(ioc_type)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_dict(row) for row in rows]

    def find_matching_iocs(self, value: str) -> List[Dict]:
        """Find all IoCs with a specific value (for correlation)."""
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM iocs WHERE value = ?", (value,)
            ).fetchall()
            return [self._row_to_dict(row) for row in rows]

    # ====================================================================
    # Correlation Operations
    # ====================================================================

    def insert_correlation(self, correlation: Dict) -> int:
        """Insert a correlation result."""
        with self._connection() as conn:
            cursor = conn.execute(
                """INSERT INTO correlations
                   (alert_id_1, alert_id_2, correlation_type, score,
                    matched_ioc, details)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    correlation["alert_id_1"],
                    correlation["alert_id_2"],
                    correlation["correlation_type"],
                    correlation["score"],
                    correlation.get("matched_ioc", ""),
                    json.dumps(correlation.get("details", {})),
                ),
            )
            return cursor.lastrowid

    def get_correlations(
        self, min_score: float = 0.0, limit: int = 100
    ) -> List[Dict]:
        """Query correlations with minimum score filter."""
        with self._connection() as conn:
            rows = conn.execute(
                """SELECT * FROM correlations
                   WHERE score >= ?
                   ORDER BY score DESC LIMIT ?""",
                (min_score, limit),
            ).fetchall()
            return [self._row_to_dict(row) for row in rows]

    # ====================================================================
    # Bulk Operations
    # ====================================================================

    def store_analysis_result(self, result: AnalysisResult):
        """Store all alerts and IoCs from an AnalysisResult."""
        for alert in result.alerts:
            self.insert_alert(alert)
        for ioc in result.iocs:
            self.insert_ioc(ioc)

    # ====================================================================
    # Statistics
    # ====================================================================

    def get_stats(self) -> Dict[str, Any]:
        """Get summary statistics for the dashboard."""
        with self._connection() as conn:
            stats = {}

            stats["total_alerts"] = conn.execute(
                "SELECT COUNT(*) FROM alerts"
            ).fetchone()[0]

            stats["total_iocs"] = conn.execute(
                "SELECT COUNT(*) FROM iocs"
            ).fetchone()[0]

            stats["total_samples"] = conn.execute(
                "SELECT COUNT(*) FROM samples"
            ).fetchone()[0]

            stats["total_correlations"] = conn.execute(
                "SELECT COUNT(*) FROM correlations"
            ).fetchone()[0]

            # Alerts by source
            rows = conn.execute(
                "SELECT source, COUNT(*) as cnt FROM alerts GROUP BY source"
            ).fetchall()
            stats["alerts_by_source"] = {
                row["source"]: row["cnt"] for row in rows
            }

            # Alerts by severity
            rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM alerts "
                "GROUP BY severity"
            ).fetchall()
            stats["alerts_by_severity"] = {
                row["severity"]: row["cnt"] for row in rows
            }

            # IoCs by type
            rows = conn.execute(
                "SELECT ioc_type, COUNT(*) as cnt FROM iocs "
                "GROUP BY ioc_type"
            ).fetchall()
            stats["iocs_by_type"] = {
                row["ioc_type"]: row["cnt"] for row in rows
            }

            return stats

    # ====================================================================
    # Timeline Data
    # ====================================================================

    def get_timeline_data(self, limit: int = 500) -> List[Dict]:
        """
        Get alert data formatted for timeline visualisation.

        Returns alerts sorted by timestamp with correlation links.
        """
        with self._connection() as conn:
            alerts = conn.execute(
                """SELECT alert_id, source, severity, message,
                          timestamp, details
                   FROM alerts
                   ORDER BY timestamp ASC LIMIT ?""",
                (limit,),
            ).fetchall()

            correlations = conn.execute(
                """SELECT alert_id_1, alert_id_2, correlation_type, score
                   FROM correlations
                   ORDER BY score DESC"""
            ).fetchall()

            return {
                "events": [self._row_to_dict(a) for a in alerts],
                "links": [self._row_to_dict(c) for c in correlations],
            }

    # ====================================================================
    # Helpers
    # ====================================================================

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict:
        """Convert a sqlite3.Row to a regular dict."""
        d = dict(row)
        # Parse JSON fields
        for key in ("details", "analysis_summary"):
            if key in d and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    def close(self):
        """Explicit close (connections auto-close via context manager)."""
        pass

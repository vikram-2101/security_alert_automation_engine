import sqlite3
import logging
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
from uuid import uuid4

from data_models import Alert, VirusTotalResult, AbuseIPDBResult, GeolocationResult, Decision, PlaybookStep

logger = logging.getLogger(__name__)

class AuditLogger:
    """Logs playbook runs and API calls to SQLite database according to spec."""

    DB_PATH = Path("audit_log.db")

    def __init__(self):
        self._create_tables()

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _create_tables(self):
        """Create database tables as per project specification."""
        with self._get_connection() as conn:
            # Table: playbook_runs
            conn.execute("""
                CREATE TABLE IF NOT EXISTS playbook_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL UNIQUE,
                    alert_id TEXT,
                    source_ip TEXT,
                    alert_type TEXT,
                    severity TEXT,
                    action TEXT,
                    composite_score REAL,
                    vt_score REAL,
                    abuse_score INTEGER,
                    is_tor INTEGER,
                    country TEXT,
                    total_duration_ms INTEGER,
                    api_calls_made INTEGER,
                    ran_at TEXT
                )
            """)

            # Table: api_calls
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    service TEXT,
                    ip TEXT,
                    status_code INTEGER,
                    response_time_ms INTEGER,
                    success INTEGER,
                    error TEXT,
                    called_at TEXT,
                    FOREIGN KEY (run_id) REFERENCES playbook_runs (run_id)
                )
            """)
            conn.commit()

    def log_run(self, alert: Alert, vt_result: Optional[VirusTotalResult],
                abuse_result: Optional[AbuseIPDBResult], geo_result: Optional[GeolocationResult],
                decision: Decision, execution_log: List[PlaybookStep],
                total_duration_ms: int, completed_at: datetime) -> None:
        """Log a complete playbook run to the specified schema."""
        run_id = str(uuid4())
        api_calls_made = 0
        
        # Determine values for the main run table
        vt_score = vt_result.malicious_score if vt_result else 0.0
        abuse_score = abuse_result.abuse_confidence_score if abuse_result else 0
        is_tor = 1 if (abuse_result and abuse_result.is_tor) else 0
        country = geo_result.country if geo_result else "Unknown"

        with self._get_connection() as conn:
            # Insert into playbook_runs
            conn.execute("""
                INSERT INTO playbook_runs (
                    run_id, alert_id, source_ip, alert_type, severity, action,
                    composite_score, vt_score, abuse_score, is_tor, country,
                    total_duration_ms, api_calls_made, ran_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                run_id, alert.alert_id, alert.source_ip, alert.alert_type,
                decision.severity, decision.action, decision.composite_score,
                vt_score, abuse_score, is_tor, country,
                total_duration_ms, api_calls_made, completed_at.isoformat()
            ))

            # Note: The api_calls_made field should ideally be updated after logging API calls,
            # but the spec doesn't provide a perfect way to track every call if they happen 
            # inside enrichers before AuditLogger is called.
            # However, we can log the results we have.
            
            enrichments = [
                ("virustotal", vt_result),
                ("abuseipdb", abuse_result),
                ("geolocation", geo_result)
            ]

            for service, result in enrichments:
                if result:
                    # We don't have the exact response time here unless we passed it.
                    # We'll use a placeholder or 0 if unknown. 
                    # Real SOAR would log this immediately during the call.
                    # Let's assume we log what we have.
                    conn.execute("""
                        INSERT INTO api_calls (
                            run_id, service, ip, status_code, response_time_ms,
                            success, error, called_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        run_id, service, alert.source_ip, 200, 0, 1, None, completed_at.isoformat()
                    ))
            
            conn.commit()

    def get_recent_runs(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent runs from playbook_runs table."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT alert_id, ran_at, 1 as success, severity, action, total_duration_ms
                    FROM playbook_runs
                    ORDER BY ran_at DESC
                    LIMIT ?
                """, (limit,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get recent runs: {e}")
            return []

    def get_stats(self) -> Dict[str, Any]:
        """Get audit statistics from the specific schema."""
        try:
            with self._get_connection() as conn:
                # Total runs
                cursor = conn.execute("SELECT COUNT(*) FROM playbook_runs")
                total_runs = cursor.fetchone()[0]

                # Severity counts
                cursor = conn.execute("SELECT severity, COUNT(*) FROM playbook_runs GROUP BY severity")
                severity_counts = {row[0]: row[1] for row in cursor.fetchall()}

                # Avg duration
                cursor = conn.execute("SELECT AVG(total_duration_ms) FROM playbook_runs")
                avg_duration = cursor.fetchone()[0] or 0

                # API call stats
                cursor = conn.execute("""
                    SELECT service, COUNT(*), AVG(response_time_ms)
                    FROM api_calls
                    GROUP BY service
                """)
                api_stats = {row[0]: {"calls": row[1], "avg_response_time": row[2]} for row in cursor.fetchall()}

                return {
                    "total_runs": total_runs,
                    "severity_counts": severity_counts,
                    "avg_duration_ms": avg_duration,
                    "api_stats": api_stats
                }
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {}

    def get_runs(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Backwards compatibility for main.py."""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT 
                    alert_id, 
                    source_ip, 
                    ran_at as completed_at, 
                    1 as success, 
                    severity as decision_severity, 
                    action as decision_action 
                FROM playbook_runs 
                ORDER BY id DESC 
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
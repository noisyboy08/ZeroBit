"""
Performance metrics and health monitoring for ZeroBit.
Tracks detection rates, model confidence, and system resource usage.
"""

from __future__ import annotations

import psutil
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Tuple
from collections import defaultdict


class MetricsTracker:
    """Tracks system health, detection rates, and model performance."""

    def __init__(self, db_path: Path = Path("data/metrics.db")) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.start_time = time.time()
        self._init_db()

    def _init_db(self) -> None:
        """Initialize metrics database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    metric_type TEXT,
                    metric_name TEXT,
                    value REAL
                )
            """)
            conn.commit()

    def record_alert(self, confidence: float, alert_type: str) -> None:
        """Record a new alert detection."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO metrics (timestamp, metric_type, metric_name, value) VALUES (?, ?, ?, ?)",
                (
                    datetime.now().isoformat(),
                    "alert",
                    alert_type,
                    confidence,
                ),
            )
            conn.commit()

    def record_feedback(self, alert_id: int, is_correct: bool) -> None:
        """Record analyst feedback on alert accuracy."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO metrics (timestamp, metric_type, metric_name, value) VALUES (?, ?, ?, ?)",
                (
                    datetime.now().isoformat(),
                    "feedback",
                    "correct" if is_correct else "false_positive",
                    1.0,
                ),
            )
            conn.commit()

    def get_detection_rate(self, hours: int = 1) -> float:
        """Get alerts per hour in the last N hours."""
        with sqlite3.connect(self.db_path) as conn:
            cutoff = datetime.now() - timedelta(hours=hours)
            result = conn.execute(
                """
                SELECT COUNT(*) FROM metrics 
                WHERE metric_type = 'alert' AND timestamp > ?
                """,
                (cutoff.isoformat(),),
            ).fetchone()
            return (result[0] / hours) if result[0] else 0.0

    def get_false_positive_rate(self, hours: int = 24) -> float:
        """Get false positive rate from feedback."""
        with sqlite3.connect(self.db_path) as conn:
            cutoff = datetime.now() - timedelta(hours=hours)
            total = conn.execute(
                """
                SELECT COUNT(*) FROM metrics 
                WHERE metric_type = 'feedback' AND timestamp > ?
                """,
                (cutoff.isoformat(),),
            ).fetchone()[0]
            
            false_positives = conn.execute(
                """
                SELECT COUNT(*) FROM metrics 
                WHERE metric_type = 'feedback' AND metric_name = 'false_positive' AND timestamp > ?
                """,
                (cutoff.isoformat(),),
            ).fetchone()[0]
            
            return (false_positives / total * 100) if total > 0 else 0.0

    def get_avg_confidence(self, hours: int = 24) -> float:
        """Get average confidence score of recent alerts."""
        with sqlite3.connect(self.db_path) as conn:
            cutoff = datetime.now() - timedelta(hours=hours)
            result = conn.execute(
                """
                SELECT AVG(value) FROM metrics 
                WHERE metric_type = 'alert' AND timestamp > ?
                """,
                (cutoff.isoformat(),),
            ).fetchone()
            avg = result[0] if result[0] else 0.0
            return avg * 100  # Return as percentage

    def get_system_metrics(self) -> Dict[str, float]:
        """Get current system resource usage."""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            disk = psutil.disk_usage("/")
            disk_percent = disk.percent
            
            return {
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "disk_percent": disk_percent,
                "memory_available_gb": memory.available / (1024**3),
            }
        except Exception:
            return {
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "disk_percent": 0.0,
                "memory_available_gb": 0.0,
            }

    def get_uptime(self) -> str:
        """Get system uptime in human-readable format."""
        elapsed = time.time() - self.start_time
        hours, remainder = divmod(int(elapsed), 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"

    def get_health_summary(self) -> Dict[str, any]:
        """Get comprehensive health summary."""
        system = self.get_system_metrics()
        
        return {
            "uptime": self.get_uptime(),
            "detection_rate_per_hour": round(self.get_detection_rate(hours=1), 2),
            "false_positive_rate_percent": round(self.get_false_positive_rate(hours=24), 2),
            "avg_confidence_percent": round(self.get_avg_confidence(hours=24), 2),
            "cpu_percent": round(system["cpu_percent"], 1),
            "memory_percent": round(system["memory_percent"], 1),
            "disk_percent": round(system["disk_percent"], 1),
            "memory_available_gb": round(system["memory_available_gb"], 2),
            "status": "Healthy" if system["cpu_percent"] < 80 and system["memory_percent"] < 85 else "Warning",
        }

    def get_confidence_distribution(self, hours: int = 24) -> Dict[str, int]:
        """Get distribution of confidence scores."""
        with sqlite3.connect(self.db_path) as conn:
            cutoff = datetime.now() - timedelta(hours=hours)
            results = conn.execute(
                """
                SELECT 
                    CASE 
                        WHEN value >= 0.9 THEN '90-100%'
                        WHEN value >= 0.8 THEN '80-89%'
                        WHEN value >= 0.7 THEN '70-79%'
                        WHEN value >= 0.6 THEN '60-69%'
                        ELSE '<60%'
                    END as range,
                    COUNT(*) as count
                FROM metrics 
                WHERE metric_type = 'alert' AND timestamp > ?
                GROUP BY range
                ORDER BY range DESC
                """,
                (cutoff.isoformat(),),
            ).fetchall()
            
            return {range_val: count for range_val, count in results}

"""
Smart SOC Module: Incident Management with Adaptive Learning and Historical Knowledge.
Manages incident logging, feedback collection, and similarity search for past incidents.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd
from sklearn.metrics.pairwise import cosine_similarity  # type: ignore


class IncidentManager:
    """Manages incident history, feedback, and similarity search."""

    def __init__(self, db_path: Path | str = Path("data/soc_history.db")) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _init_database(self) -> None:
        """Initialize SQLite database with incidents table."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT,
                attack_type TEXT,
                feature_vector TEXT,
                threat_score REAL,
                human_label INTEGER,
                analyst_notes TEXT,
                priority TEXT,
                resolved BOOLEAN DEFAULT 0,
                resolved_by TEXT,
                resolved_at TEXT
            )
            """
        )
        conn.commit()
        conn.close()

    def log_incident(
        self,
        features: Dict[str, float] | pd.DataFrame,
        prediction: int,
        threat_score: float,
        ip: str | None = None,
        attack_type: str | None = None,
    ) -> int:
        """
        Log a new incident to the database.
        Returns the incident ID.
        """
        # Convert features to JSON string
        if isinstance(features, pd.DataFrame):
            feature_dict = features.iloc[0].to_dict()
        else:
            feature_dict = features

        feature_json = json.dumps(feature_dict)
        priority = self.calculate_priority(threat_score)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO incidents 
            (timestamp, ip, attack_type, feature_vector, threat_score, human_label, priority)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().isoformat(),
                ip or "Unknown",
                attack_type or "Unknown",
                feature_json,
                threat_score,
                None,  # human_label - will be set by feedback
                priority,
            ),
        )
        incident_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return incident_id

    def add_feedback(
        self,
        incident_id: int,
        is_true_positive: bool,
        notes: str = "",
    ) -> bool:
        """
        Add human feedback to an incident.
        is_true_positive: True if confirmed attack, False if false positive.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE incidents 
            SET human_label = ?, analyst_notes = ?
            WHERE id = ?
            """,
            (1 if is_true_positive else 0, notes, incident_id),
        )
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success

    def get_similar_incidents(
        self, current_features: Dict[str, float] | pd.DataFrame, top_k: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Find top K most similar past incidents using cosine similarity.
        Returns list of incident dictionaries with similarity scores.
        """
        # Convert current features to vector
        if isinstance(current_features, pd.DataFrame):
            current_vec = current_features.iloc[0].values.reshape(1, -1)
        else:
            current_vec = np.array([list(current_features.values())]).reshape(1, -1)

        # Load all past incidents with feedback
        conn = sqlite3.connect(self.db_path)
        df = pd.read_sql_query(
            """
            SELECT id, timestamp, ip, attack_type, feature_vector, 
                   threat_score, human_label, analyst_notes, priority,
                   resolved, resolved_by, resolved_at
            FROM incidents
            WHERE feature_vector IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT 1000
            """,
            conn,
        )
        conn.close()

        if df.empty:
            return []

        # Calculate similarities
        similarities = []
        for idx, row in df.iterrows():
            try:
                past_features = json.loads(row["feature_vector"])
                past_vec = np.array([list(past_features.values())]).reshape(1, -1)

                # Ensure same dimensions
                min_len = min(current_vec.shape[1], past_vec.shape[1])
                if min_len == 0:
                    continue

                curr_trimmed = current_vec[:, :min_len]
                past_trimmed = past_vec[:, :min_len]

                similarity = cosine_similarity(curr_trimmed, past_trimmed)[0][0]
                similarities.append(
                    {
                        "id": int(row["id"]),
                        "timestamp": row["timestamp"],
                        "ip": row["ip"],
                        "attack_type": row["attack_type"],
                        "threat_score": float(row["threat_score"]),
                        "human_label": row["human_label"],
                        "analyst_notes": row["analyst_notes"] or "",
                        "priority": row["priority"],
                        "resolved": bool(row["resolved"]),
                        "resolved_by": row["resolved_by"] or "",
                        "resolved_at": row["resolved_at"] or "",
                        "similarity": float(similarity),
                    }
                )
            except Exception:
                continue

        # Sort by similarity and return top K
        similarities.sort(key=lambda x: x["similarity"], reverse=True)
        return similarities[:top_k]

    def calculate_priority(self, threat_score: float, asset_value: float = 1.0) -> str:
        """
        Calculate priority label based on threat score.
        Returns: P0-Critical, P1-High, P2-Medium, P3-Low
        """
        adjusted_score = threat_score * asset_value

        if adjusted_score > 90:
            return "P0-Critical"
        elif adjusted_score > 70:
            return "P1-High"
        elif adjusted_score > 40:
            return "P2-Medium"
        else:
            return "P3-Low"

    def get_incident(self, incident_id: int) -> Dict[str, Any] | None:
        """Retrieve a specific incident by ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, ip, attack_type, feature_vector, 
                   threat_score, human_label, analyst_notes, priority,
                   resolved, resolved_by, resolved_at
            FROM incidents
            WHERE id = ?
            """,
            (incident_id,),
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return {
            "id": row[0],
            "timestamp": row[1],
            "ip": row[2],
            "attack_type": row[3],
            "feature_vector": row[4],
            "threat_score": row[5],
            "human_label": row[6],
            "analyst_notes": row[7],
            "priority": row[8],
            "resolved": bool(row[9]),
            "resolved_by": row[10] or "",
            "resolved_at": row[11] or "",
        }

    def get_feedback_data(self) -> pd.DataFrame:
        """Get all incidents with human feedback for retraining."""
        conn = sqlite3.connect(self.db_path)
        df = pd.read_sql_query(
            """
            SELECT feature_vector, human_label
            FROM incidents
            WHERE human_label IS NOT NULL
            """,
            conn,
        )
        conn.close()
        return df


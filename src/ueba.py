"""
User & Entity Behavior Analytics (UEBA) profiler.
Maintains per-IP traffic history and flags statistical anomalies.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import numpy as np
import pandas as pd


class BehaviorProfiler:
    def __init__(self, store_path: Path | str = Path("data/ueba_history.json")) -> None:
        self.store_path = Path(store_path)
        self.store_path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> List[Dict[str, str]]:
        if not self.store_path.exists():
            return []
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _save(self, records: List[Dict[str, str]]) -> None:
        self.store_path.write_text(json.dumps(records, indent=2), encoding="utf-8")

    def _prune(self, records: List[Dict[str, str]]) -> List[Dict[str, str]]:
        cutoff = datetime.utcnow() - timedelta(hours=24)
        kept: List[Dict[str, str]] = []
        for r in records:
            try:
                ts = datetime.fromisoformat(r["timestamp"].replace("Z", ""))
                if ts >= cutoff:
                    kept.append(r)
            except Exception:
                continue
        return kept

    def update_profile(self, ip: str, bytes_sent: float, bytes_received: float = 0.0) -> None:
        records = self._load()
        record = {
            "ip": ip,
            "bytes": float(bytes_sent + bytes_received),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        records.append(record)
        records = self._prune(records)
        self._save(records)

    def calculate_baseline(self, ip: str) -> Tuple[Optional[float], Optional[float]]:
        records = self._load()
        vals = [r["bytes"] for r in records if r.get("ip") == ip]
        if not vals:
            return None, None
        arr = np.array(vals, dtype=float)
        return float(arr.mean()), float(arr.std())

    def is_anomalous(self, ip: str, current_bytes: float) -> bool:
        mean, std = self.calculate_baseline(ip)
        if mean is None or std is None:
            return False
        threshold = mean + 3 * std
        return current_bytes > threshold

    def history_df(self) -> pd.DataFrame:
        data = self._load()
        if not data:
            return pd.DataFrame(columns=["timestamp", "ip", "bytes"])
        return pd.DataFrame(data)


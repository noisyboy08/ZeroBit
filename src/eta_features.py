"""
Feature extraction for Encrypted Traffic Analysis (ETA) using Joy JSON outputs.
Focuses on flow-level metadata (sizes, timings, JA3) without decrypting payloads.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import numpy as np
import pandas as pd


def _safe_stats(values: Iterable[float]) -> Dict[str, float]:
    """Compute basic statistics with safe defaults for empty sequences."""
    arr = np.array(list(values), dtype=float)
    if arr.size == 0:
        return {
            "count": 0.0,
            "min": 0.0,
            "max": 0.0,
            "mean": 0.0,
            "std": 0.0,
            "median": 0.0,
        }
    return {
        "count": float(arr.size),
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "mean": float(np.mean(arr)),
        "std": float(np.std(arr)),
        "median": float(np.median(arr)),
    }


def _inter_arrivals(times: Iterable[float]) -> List[float]:
    """Compute inter-arrival times from a sequence of timestamps."""
    ts = list(times)
    if len(ts) < 2:
        return []
    return [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]


def _hash_fingerprint(fp: str | None) -> float:
    """Convert a JA3/JA3S fingerprint string into a stable numeric bucket."""
    if not fp:
        return 0.0
    # Stable hash: Python's hash is salted; use a simple deterministic hash.
    h = 0
    for ch in fp:
        h = (h * 31 + ord(ch)) % 1_000_000_007
    return float(h)


def flow_to_features(flow: Dict[str, Any]) -> Dict[str, float]:
    """
    Convert a Joy flow dictionary into numeric features.
    Expected keys (best effort): lengths, times, tls -> ja3/ja3s.
    """
    lengths = flow.get("lengths") or flow.get("packets") or []
    times = flow.get("times") or flow.get("timestamps") or []
    size_stats = _safe_stats(lengths)
    iats = _inter_arrivals(times)
    iat_stats = _safe_stats(iats)

    tls = flow.get("tls", {}) or {}
    ja3 = tls.get("ja3") or flow.get("ja3")
    ja3s = tls.get("ja3s") or flow.get("ja3s")

    features = {
        "size_count": size_stats["count"],
        "size_min": size_stats["min"],
        "size_max": size_stats["max"],
        "size_mean": size_stats["mean"],
        "size_std": size_stats["std"],
        "size_median": size_stats["median"],
        "iat_count": iat_stats["count"],
        "iat_mean": iat_stats["mean"],
        "iat_std": iat_stats["std"],
        "iat_max": iat_stats["max"],
        "iat_median": iat_stats["median"],
        "ja3_hash": _hash_fingerprint(ja3),
        "ja3s_hash": _hash_fingerprint(ja3s),
        "ja3_present": 1.0 if ja3 else 0.0,
        "ja3s_present": 1.0 if ja3s else 0.0,
    }
    return features


def load_joy_json(json_path: Path) -> List[Dict[str, Any]]:
    """Load Joy JSON output. Supports list of flows or dict with 'flows' key."""
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "flows" in data and isinstance(data["flows"], list):
            return data["flows"]
    raise ValueError("Unexpected Joy JSON structure: expected list or dict with 'flows'.")


def build_eta_frame(json_path: Path) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Build ETA feature frame (X, y) from Joy JSON exports.
    Expects each flow to carry a 'label' field for supervision.
    """
    flows = load_joy_json(json_path)
    records: List[Dict[str, float]] = []
    labels: List[Any] = []
    for flow in flows:
        if "label" not in flow:
            raise ValueError("Each flow must include a 'label' field for ETA training.")
        records.append(flow_to_features(flow))
        labels.append(flow["label"])
    X = pd.DataFrame.from_records(records)
    y = pd.Series(labels, name="label")
    return X, y


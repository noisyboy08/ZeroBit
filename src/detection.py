"""
Detection utilities for ZeroBit.
Wire feature extraction to your trained model.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
from datetime import datetime
import csv

import joblib  # type: ignore
import numpy as np
import pandas as pd
from scapy.all import IP  # type: ignore

from .alerts import send_telegram_alert
from .explainability import TrafficExplainer
from .enrichment import get_ip_details
from .ueba import BehaviorProfiler


def load_model(model_path: Path) -> Any:
    """Load a persisted scikit-learn model."""
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")
    return joblib.load(model_path)


def extract_features(packet: Any) -> Dict[str, float]:
    """
    Convert a Scapy packet into a feature dict.
    Replace this stub with real parsing logic (e.g., lengths, flags, TTL).
    """
    return {
        "packet_length": float(len(packet)),
    }


def predict(packet: Any, model: Any) -> Any:
    """Run inference on a single packet."""
    features = extract_features(packet)
    X = np.array([list(features.values())])
    return model.predict(X)[0]


# Initialize explainability and output directory
ALERT_DIR = Path("static/alerts")
ALERT_DIR.mkdir(parents=True, exist_ok=True)
ALERT_LOG = Path("data/alerts.csv")
ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
explainer = TrafficExplainer()
profiler = BehaviorProfiler()

# Telegram alerting configuration (replace with real values)
TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"


def _append_alert_log(row: Dict[str, Any]) -> None:
    """Append alert details to CSV log with headers."""
    headers = ["timestamp", "src_ip", "country", "city", "lat", "lon", "isp", "confidence", "reason"]
    exists = ALERT_LOG.exists()
    with ALERT_LOG.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def predict_with_explanation(packet: Any, model: Any) -> Any:
    """
    Run inference and, on malicious predictions, emit SHAP-based reasoning and plot.
    """
    features = extract_features(packet)
    df = pd.DataFrame([features])
    pred = model.predict(df)[0]

    src_ip = None
    if IP in packet:
        src_ip = packet[IP].src
    current_bytes = float(len(packet))
    profiler.update_profile(src_ip or "Unknown", bytes_sent=current_bytes, bytes_received=0.0)
    anomaly = profiler.is_anomalous(src_ip or "Unknown", current_bytes)

    is_alert = pred == 1 or anomaly
    reason = None

    if pred == 1:
        reason = explainer.generate_explanation(df)
        print(f"\033[91m{reason}\033[0m")
        explainer.save_plot(df, datetime.utcnow().strftime("%Y%m%d_%H%M%S%f"), output_dir=str(ALERT_DIR))
    elif anomaly:
        reason = "🚨 UEBA Alert: Abnormal Data Spike Detected."
        print(f"\033[91m{reason}\033[0m")

    if is_alert:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S%f")
        details = get_ip_details(src_ip) if src_ip else {
            "country": "Unknown",
            "city": "Unknown",
            "lat": None,
            "lon": None,
            "isp": "Unknown",
        }
        confidence = None
        if hasattr(model, "predict_proba"):
            try:
                confidence = float(model.predict_proba(df)[0][1])
            except Exception:
                confidence = None
        _append_alert_log(
            {
                "timestamp": ts,
                "src_ip": src_ip or "Unknown",
                "country": details.get("country", "Unknown"),
                "city": details.get("city", "Unknown"),
                "lat": details.get("lat", None),
                "lon": details.get("lon", None),
                "isp": details.get("isp", "Unknown"),
                "confidence": confidence,
                "reason": reason or "Alert",
            }
        )
        alert_msg = (
            "🚨 **ZeroBit Alert** 🚨\n\n"
            f"IP: {src_ip or 'Unknown'}\n"
            f"Reason: {reason or 'Alert triggered'}"
        )
        if TELEGRAM_BOT_TOKEN != "YOUR_TELEGRAM_BOT_TOKEN" and TELEGRAM_CHAT_ID != "YOUR_TELEGRAM_CHAT_ID":
            send_telegram_alert(alert_msg, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)
    return pred


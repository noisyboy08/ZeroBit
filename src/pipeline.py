"""
Real-Time Packet Processing Pipeline for ZeroBit.
Connects packet capture, feature extraction, model inference, and alert storage.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from queue import Queue
from typing import Any

from scapy.all import sniff  # type: ignore

from .detection import extract_features, load_model, predict


# Global queue for decoupling packet capture from processing
packet_queue: Queue = Queue(maxsize=1000)

# Global model instance (Singleton pattern)
_model_instance: Any = None
_model_path: Path | None = None


def init_db(db_path: Path = Path("data/alerts.db")) -> None:
    """Initialize SQLite database for storing alerts."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            attack_type TEXT,
            confidence REAL,
            is_read INTEGER DEFAULT 0,
            feature_vector TEXT
        )
        """
    )
    conn.commit()
    conn.close()
    print(f"[Pipeline] Database initialized at {db_path}")


def get_model(model_path: Path | str = Path("models/eta_model.pkl")) -> Any:
    """Get or load the model instance (Singleton pattern)."""
    global _model_instance, _model_path
    model_path_obj = Path(model_path)
    
    if _model_instance is None or _model_path != model_path_obj:
        print(f"[Pipeline] Loading model from {model_path_obj}")
        _model_instance = load_model(model_path_obj)
        _model_path = model_path_obj
        print("[Pipeline] Model loaded successfully")
    
    return _model_instance


def packet_handler(packet: Any) -> None:
    """Callback for Scapy sniff - puts packets into queue."""
    try:
        if not packet_queue.full():
            packet_queue.put(packet, block=False)
        else:
            print("[Pipeline] Warning: Packet queue full, dropping packet")
    except Exception as exc:
        print(f"[Pipeline] Error queuing packet: {exc}")


def start_sniffing(iface: str | None = None, count: int | None = None) -> None:
    """Start packet sniffing in a daemon thread."""
    def sniff_worker() -> None:
        try:
            print(f"[Pipeline] Starting packet capture on interface: {iface or 'default'}")
            sniff(
                iface=iface,
                prn=packet_handler,
                store=0,
                count=count,
            )
        except Exception as exc:
            print(f"[Pipeline] Sniffing error: {exc}")

    thread = threading.Thread(target=sniff_worker, daemon=True)
    thread.start()
    print("[Pipeline] Sniffer thread started")


def process_packets(
    model_path: Path | str = Path("models/eta_model.pkl"),
    db_path: Path = Path("data/alerts.db"),
) -> None:
    """Process packets from queue: extract features, run model, store alerts."""
    model = get_model(model_path)
    print("[Pipeline] Processor thread started")

    while True:
        try:
            # Get packet from queue (blocking with timeout)
            try:
                packet = packet_queue.get(timeout=1.0)
            except Exception:
                continue  # Timeout, check again

            # Extract features
            try:
                features = extract_features(packet)
            except Exception as exc:
                print(f"[Pipeline] Feature extraction failed: {exc}")
                continue

            # Run model prediction
            try:
                prediction = predict(packet, model)
            except Exception as exc:
                print(f"[Pipeline] Prediction failed: {exc}")
                continue

            # If malicious (prediction == 1), store alert
            if prediction == 1:
                # Extract IP addresses
                src_ip = "Unknown"
                dst_ip = "Unknown"
                try:
                    if hasattr(packet, "src"):
                        src_ip = packet.src
                    if hasattr(packet, "dst"):
                        dst_ip = packet.dst
                    # Try IP layer
                    if hasattr(packet, "payload") and hasattr(packet.payload, "src"):
                        src_ip = packet.payload.src
                    if hasattr(packet, "payload") and hasattr(packet.payload, "dst"):
                        dst_ip = packet.payload.dst
                except Exception:
                    pass

                # Get confidence if available
                confidence = None
                try:
                    if hasattr(model, "predict_proba"):
                        import numpy as np
                        import pandas as pd
                        feature_df = pd.DataFrame([features])
                        proba = model.predict_proba(feature_df)[0]
                        confidence = float(proba[1])  # Probability of malicious class
                except Exception:
                    pass

                # Store in database
                try:
                    conn = sqlite3.connect(db_path)
                    cursor = conn.cursor()
                    import json
                    cursor.execute(
                        """
                        INSERT INTO alerts (timestamp, src_ip, dst_ip, attack_type, confidence, feature_vector)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            time.strftime("%Y-%m-%d %H:%M:%S"),
                            src_ip,
                            dst_ip,
                            "Malicious",
                            confidence,
                            json.dumps(features),
                        ),
                    )
                    conn.commit()
                    conn.close()

                    print(f"🚨 Attack Detected from {src_ip} to {dst_ip}! (Confidence: {confidence:.2%})" if confidence else f"🚨 Attack Detected from {src_ip} to {dst_ip}!")
                except Exception as exc:
                    print(f"[Pipeline] Database write failed: {exc}")

        except KeyboardInterrupt:
            print("[Pipeline] Processor thread interrupted")
            break
        except Exception as exc:
            print(f"[Pipeline] Processing error: {exc}")
            time.sleep(0.1)  # Brief pause on error


def start_pipeline(
    model_path: Path | str = Path("models/eta_model.pkl"),
    iface: str | None = None,
    count: int | None = None,
) -> None:
    """Start the complete pipeline: initialize DB, start sniffing and processing threads."""
    print("[Pipeline] Starting ZeroBit Real-Time Processing Pipeline...")
    
    # Initialize database
    init_db()
    
    # Start sniffer thread
    start_sniffing(iface=iface, count=count)
    
    # Start processor thread (main thread)
    process_packets(model_path=model_path)


def main() -> None:
    """Main entry point for the pipeline."""
    import argparse
    
    parser = argparse.ArgumentParser(description="ZeroBit Real-Time Packet Processing Pipeline")
    parser.add_argument("--model-path", type=Path, default=Path("models/eta_model.pkl"), help="Path to trained model")
    parser.add_argument("--iface", type=str, default=None, help="Network interface to sniff on")
    parser.add_argument("--count", type=int, default=None, help="Number of packets to capture (None = infinite)")
    
    args = parser.parse_args()
    
    try:
        start_pipeline(
            model_path=args.model_path,
            iface=args.iface,
            count=args.count,
        )
    except KeyboardInterrupt:
        print("\n[Pipeline] Shutting down...")


if __name__ == "__main__":
    main()


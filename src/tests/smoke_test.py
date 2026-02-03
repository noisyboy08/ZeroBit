"""Smoke tests to verify core ZeroBit modules load and basic behavior."""
from pathlib import Path
import os
import sys

# allow imports from project root
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

print("Root:", ROOT)

from src.metrics import MetricsTracker
from src.logger import get_logger, log_alert, log_info
from src.config import get_config
from src.email_alerter import EmailAlerter


def run():
    print("Starting smoke tests...")

    # Config
    cfg = get_config()
    print("Config loaded. email_enabled:", cfg.get("email_enabled"))
    valid = cfg.validate()
    print("Config validation result:", valid)

    # Logger
    logger = get_logger()
    logger.log_info("Smoke test: logger initialized")
    print("Logger initialised.")

    # Metrics
    tracker = MetricsTracker()
    print("Metrics DB:", tracker.db_path)
    tracker.record_alert(confidence=0.85, alert_type="smoke_test")
    detection_rate = tracker.get_detection_rate(hours=1)
    avg_conf = tracker.get_avg_confidence(hours=24)
    fp_rate = tracker.get_false_positive_rate(hours=24)
    print(f"Detection rate (1h): {detection_rate}")
    print(f"Average confidence (24h): {avg_conf}%")
    print(f"False positive rate (24h): {fp_rate}%")

    # Email alerter (should not send without config)
    alerter = EmailAlerter()
    sent = alerter.send_alert(
        recipient_email="test@example.com",
        alert_type="smoke_test",
        source_ip="127.0.0.1",
        dest_ip="127.0.0.1",
        dest_port=9999,
        confidence=0.9,
        threat_details="Test"
    )
    print("Email send attempted (should be False unless configured):", sent)

    print("Smoke tests completed.")


if __name__ == '__main__':
    run()

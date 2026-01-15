"""
Telegram alerting for ZeroBit.
Sends messages via the Telegram Bot API with basic error handling.
"""

from __future__ import annotations

import requests


def send_telegram_alert(message: str, bot_token: str, chat_id: str) -> None:
    """
    Send a Telegram message. Fails quietly to avoid crashing detection.
    """
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}
    try:
        requests.post(url, data=payload, timeout=5)
    except Exception:
        # Intentionally swallow errors (offline/no internet) to keep detector running.
        return


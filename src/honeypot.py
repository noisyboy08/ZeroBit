"""
Simple TCP honeypot for active deception.
Listens on a port, presents a fake banner, and logs attacker payloads.
"""

from __future__ import annotations

import json
import socket
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict

LOG_PATH = Path("data/honeypot_logs.json")
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def _append_log(entry: Dict[str, str]) -> None:
    """Append an entry to the honeypot log file."""
    if LOG_PATH.exists():
        try:
            data: List[Dict[str, str]] = json.loads(LOG_PATH.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                data = []
        except Exception:
            data = []
    else:
        data = []
    data.append(entry)
    LOG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _serve(port: int, banner: str) -> None:
    """Blocking server loop to accept and log attacker input."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen()
        while True:
            conn, addr = s.accept()
            with conn:
                try:
                    conn.sendall((banner + "\r\n").encode())
                except Exception:
                    pass
                payload = b""
                try:
                    conn.settimeout(5)
                    payload = conn.recv(4096)
                except Exception:
                    payload = b""
                entry = {
                    "attacker_ip": addr[0],
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "payload": payload.decode(errors="replace"),
                }
                _append_log(entry)


def start_honeypot(
    port: int = 2222,
    banner: str = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
) -> threading.Thread:
    """
    Start the honeypot server in a daemon thread.
    """
    thread = threading.Thread(target=_serve, args=(port, banner), daemon=True)
    thread.start()
    return thread


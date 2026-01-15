"""
ZeroBit Canary - Ransomware Kill Switch Module.
Monitors bait files (canaries) and triggers immediate network isolation on ransomware detection.
"""

from __future__ import annotations

import os
import platform
import subprocess
import threading
import time
from pathlib import Path
from typing import List

from watchdog.events import FileSystemEventHandler  # type: ignore
from watchdog.observers import Observer  # type: ignore

try:
    import psutil  # type: ignore
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class CanaryEventHandler(FileSystemEventHandler):
    """Handles file system events for canary files."""

    def __init__(self, canary_monitor) -> None:
        super().__init__()
        self.canary_monitor = canary_monitor
        self.last_triggered = 0
        self.cooldown = 5  # Prevent multiple triggers within 5 seconds

    def on_modified(self, event) -> None:
        """Triggered when a canary file is modified (encrypted by ransomware)."""
        if event.is_directory:
            return

        # Cooldown check
        current_time = time.time()
        if current_time - self.last_triggered < self.cooldown:
            return

        file_path = Path(event.src_path)
        if file_path.name.startswith(("_", "$")) or "canary" in file_path.name.lower():
            self.last_triggered = current_time
            self.canary_monitor.trigger_alert(file_path)

    def on_created(self, event) -> None:
        """Triggered when a new file is created (backup canary detection)."""
        if event.is_directory:
            return
        file_path = Path(event.src_path)
        # Check for suspicious file extensions (encrypted files)
        suspicious_extensions = [".encrypted", ".locked", ".crypto", ".vault", ".ecc"]
        if any(file_path.suffix.lower() == ext for ext in suspicious_extensions):
            self.canary_monitor.trigger_alert(file_path, reason="Suspicious encrypted file created")


class CanaryMonitor:
    """Monitors bait files and triggers ransomware kill switch."""

    def __init__(self) -> None:
        self.observer: Observer | None = None
        self.monitored_directories: List[Path] = []
        self.canary_files: List[Path] = []
        self.is_active = False
        self.alert_triggered = False
        self.last_alert_time: float = 0
        self.alert_file: Path | None = None

    def setup_traps(self, directory: str | Path) -> List[Path]:
        """
        Create bait files (canaries) in the target directory.
        Returns list of created canary file paths.
        """
        target_dir = Path(directory)
        target_dir.mkdir(parents=True, exist_ok=True)

        # Bait file names that ransomware typically targets first
        bait_files = [
            "_00_confidential.docx",
            "_aa_passwords.xlsx",
            "_backup_important.txt",
            "$canary_secrets.pdf",
            "_financial_data.xlsx",
            "_personal_info.doc",
            "$admin_credentials.txt",
            "_database_backup.sql",
        ]

        created_files = []
        for filename in bait_files:
            file_path = target_dir / filename
            if not file_path.exists():
                # Create file with some content (ransomware targets non-empty files)
                file_path.write_text(
                    f"ZeroBit Canary File - DO NOT MODIFY\n"
                    f"Created: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"This is a monitoring file. Any modification will trigger security alerts."
                )
            created_files.append(file_path)

        self.canary_files.extend(created_files)
        return created_files

    def start_monitoring(self, directory: str | Path) -> bool:
        """
        Start monitoring a directory for canary file modifications.
        Returns True if monitoring started successfully.
        """
        target_dir = Path(directory)
        if not target_dir.exists():
            return False

        if self.observer is None:
            self.observer = Observer()
            event_handler = CanaryEventHandler(self)
            self.observer.schedule(event_handler, str(target_dir), recursive=True)
            self.observer.start()
            self.is_active = True
            self.monitored_directories.append(target_dir)
            return True
        else:
            # Add additional directory to existing observer
            event_handler = CanaryEventHandler(self)
            self.observer.schedule(event_handler, str(target_dir), recursive=True)
            self.monitored_directories.append(target_dir)
            return True

    def stop_monitoring(self) -> None:
        """Stop all monitoring."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        self.is_active = False

    def trigger_alert(self, file_path: Path, reason: str = "Canary file modified") -> None:
        """
        Trigger ransomware alert and execute kill switch.
        """
        current_time = time.time()
        # Prevent duplicate alerts within short time window
        if current_time - self.last_alert_time < 2:
            return

        self.alert_triggered = True
        self.last_alert_time = current_time
        self.alert_file = file_path

        print(f"[CANARY ALERT] {reason}: {file_path}")
        print("[CANARY ALERT] CRITICAL RANSOMWARE DETECTED - ACTIVATING KILL SWITCH")

        # Import here to avoid circular dependency
        from .response import ResponseEngine

        response = ResponseEngine()

        # Isolate machine from network
        isolation_result = response.isolate_machine()
        print(f"[CANARY ALERT] Network isolation: {isolation_result}")

        # Try to identify and kill the process (optional)
        if PSUTIL_AVAILABLE:
            self._attempt_process_kill(file_path)

        # Log the alert
        self._log_alert(file_path, reason)

    def _attempt_process_kill(self, file_path: Path) -> None:
        """Attempt to identify and kill the process accessing the canary file."""
        if not PSUTIL_AVAILABLE:
            return

        try:
            # Find processes with open file handles
            for proc in psutil.process_iter(["pid", "name", "open_files"]):
                try:
                    if proc.info["open_files"]:
                        for open_file in proc.info["open_files"]:
                            if str(file_path) in str(open_file.path):
                                print(f"[CANARY] Attempting to terminate process: {proc.info['name']} (PID: {proc.info['pid']})")
                                proc.terminate()
                                time.sleep(0.5)
                                if proc.is_running():
                                    proc.kill()
                                return
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as exc:
            print(f"[CANARY] Process kill attempt failed: {exc}")

    def _log_alert(self, file_path: Path, reason: str) -> None:
        """Log the ransomware alert to a file."""
        log_file = Path("data/canary_alerts.log")
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as f:
            f.write(
                f"{time.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"ALERT: {reason} | File: {file_path} | Network: ISOLATED\n"
            )

    def get_status(self) -> dict:
        """Get current canary monitoring status."""
        return {
            "is_active": self.is_active,
            "alert_triggered": self.alert_triggered,
            "monitored_directories": [str(d) for d in self.monitored_directories],
            "canary_files_count": len(self.canary_files),
            "last_alert_file": str(self.alert_file) if self.alert_file else None,
            "last_alert_time": self.last_alert_time,
        }

    def reset_alert(self) -> None:
        """Reset alert status (for testing/recovery)."""
        self.alert_triggered = False
        self.alert_file = None


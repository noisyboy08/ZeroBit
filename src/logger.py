"""
Structured logging and error handling for ZeroBit.
Provides JSON-formatted logs with full context for debugging and auditing.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
import traceback
import sys


class JSONFormatter(logging.Formatter):
    """Format logs as JSON for better parsing and analysis."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        if hasattr(record, "extra_data"):
            log_obj["context"] = record.extra_data

        return json.dumps(log_obj)


class ZeroBitLogger:
    """Centralized logging for ZeroBit with JSON format and rotation."""

    def __init__(self, log_dir: Path = Path("logs")) -> None:
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._setup_loggers()

    def _setup_loggers(self) -> None:
        """Configure rotating file handlers and console logging."""
        # Main logger
        self.main_logger = logging.getLogger("zerobit.main")
        self.main_logger.setLevel(logging.DEBUG)

        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "zerobit.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=10,
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JSONFormatter())

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            "[%(levelname)s] %(asctime)s - %(name)s: %(message)s"
        )
        console_handler.setFormatter(console_formatter)

        self.main_logger.addHandler(file_handler)
        self.main_logger.addHandler(console_handler)

        # Security-specific logger
        self.security_logger = logging.getLogger("zerobit.security")
        self.security_logger.setLevel(logging.DEBUG)

        security_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "security_events.log",
            maxBytes=50 * 1024 * 1024,  # 50MB
            backupCount=20,
        )
        security_handler.setLevel(logging.DEBUG)
        security_handler.setFormatter(JSONFormatter())
        self.security_logger.addHandler(security_handler)

    def log_alert(
        self,
        alert_type: str,
        source_ip: str,
        dest_ip: str,
        confidence: float,
        **extra_data: Any,
    ) -> None:
        """Log a security alert with full context."""
        self.security_logger.info(
            f"ALERT: {alert_type} from {source_ip} to {dest_ip} (confidence: {confidence:.2%})",
            extra={"extra_data": extra_data},
        )

    def log_error(
        self,
        error: Exception,
        context: str = "",
        **extra_data: Any,
    ) -> None:
        """Log an error with full traceback and context."""
        self.main_logger.error(
            f"Error in {context}: {str(error)}\n{traceback.format_exc()}",
            extra={"extra_data": extra_data},
        )

    def log_info(self, message: str, **extra_data: Any) -> None:
        """Log info message."""
        self.main_logger.info(
            message,
            extra={"extra_data": extra_data} if extra_data else {},
        )

    def log_debug(self, message: str, **extra_data: Any) -> None:
        """Log debug message."""
        self.main_logger.debug(
            message,
            extra={"extra_data": extra_data} if extra_data else {},
        )

    def log_warning(self, message: str, **extra_data: Any) -> None:
        """Log warning message."""
        self.main_logger.warning(
            message,
            extra={"extra_data": extra_data} if extra_data else {},
        )


# Global logger instance
_logger: Optional[ZeroBitLogger] = None


def get_logger() -> ZeroBitLogger:
    """Get or create the global logger instance."""
    global _logger
    if _logger is None:
        _logger = ZeroBitLogger()
    return _logger


def log_alert(
    alert_type: str,
    source_ip: str,
    dest_ip: str,
    confidence: float,
    **extra_data: Any,
) -> None:
    """Convenience function to log alerts."""
    get_logger().log_alert(alert_type, source_ip, dest_ip, confidence, **extra_data)


def log_error(
    error: Exception,
    context: str = "",
    **extra_data: Any,
) -> None:
    """Convenience function to log errors."""
    get_logger().log_error(error, context, **extra_data)


def log_info(message: str, **extra_data: Any) -> None:
    """Convenience function to log info."""
    get_logger().log_info(message, **extra_data)

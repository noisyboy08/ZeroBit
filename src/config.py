"""
Configuration management for ZeroBit.
Handles environment variables, config files, and default settings.
"""

from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, asdict


@dataclass
class ZeroBitConfig:
    """ZeroBit configuration settings."""

    # Detection settings
    detection_enabled: bool = True
    confidence_threshold: float = 0.6
    model_path: str = "models/eta_model.pkl"
    
    # Alert settings
    max_alerts_per_hour: int = 1000
    auto_block_enabled: bool = False
    
    # Email alerting
    email_enabled: bool = False
    email_recipients: list = None
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    
    # Honeypot settings
    honeypot_enabled: bool = False
    honeypot_ports: list = None
    
    # API settings
    api_enabled: bool = False
    api_port: int = 8000
    
    # Logging settings
    log_level: str = "INFO"
    log_dir: str = "logs"
    
    # Data settings
    data_dir: str = "data"
    
    def __post_init__(self) -> None:
        """Set defaults for list fields."""
        if self.email_recipients is None:
            self.email_recipients = []
        if self.honeypot_ports is None:
            self.honeypot_ports = [22, 23, 3389]

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return asdict(self)

    def to_json(self, path: Path) -> None:
        """Save config to JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @staticmethod
    def from_json(path: Path) -> ZeroBitConfig:
        """Load config from JSON file."""
        with open(path, "r") as f:
            data = json.load(f)
        return ZeroBitConfig(**data)

    @staticmethod
    def from_env() -> ZeroBitConfig:
        """Load config from environment variables."""
        return ZeroBitConfig(
            detection_enabled=os.getenv("ZEROBIT_DETECTION_ENABLED", "true").lower() == "true",
            confidence_threshold=float(os.getenv("ZEROBIT_CONFIDENCE_THRESHOLD", "0.6")),
            model_path=os.getenv("ZEROBIT_MODEL_PATH", "models/eta_model.pkl"),
            max_alerts_per_hour=int(os.getenv("ZEROBIT_MAX_ALERTS_PER_HOUR", "1000")),
            auto_block_enabled=os.getenv("ZEROBIT_AUTO_BLOCK_ENABLED", "false").lower() == "true",
            email_enabled=os.getenv("ZEROBIT_EMAIL_ENABLED", "false").lower() == "true",
            email_recipients=os.getenv("ZEROBIT_EMAIL_RECIPIENTS", "").split(","),
            smtp_server=os.getenv("ZEROBIT_SMTP_SERVER", "smtp.gmail.com"),
            smtp_port=int(os.getenv("ZEROBIT_SMTP_PORT", "587")),
            honeypot_enabled=os.getenv("ZEROBIT_HONEYPOT_ENABLED", "false").lower() == "true",
            honeypot_ports=list(map(int, os.getenv("ZEROBIT_HONEYPOT_PORTS", "22,23,3389").split(","))),
            api_enabled=os.getenv("ZEROBIT_API_ENABLED", "false").lower() == "true",
            api_port=int(os.getenv("ZEROBIT_API_PORT", "8000")),
            log_level=os.getenv("ZEROBIT_LOG_LEVEL", "INFO"),
            log_dir=os.getenv("ZEROBIT_LOG_DIR", "logs"),
            data_dir=os.getenv("ZEROBIT_DATA_DIR", "data"),
        )


class ConfigManager:
    """Manages ZeroBit configuration."""

    def __init__(self, config_path: Optional[Path] = None) -> None:
        """
        Initialize config manager.
        
        Priority:
        1. config_path parameter
        2. ZEROBIT_CONFIG env variable
        3. config.json in project root
        4. Environment variables
        5. Defaults
        """
        if config_path and config_path.exists():
            self.config = ZeroBitConfig.from_json(config_path)
        elif (env_config := os.getenv("ZEROBIT_CONFIG")) and Path(env_config).exists():
            self.config = ZeroBitConfig.from_json(Path(env_config))
        elif Path("config.json").exists():
            self.config = ZeroBitConfig.from_json(Path("config.json"))
        else:
            # Fall back to environment variables or defaults
            self.config = ZeroBitConfig.from_env()

    def get(self, key: str, default: Any = None) -> Any:
        """Get config value by key."""
        return getattr(self.config, key, default)

    def set(self, key: str, value: Any) -> None:
        """Set config value."""
        if hasattr(self.config, key):
            setattr(self.config, key, value)

    def save(self, path: Path) -> None:
        """Save current config to file."""
        self.config.to_json(path)

    def reload(self, path: Path) -> None:
        """Reload config from file."""
        self.config = ZeroBitConfig.from_json(path)

    def validate(self) -> bool:
        """Validate configuration."""
        issues = []

        if self.config.confidence_threshold < 0 or self.config.confidence_threshold > 1:
            issues.append("confidence_threshold must be between 0 and 1")

        if self.config.max_alerts_per_hour < 0:
            issues.append("max_alerts_per_hour must be positive")

        if self.config.api_port < 1024 or self.config.api_port > 65535:
            issues.append("api_port must be between 1024 and 65535")

        if issues:
            print("Configuration validation errors:")
            for issue in issues:
                print(f"  - {issue}")
            return False

        return True


# Global config manager instance
_config_manager: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """Get or create the global config manager."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def load_config(path: Path) -> ConfigManager:
    """Load config from a specific path."""
    global _config_manager
    _config_manager = ConfigManager(path)
    return _config_manager

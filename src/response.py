"""
Automated Incident Response Engine for ZeroBit.
Provides automated blocking and playbook execution capabilities.
"""

from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from typing import Dict, Any

import pandas as pd


class ResponseEngine:
    """Handles automated response actions based on threat intelligence."""

    def __init__(self) -> None:
        self.os_type = platform.system().lower()
        self.block_log = Path("data/blocked_ips.csv")
        self.block_log.parent.mkdir(parents=True, exist_ok=True)

    def block_ip_firewall(self, ip: str, os_type: str | None = None) -> Dict[str, Any]:
        """
        Block an IP address using system firewall.
        Returns: {'status': str, 'command': str, 'error': str|None}
        """
        os_sys = (os_type or self.os_type).lower()

        if os_sys == "linux":
            # iptables blocking
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=5, check=False
                )
                if result.returncode == 0:
                    return {"status": "blocked", "command": " ".join(cmd), "error": None}
                else:
                    return {
                        "status": "failed",
                        "command": " ".join(cmd),
                        "error": result.stderr or "Permission denied (requires sudo)",
                    }
            except Exception as exc:
                return {"status": "error", "command": " ".join(cmd), "error": str(exc)}

        elif os_sys == "windows":
            # Windows Firewall blocking via netsh
            rule_name = f"ZeroBit_Block_{ip.replace('.', '_')}"
            cmd = [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
            ]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=5, check=False, shell=True
                )
                if result.returncode == 0:
                    return {"status": "blocked", "command": " ".join(cmd), "error": None}
                else:
                    return {
                        "status": "failed",
                        "command": " ".join(cmd),
                        "error": result.stderr or "Requires admin privileges",
                    }
            except Exception as exc:
                return {"status": "error", "command": " ".join(cmd), "error": str(exc)}

        else:
            return {
                "status": "unsupported",
                "command": "",
                "error": f"OS {os_sys} not supported for auto-blocking",
            }

    def _log_blocked_ip(self, ip: str, reason: str, threat_score: float) -> None:
        """Log blocked IP to CSV for audit trail."""
        headers = ["timestamp", "ip", "reason", "threat_score"]
        exists = self.block_log.exists()
        row = {
            "timestamp": pd.Timestamp.now().isoformat(),
            "ip": ip,
            "reason": reason,
            "threat_score": threat_score,
        }
        df = pd.DataFrame([row])
        df.to_csv(self.block_log, mode="a", header=not exists, index=False)

    def execute_playbook(
        self, alert_data: Dict[str, Any], threat_score: float
    ) -> Dict[str, Any]:
        """
        Execute automated response playbook based on threat score.
        Returns: {'action': str, 'status': str, 'details': dict}
        """
        ip = alert_data.get("src_ip") or alert_data.get("ip", "Unknown")
        if ip == "Unknown":
            return {
                "action": "monitored",
                "status": "No IP to block",
                "details": {},
            }

        if threat_score > 80:
            # Auto-block high-risk IPs
            block_result = self.block_ip_firewall(ip)
            self._log_blocked_ip(ip, "High threat score auto-block", threat_score)
            return {
                "action": "blocked",
                "status": "Auto-Blocked High Risk IP",
                "details": block_result,
            }
        elif threat_score > 60:
            # Monitor and alert (could add rate limiting here)
            return {
                "action": "monitored",
                "status": "High Risk - Monitored Only",
                "details": {"threat_score": threat_score},
            }
        else:
            return {
                "action": "monitored",
                "status": "Monitored Only",
                "details": {"threat_score": threat_score},
            }

    def isolate_machine(self) -> Dict[str, Any]:
        """
        Isolate machine from network by blocking all traffic (ransomware kill switch).
        This is a drastic measure - use only in emergency situations.
        Returns: {'status': str, 'command': str, 'error': str|None}
        """
        os_sys = self.os_type.lower()

        if os_sys == "linux":
            # Block all incoming and outgoing traffic
            commands = [
                ["sudo", "iptables", "-P", "INPUT", "DROP"],
                ["sudo", "iptables", "-P", "OUTPUT", "DROP"],
                ["sudo", "iptables", "-P", "FORWARD", "DROP"],
            ]
            results = []
            for cmd in commands:
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=5, check=False
                    )
                    results.append({
                        "command": " ".join(cmd),
                        "success": result.returncode == 0,
                        "error": result.stderr if result.returncode != 0 else None,
                    })
                except Exception as exc:
                    results.append({
                        "command": " ".join(cmd),
                        "success": False,
                        "error": str(exc),
                    })

            all_success = all(r["success"] for r in results)
            return {
                "status": "isolated" if all_success else "partial",
                "commands": results,
                "error": None if all_success else "Some commands failed",
            }

        elif os_sys == "windows":
            # Windows: Block all firewall profiles
            commands = [
                ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
                ["netsh", "advfirewall", "firewall", "add", "rule", "name=ZeroBit_KillSwitch_IN", "dir=in", "action=block"],
                ["netsh", "advfirewall", "firewall", "add", "rule", "name=ZeroBit_KillSwitch_OUT", "dir=out", "action=block"],
            ]
            results = []
            for cmd in commands:
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=5, check=False, shell=True
                    )
                    results.append({
                        "command": " ".join(cmd),
                        "success": result.returncode == 0,
                        "error": result.stderr if result.returncode != 0 else None,
                    })
                except Exception as exc:
                    results.append({
                        "command": " ".join(cmd),
                        "success": False,
                        "error": str(exc),
                    })

            all_success = all(r["success"] for r in results)
            return {
                "status": "isolated" if all_success else "partial",
                "commands": results,
                "error": None if all_success else "Some commands failed",
            }

        else:
            return {
                "status": "unsupported",
                "commands": [],
                "error": f"OS {os_sys} not supported for network isolation",
            }


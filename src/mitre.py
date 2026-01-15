"""
MITRE ATT&CK mapping utilities.
"""

from __future__ import annotations

from typing import Dict

ATTACK_MAP: Dict[str, Dict[str, str]] = {
    "probe": {
        "id": "T1046",
        "name": "Network Service Scanning",
        "phase": "Reconnaissance",
        "description": "Adversaries scan for services on remote systems to identify potential weaknesses.",
    },
    "dos": {
        "id": "T1498",
        "name": "Network Denial of Service",
        "phase": "Impact",
        "description": "Adversaries flood networks or services to exhaust resources and deny availability.",
    },
    "u2r": {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "phase": "Privilege Escalation",
        "description": "Adversaries exploit vulnerabilities to elevate permissions on a compromised system.",
    },
    "r2l": {
        "id": "T1078",
        "name": "Valid Accounts",
        "phase": "Defense Evasion",
        "description": "Adversaries leverage stolen or default credentials to gain access to systems.",
    },
    "generic": {
        "id": "TTP",
        "name": "Unmapped Technique",
        "phase": "Unknown",
        "description": "No specific mapping available for this alert type.",
    },
}


def get_mitre_details(attack_label: str) -> Dict[str, str]:
    key = (attack_label or "").strip().lower()
    return ATTACK_MAP.get(key, ATTACK_MAP["generic"])


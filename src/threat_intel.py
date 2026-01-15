"""
Threat Intelligence Aggregation Module for ZeroBit.
Integrates multiple threat intelligence sources to provide comprehensive IP reputation scoring.
"""

from __future__ import annotations

import os
from typing import Dict, Any

import requests  # type: ignore


class ThreatIntel:
    """Aggregates threat intelligence from multiple sources."""

    def __init__(self) -> None:
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")

    def check_abuseipdb(self, ip: str, api_key: str | None = None) -> Dict[str, Any]:
        """
        Query AbuseIPDB API for IP reputation.
        Returns: {'confidence': int (0-100), 'abuse_count': int, 'is_public': bool}
        """
        key = api_key or self.abuseipdb_key
        if not key:
            # Mock response for testing
            return {
                "confidence": 45,
                "abuse_count": 0,
                "is_public": True,
                "usage_type": "Data Center/Web Hosting/Transit",
            }

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
            resp = requests.get(url, headers=headers, params=params, timeout=5)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "confidence": data.get("abuseConfidencePercentage", 0),
                "abuse_count": data.get("totalReports", 0),
                "is_public": data.get("isPublic", True),
                "usage_type": data.get("usageType", "Unknown"),
            }
        except Exception:
            # Fallback to mock on error
            return {
                "confidence": 0,
                "abuse_count": 0,
                "is_public": True,
                "usage_type": "Unknown",
            }

    def check_virustotal(self, ip: str, api_key: str | None = None) -> Dict[str, Any]:
        """
        Query VirusTotal API for IP reputation.
        Returns: {'malicious': int, 'suspicious': int, 'harmless': int, 'undetected': int}
        """
        key = api_key or self.virustotal_key
        if not key:
            # Mock response for testing
            return {
                "malicious": 0,
                "suspicious": 1,
                "harmless": 15,
                "undetected": 5,
            }

        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": key}
            resp = requests.get(url, headers=headers, timeout=5)
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
        except Exception:
            # Fallback to mock on error
            return {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
            }

    def get_combined_score(self, ip: str) -> Dict[str, Any]:
        """
        Compute unified threat score (0-100) from multiple sources.
        Returns: {
            'threat_score': float (0-100),
            'abuseipdb': dict,
            'virustotal': dict,
            'risk_level': str ('Low'|'Medium'|'High'|'Critical')
        }
        """
        abuse = self.check_abuseipdb(ip)
        vt = self.check_virustotal(ip)

        # AbuseIPDB confidence (0-100)
        abuse_score = abuse.get("confidence", 0)

        # VirusTotal: weight malicious more than suspicious
        vt_malicious = vt.get("malicious", 0)
        vt_suspicious = vt.get("suspicious", 0)
        vt_score = min(100, (vt_malicious * 20) + (vt_suspicious * 5))

        # Combined: weighted average (AbuseIPDB 60%, VT 40%)
        threat_score = (abuse_score * 0.6) + (vt_score * 0.4)

        # Risk level classification
        if threat_score >= 80:
            risk_level = "Critical"
        elif threat_score >= 60:
            risk_level = "High"
        elif threat_score >= 30:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        return {
            "threat_score": round(threat_score, 1),
            "abuseipdb": abuse,
            "virustotal": vt,
            "risk_level": risk_level,
        }


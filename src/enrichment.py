"""
IP enrichment via ip-api.com.
Fetches geolocation and ISP metadata for a given IP address.
"""

from __future__ import annotations

import requests


def get_ip_details(ip_address: str):
    """
    Query ip-api.com for IP metadata.
    Returns a dict with country, city, lat, lon, isp; falls back to 'Unknown' on failure.
    """
    url = f"http://ip-api.com/json/{ip_address}"
    try:
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            raise ValueError("Lookup failed")
        return {
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "lat": data.get("lat", None),
            "lon": data.get("lon", None),
            "isp": data.get("isp", "Unknown"),
        }
    except Exception:
        return {
            "country": "Unknown",
            "city": "Unknown",
            "lat": None,
            "lon": None,
            "isp": "Unknown",
        }


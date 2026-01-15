"""
Network discovery helpers.
Uses ARP scanning to find active hosts and optional MAC vendor lookup.
"""

from __future__ import annotations

from typing import List, Dict

import requests
from scapy.all import ARP, Ether, srp  # type: ignore


def scan_network(ip_range: str = "192.168.1.1/24") -> List[Dict[str, str]]:
    """
    Perform an ARP scan over the given IP range.
    Returns a list of {'IP': ip, 'MAC': mac}.
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    answered = srp(packet, timeout=3, verbose=0)[0]
    results: List[Dict[str, str]] = []
    for _, recv in answered:
        results.append({"IP": recv.psrc, "MAC": recv.hwsrc})
    return results


def get_mac_vendor(mac_address: str) -> str:
    """
    Lookup MAC vendor using macvendors API. Returns vendor name or 'Unknown'.
    """
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.text.strip()
        return "Unknown"
    except Exception:
        return "Unknown"


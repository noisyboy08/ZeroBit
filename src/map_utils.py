"""
Map utilities: prepare alert data and optionally geocode IPs using ip-api.com with caching.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

import pandas as pd
import requests

CACHE_PATH = Path("data/geo_cache.json")


def _load_cache() -> Dict[str, Dict]:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text())
        except Exception:
            return {}
    return {}


def _save_cache(cache: Dict[str, Dict]) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache, indent=2))


def geocode_ip(ip: str, use_cache: bool = True, pause: float = 1.0) -> Optional[Dict]:
    """Geocode an IP using ip-api.com and cache results locally.

    Returns a dict with keys: lat, lon, country, city, isp, org, as, query
    Returns None on failure.
    """
    if not ip:
        return None

    cache = _load_cache() if use_cache else {}
    if use_cache and ip in cache:
        return cache[ip]

    try:
        # rate limiting modest pause
        time.sleep(pause)
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp,org,as,query,message", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            record = {
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "country": data.get("country"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
                "ip": data.get("query"),
            }
            cache[ip] = record
            _save_cache(cache)
            return record
        else:
            return None
    except Exception:
        return None


def prepare_alerts_for_map(alerts_csv: Path = Path("data/alerts.csv"), enrich_missing: bool = False, min_confidence: float = 0.0) -> pd.DataFrame:
    """Load alerts and return DataFrame with lat/lon and necessary fields.

    If `enrich_missing` is True, geocode IPs that lack lat/lon using `geocode_ip`.
    Filters alerts by `min_confidence`.
    """
    if not alerts_csv.exists():
        return pd.DataFrame()

    df = pd.read_csv(alerts_csv)

    # Normalize column names
    cols = {c.lower(): c for c in df.columns}
    # Support common names
    if "timestamp" in cols:
        df["timestamp"] = pd.to_datetime(df[cols.get("timestamp", cols.get("time", "timestamp"))], errors="coerce")
    if "src_ip" not in df.columns and "ip" in df.columns:
        df.rename(columns={cols.get("ip", "ip"): "src_ip"}, inplace=True)

    # Ensure confidence numeric
    if "confidence" in df.columns:
        df["confidence"] = pd.to_numeric(df["confidence"], errors="coerce").fillna(0.0)
    else:
        df["confidence"] = 0.0

    # If lat/lon provided in file, use them
    has_latlon = "lat" in df.columns and "lon" in df.columns

    if not has_latlon and enrich_missing:
        # Attempt to enrich from src_ip
        lats = []
        lons = []
        countries = []
        cities = []
        isps = []
        for ip in df.get("src_ip", []):
            rec = geocode_ip(ip)
            if rec:
                lats.append(rec.get("lat"))
                lons.append(rec.get("lon"))
                countries.append(rec.get("country"))
                cities.append(rec.get("city"))
                isps.append(rec.get("isp"))
            else:
                lats.append(None)
                lons.append(None)
                countries.append(None)
                cities.append(None)
                isps.append(None)
        df["lat"] = lats
        df["lon"] = lons
        df["country"] = countries
        df["city"] = cities
        df["isp"] = isps

    # Filter by confidence
    if min_confidence > 0:
        df = df[df["confidence"] >= min_confidence]

    # Drop rows without lat/lon
    df = df.dropna(subset=["lat", "lon"]) if "lat" in df.columns and "lon" in df.columns else pd.DataFrame()

    return df

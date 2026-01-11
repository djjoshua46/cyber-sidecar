from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Optional

import geoip2.database

# Default: GeoLite2-City.mmdb in the same folder as this file
DEFAULT_DB_PATH = Path(__file__).with_name("GeoLite2-City.mmdb")

GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", str(DEFAULT_DB_PATH))

_GEOIP_READER: Optional[geoip2.database.Reader]

try:
    _GEOIP_READER = geoip2.database.Reader(GEOIP_DB_PATH)
    print(f"[geoip] Loaded GeoIP DB from {GEOIP_DB_PATH}")
except Exception as exc:
    _GEOIP_READER = None
    print(f"[geoip] GeoIP disabled: {exc!r}")


def lookup_ip(ip: str) -> Dict[str, Optional[str]]:
    """
    Lookup IP and return country / region / city.
    If DB not available or lookup fails, return Nones.
    """
    if not _GEOIP_READER or not ip:
        return {"country": None, "region": None, "city": None}

    try:
        resp = _GEOIP_READER.city(ip)
        return {
            "country": resp.country.iso_code,
            "region": resp.subdivisions.most_specific.name,
            "city": resp.city.name,
        }
    except Exception:
        # Don't ever blow up the request path because GeoIP failed
        return {"country": None, "region": None, "city": None}

def lookup_geo_label(ip: str) -> Optional[str]:
    """
    Backwards-compatible helper for older code that expects a single geo label.
    Uses lookup_ip() and returns something like: 'US / California / Sacramento'
    or None if lookup fails.
    """
    info = lookup_ip(ip)
    country = info.get("country")
    region = info.get("region")
    city = info.get("city")

    parts = [p for p in (country, region, city) if p]
    if not parts:
        return None
    return " / ".join(parts)

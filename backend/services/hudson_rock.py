"""
Hudson Rock Cavalier — Infostealer Intelligence Service

Checks if a domain appears in Hudson Rock's database of credentials
stolen by infostealer malware (Raccoon, Redline, Vidar, etc.).

Free OSINT endpoint: no API key required, but rate-limited at
50 req/10s. We cache results in-process for 1 hour to avoid re-querying
the same domain on every analysis request.

API reference: https://docs.hudsonrock.com/
"""

import time
import threading
from typing import Dict, Any, Optional
from urllib.parse import urlparse

import requests

from utils.logger import logger


# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
_BASE_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
_TIMEOUT  = 8          # seconds — tight so it never blocks the pipeline
_CACHE_TTL = 3600      # 1 hour in-process cache


# ─────────────────────────────────────────────
# In-process result cache  (domain → entry)
# ─────────────────────────────────────────────
_cache: Dict[str, Dict] = {}
_cache_lock = threading.Lock()


def _cache_get(domain: str) -> Optional[Dict]:
    with _cache_lock:
        entry = _cache.get(domain)
        if entry and time.time() < entry["expire_at"]:
            return entry["data"]
        if entry:
            del _cache[domain]
    return None


def _cache_set(domain: str, data: Dict) -> None:
    with _cache_lock:
        _cache[domain] = {
            "data":      data,
            "expire_at": time.time() + _CACHE_TTL,
        }


# ─────────────────────────────────────────────
# HTTP session (connection pooling)
# ─────────────────────────────────────────────
_session = requests.Session()
_session.headers.update({
    "User-Agent": "AIScamDetector/2.0 (security-research)",
    "Accept":     "application/json",
})


# ─────────────────────────────────────────────
# Core lookup
# ─────────────────────────────────────────────

def _search_by_domain(domain: str) -> Optional[Dict]:
    """
    Call Hudson Rock /search-by-domain endpoint.
    Returns raw JSON or None on error/timeout.
    """
    url = f"{_BASE_URL}/search-by-domain"
    try:
        resp = _session.get(url, params={"domain": domain}, timeout=_TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 429:
            logger.warning("hudson_rock_rate_limited | domain=%s", domain)
        else:
            logger.warning(
                "hudson_rock_bad_status | domain=%s | status=%d",
                domain, resp.status_code,
            )
        return None
    except requests.Timeout:
        logger.warning("hudson_rock_timeout | domain=%s", domain)
        return None
    except Exception as e:
        logger.warning("hudson_rock_error | domain=%s | %s", domain, str(e)[:120])
        return None


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def check_hudson_rock(url: str) -> Dict[str, Any]:
    """
    Check a URL's domain against Hudson Rock's infostealer database.

    Returns a dict suitable for merging into the pipeline result:
    {
        "checked":             bool,   # False = API unavailable / skipped
        "compromised":         bool,   # True if domain found in stealer data
        "total_employees_compromised": int,
        "total_users_compromised":     int,
        "third_party_compromised":     int,
        "signal":              str | None,  # risk signal name for pipeline
    }
    """
    _empty = {
        "checked":                     False,
        "compromised":                 False,
        "total_employees_compromised": 0,
        "total_users_compromised":     0,
        "third_party_compromised":     0,
        "signal":                      None,
    }

    try:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        if not domain:
            return _empty

        # Strip www prefix for broader match
        clean_domain = domain.lstrip("www.") if domain.startswith("www.") else domain

        # Check in-process cache first
        cached = _cache_get(clean_domain)
        if cached is not None:
            logger.debug("hudson_rock_cache_hit | domain=%s", clean_domain)
            return cached

        raw = _search_by_domain(clean_domain)
        if raw is None:
            _cache_set(clean_domain, _empty)
            return _empty

        # Parse response
        # Hudson Rock returns: {"stealerFamilies": [...], "total": {...}, ...}
        total = raw.get("total") or {}
        employees   = int(total.get("employees_compromised", 0) or 0)
        users       = int(total.get("users_compromised", 0)     or 0)
        third_party = int(total.get("third_party_compromised", 0) or 0)

        compromised = (employees + users + third_party) > 0

        # Determine severity signal for pipeline
        signal = None
        if compromised:
            total_count = employees + users + third_party
            if employees > 0:
                signal = "hudson_rock_employee_credentials_stolen"
            elif total_count >= 100:
                signal = "hudson_rock_high_volume_credentials_stolen"
            else:
                signal = "hudson_rock_credentials_stolen"

        result = {
            "checked":                     True,
            "compromised":                 compromised,
            "total_employees_compromised": employees,
            "total_users_compromised":     users,
            "third_party_compromised":     third_party,
            "signal":                      signal,
        }

        _cache_set(clean_domain, result)

        if compromised:
            logger.warning(
                "hudson_rock_hit | domain=%s | employees=%d | users=%d | third_party=%d",
                clean_domain, employees, users, third_party,
            )
        else:
            logger.debug("hudson_rock_clean | domain=%s", clean_domain)

        return result

    except Exception as e:
        logger.warning("hudson_rock_parse_error | %s", str(e)[:200])
        return _empty

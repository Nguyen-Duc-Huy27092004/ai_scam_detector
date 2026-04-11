"""
Domain intelligence module.

Fixes applied:
  H2 — WHOIS timeout: whois.whois() now runs in a dedicated thread with a
       hard 5-second timeout, preventing indefinite blocking.
  L2 — Removed duplicate _check_ssl(): ssl_inspector.inspect_ssl() already
       performs a full TLS check; calling _check_ssl() here was a redundant
       second TCP connection to port 443 on every analysis.
"""

import re
import socket
import ipaddress
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any, Optional

import whois

from utils.logger import logger


# ──────────────────────────────────────────────────────────────────────────────
# Suspicious pattern tables
# ──────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf",
    "xyz", "top", "win",
    "click", "review", "vip",
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "account",
    "update", "bank", "paypal", "apple",
    "google", "facebook", "confirm",
    "support", "service", "wallet",
}


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _is_ip(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return True
    except Exception:
        return False


def _safe_domain_age(domain: str) -> Optional[int]:
    """
    Return domain age in days, or None on failure.

    H2: whois.whois() has no built-in timeout and can block for 30+ seconds
    on slow TLD servers. We run it in an executor with a 5-second deadline.
    """
    def _fetch():
        return whois.whois(domain)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_fetch)
            try:
                info = future.result(timeout=5)
            except concurrent.futures.TimeoutError:
                logger.warning("whois_timeout | domain=%s", domain)
                return None

        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if not creation:
            return None
        if isinstance(creation, str):
            return None

        if creation.tzinfo:
            creation = creation.replace(tzinfo=None)

        return (datetime.utcnow() - creation).days

    except Exception as e:
        logger.warning("whois_failed | %s | %s", domain, str(e))
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Main domain intel
# ──────────────────────────────────────────────────────────────────────────────

def get_domain_intel(url: str) -> Dict[str, Any]:

    parsed = urlparse(url)
    domain = parsed.hostname or ""

    result: Dict[str, Any] = {
        "domain":             domain,
        "is_https":           url.startswith("https://"),
        "is_ip":              False,
        "age_days":           None,
        "subdomain_count":    0,
        "tld":                None,
        "whois_registered":   False,
        # L2: ssl_valid is now populated by ssl_inspector.inspect_ssl()
        # downstream; we keep the key for backwards compat but set False here.
        "ssl_valid":          False,
        "domain_length":      len(domain),
        "suspicious_patterns": [],
    }

    try:
        patterns: set = set()

        # IP address
        if _is_ip(domain):
            result["is_ip"] = True
            patterns.add("ip_address")

        # Domain structure
        parts = domain.split(".")
        if len(parts) > 2:
            result["subdomain_count"] = len(parts) - 2

        if parts:
            tld = parts[-1].lower()
            result["tld"] = tld
            if tld in SUSPICIOUS_TLDS:
                patterns.add("suspicious_tld")

        # Keyword detection
        domain_lower = domain.lower()
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in domain_lower:
                patterns.add(f"keyword_{kw}")

        # Domain length
        if len(domain) > 40:
            patterns.add("long_domain")

        # Subdomain abuse
        if result["subdomain_count"] >= 3:
            patterns.add("too_many_subdomains")

        # Punycode / IDN
        if "xn--" in domain:
            patterns.add("punycode_domain")

        # WHOIS (H2: with 5s timeout)
        age_days = _safe_domain_age(domain)
        if age_days is not None:
            result["age_days"]         = age_days
            result["whois_registered"] = True
            if age_days < 30:
                patterns.add("new_domain")
            elif age_days < 90:
                patterns.add("young_domain")
        else:
            patterns.add("whois_missing")

        # L2: Removed redundant _check_ssl() — ssl_inspector.inspect_ssl()
        # in url_pipeline.py already performs a full TLS handshake and its
        # result is fed into calculate_risk() via ssl_result.
        if not result["is_https"]:
            patterns.add("no_https")

        # Suspicious port
        if parsed.port and parsed.port not in {80, 443}:
            patterns.add("suspicious_port")

        result["suspicious_patterns"] = list(patterns)

        logger.info(
            "domain_intel_done | domain=%s | patterns=%d",
            domain, len(patterns),
        )

    except Exception as e:
        logger.exception("domain_intel_failed | %s", str(e))
        result["error"] = str(e)

    return result
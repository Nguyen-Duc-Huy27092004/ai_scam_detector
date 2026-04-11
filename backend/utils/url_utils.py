"""
URL utility functions.

Provides URL normalization, SSRF protection, and domain extraction.
"""

import ipaddress
import socket
from urllib.parse import urlparse

from urllib.parse import urlparse
import re

from utils.logger import logger


# =============================================
# SSRF — Private/reserved IP ranges to block
# =============================================

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),         # Private Class A
    ipaddress.ip_network("172.16.0.0/12"),       # Private Class B
    ipaddress.ip_network("192.168.0.0/16"),      # Private Class C
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local (AWS metadata)
    ipaddress.ip_network("100.64.0.0/10"),       # Carrier-grade NAT
    ipaddress.ip_network("::1/128"),             # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),            # IPv6 private
]


def is_safe_url(url: str) -> bool:
    """
    SSRF protection: reject URLs that resolve to private/internal IP addresses.

    This must be called BEFORE any outbound HTTP request to prevent
    Server-Side Request Forgery (SSRF) attacks.

    Args:
        url: URL to validate

    Returns:
        bool: True if URL is safe (public IP), False if it resolves to private range
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return False

        # Reject hostnames that look like internal addresses directly
        if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            logger.warning("ssrf_blocked | hostname=%s | reason=localhost_or_zero", hostname)
            return False
            
        # Reject explicitly internal/local domains
        if hostname.endswith((".local", ".internal", ".host", ".lan", ".home", ".test", ".invalid", ".example")):
            logger.warning("ssrf_blocked | hostname=%s | reason=internal_tld", hostname)
            return False
            
        # Reject AWS/GCP metadata domain spoofing
        if "169.254" in hostname or "metadata.google.internal" in hostname or "instance-data" in hostname:
            logger.warning("ssrf_blocked | hostname=%s | reason=metadata_spoofing", hostname)
            return False

        # Resolve hostname to IP
        try:
            ip_str = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_str)
        except (socket.gaierror, ValueError):
            # Cannot resolve — treat as unsafe to avoid DNS tricks
            logger.warning("ssrf_blocked | hostname=%s | reason=dns_resolution_failed", hostname)
            return False

        # Check against blocked ranges
        for network in _BLOCKED_NETWORKS:
            try:
                if ip in network:
                    logger.warning(
                        "ssrf_blocked | hostname=%s | ip=%s | network=%s",
                        hostname, ip_str, network
                    )
                    return False
            except TypeError:
                # IPv6 ip in IPv4 network (or vice versa) → skip
                continue

        return True

    except Exception as e:
        logger.warning("ssrf_check_error | url=%s | error=%s", url[:100], str(e))
        return False


def normalize_url(url: str) -> str:
    """
    Normalize URL before analysis.

    - strip whitespace
    - ensure scheme exists
    - lowercase domain
    """

    if not url:
        return ""

    url = url.strip()

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path

    normalized = f"{scheme}://{netloc}{path}"

    if parsed.query:
        normalized += f"?{parsed.query}"

    if parsed.fragment:
        normalized += f"#{parsed.fragment}"

    return normalized


def extract_domain(url: str) -> str:
    """
    Extract the root domain from a URL.

    Args:
        url: Full URL string

    Returns:
        str: Domain (netloc) or empty string
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""
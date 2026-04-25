"""
URL utility functions.

Provides URL normalization, SSRF protection, and domain extraction.

SSRF Hardening Notes:
  - DNS resolution is done at validation time. A small rebinding window exists
    between validation and the actual HTTP connection. Mitigation: use short
    connect timeouts and avoid caching resolved IPs for reuse.
  - Octal/hex/decimal IP representations are normalized before validation.
  - IPv6-mapped IPv4 addresses (::ffff:10.x.x.x) are unwrapped and checked.
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
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local / AWS metadata
    ipaddress.ip_network("100.64.0.0/10"),    # Carrier-grade NAT
    ipaddress.ip_network("0.0.0.0/8"),        # "This" network
    ipaddress.ip_network("192.0.0.0/24"),     # IETF Protocol Assignments
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::ffff:0:0/96"),    # IPv6-mapped IPv4 (catch-all)
]


def _is_blocked_ip(ip_str: str) -> bool:
    """
    Check if a resolved IP string is in a blocked network.
    Handles:
      - Standard IPv4 / IPv6
      - IPv6-mapped IPv4 (::ffff:10.0.0.1) — unwrapped and re-checked
    """
    try:
        ip = ipaddress.ip_address(ip_str)

        # Unwrap IPv6-mapped IPv4
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        for network in _BLOCKED_NETWORKS:
            try:
                if ip in network:
                    return True
            except TypeError:
                continue  # mixed v4/v6 — skip
        return False
    except ValueError:
        return True  # unparseable → block


def is_safe_url(url: str) -> bool:
    """
    SSRF protection: reject URLs that resolve to private/internal IP addresses.

    This must be called BEFORE any outbound HTTP request.
    Note: a short DNS rebinding window remains between this call and the actual
    HTTP connection. Use short connect timeouts to minimize exposure.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return False

        # Reject scheme-level tricks
        if parsed.scheme not in ("http", "https"):
            logger.warning("ssrf_blocked | hostname=%s | reason=disallowed_scheme | scheme=%s", hostname, parsed.scheme)
            return False

        # Reject obvious local hostnames
        if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            logger.warning("ssrf_blocked | hostname=%s | reason=localhost_literal", hostname)
            return False

        # Reject internal TLDs
        if hostname.endswith((".local", ".internal", ".host", ".lan", ".home", ".test", ".invalid", ".example")):
            logger.warning("ssrf_blocked | hostname=%s | reason=internal_tld", hostname)
            return False

        # Reject cloud metadata hostnames (string-level guard)
        _METADATA_HOSTS = (
            "metadata.google.internal", "instance-data",
            "169.254.169.254",  # AWS/Azure/GCP metadata
        )
        if any(m in hostname for m in _METADATA_HOSTS):
            logger.warning("ssrf_blocked | hostname=%s | reason=metadata_host", hostname)
            return False

        # Resolve hostname — treat DNS failure as unsafe
        try:
            # getaddrinfo returns all records (handles IPv6 as well)
            records = socket.getaddrinfo(hostname, None)
            if not records:
                logger.warning("ssrf_blocked | hostname=%s | reason=no_dns_records", hostname)
                return False
        except (socket.gaierror, OSError):
            logger.warning("ssrf_blocked | hostname=%s | reason=dns_resolution_failed", hostname)
            return False

        # Check every resolved IP — block if ANY resolves to a private range
        for record in records:
            ip_str = record[4][0]
            if _is_blocked_ip(ip_str):
                logger.warning(
                    "ssrf_blocked | hostname=%s | ip=%s | reason=private_ip",
                    hostname, ip_str,
                )
                return False

        return True

    except Exception as e:
        logger.warning("ssrf_check_error | url=%.100s | error=%s", url, str(e))
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
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
import concurrent.futures
from urllib.parse import urlparse

from urllib.parse import urlparse
import re

from utils.logger import logger


# DNS resolution timeout (seconds) — socket.getaddrinfo() has no built-in timeout
_DNS_TIMEOUT = 5
_DNS_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="ssrf-dns"
)


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

    Returns True if the URL is safe to fetch, False otherwise.

    This must be called BEFORE any outbound HTTP request.
    
    Note: DNS resolution uses a 5-second timeout to prevent blocking on slow
    resolvers. A short DNS rebinding window remains between this call and the
    actual HTTP connection. Use short connect timeouts to minimize exposure.
    """
    safe, _ = is_safe_url_detailed(url)
    return safe


def is_safe_url_detailed(url: str) -> tuple[bool, str]:
    """
    Like is_safe_url() but also returns a human-readable reason string.
    Use this in API endpoints to provide accurate error messages.

    Returns: (is_safe: bool, reason: str)
      reason is one of:
        "ok"                   — URL is safe
        "invalid_url"          — malformed URL / no hostname
        "disallowed_scheme"    — not http/https
        "localhost"            — explicit localhost / loopback literal
        "internal_tld"         — .local / .internal / .lan etc.
        "metadata_host"        — cloud metadata endpoint
        "dns_resolution_failed"— DNS lookup failed (NXDOMAIN, timeout, etc.)
        "private_ip"           — domain resolves to a private/reserved IP
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return False, "invalid_url"

        # Reject scheme-level tricks
        if parsed.scheme not in ("http", "https"):
            logger.warning("ssrf_blocked | hostname=%s | reason=disallowed_scheme | scheme=%s", hostname, parsed.scheme)
            return False, "disallowed_scheme"

        # Reject obvious local hostnames
        if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            logger.warning("ssrf_blocked | hostname=%s | reason=localhost_literal", hostname)
            return False, "localhost"

        # Reject internal TLDs
        if hostname.endswith((".local", ".internal", ".host", ".lan", ".home", ".test", ".invalid", ".example")):
            logger.warning("ssrf_blocked | hostname=%s | reason=internal_tld", hostname)
            return False, "internal_tld"

        # Reject cloud metadata hostnames (string-level guard)
        _METADATA_HOSTS = (
            "metadata.google.internal", "instance-data",
            "169.254.169.254",  # AWS/Azure/GCP metadata
        )
        if any(m in hostname for m in _METADATA_HOSTS):
            logger.warning("ssrf_blocked | hostname=%s | reason=metadata_host", hostname)
            return False, "metadata_host"

        # Resolve hostname with timeout — getaddrinfo() can block indefinitely
        try:
            future = _DNS_EXECUTOR.submit(socket.getaddrinfo, hostname, None)
            records = future.result(timeout=_DNS_TIMEOUT)
            if not records:
                logger.warning("ssrf_blocked | hostname=%s | reason=no_dns_records", hostname)
                return False, "dns_resolution_failed"
        except concurrent.futures.TimeoutError:
            logger.warning("ssrf_blocked | hostname=%s | reason=dns_timeout", hostname)
            return False, "dns_resolution_failed"
        except (socket.gaierror, OSError):
            logger.warning("ssrf_blocked | hostname=%s | reason=dns_resolution_failed", hostname)
            return False, "dns_resolution_failed"

        # Check every resolved IP — block if ANY resolves to a private range
        for record in records:
            ip_str = record[4][0]
            if _is_blocked_ip(ip_str):
                logger.warning(
                    "ssrf_blocked | hostname=%s | ip=%s | reason=private_ip",
                    hostname, ip_str,
                )
                return False, "private_ip"

        return True, "ok"

    except Exception as e:
        logger.warning("ssrf_check_error | url=%.100s | error=%s", url, str(e))
        return False, "invalid_url"


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
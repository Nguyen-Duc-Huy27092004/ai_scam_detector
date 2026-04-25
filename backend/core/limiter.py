"""
Rate limiter singleton — Production Safe.

Key changes vs original:
  - USE_REDIS=true is REQUIRED in production (DEBUG=false).
    In-memory fallback is only allowed in development to prevent per-worker
    limit bypass in multi-worker deployments.
  - Client IP is extracted respecting X-Forwarded-For when TRUSTED_PROXIES
    is configured (prevents rate limit bypass behind Nginx/Cloudflare).
  - Falls back to in-memory ONLY in dev (DEBUG=true) with a loud warning.
"""

import os
import ipaddress
import logging
from typing import Optional

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

from utils.logger import logger

_DEBUG = os.getenv("DEBUG", "false").lower() == "true"
_RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
_USE_REDIS = os.getenv("USE_REDIS", "false").lower() == "true"
_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Comma-separated CIDRs or IPs of trusted upstream proxies
_TRUSTED_PROXIES_RAW = os.getenv("TRUSTED_PROXIES", "")


def _parse_trusted_proxies(raw: str) -> list:
    result = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            result.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            try:
                result.append(ipaddress.ip_address(part))
            except ValueError:
                logger.warning("trusted_proxies_invalid_entry | entry=%s", part)
    return result


_TRUSTED_NETWORKS = _parse_trusted_proxies(_TRUSTED_PROXIES_RAW)


def _is_trusted_proxy(ip_str: str) -> bool:
    """Return True if the given IP is a trusted proxy."""
    if not _TRUSTED_NETWORKS:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in _TRUSTED_NETWORKS:
            if isinstance(net, ipaddress.IPv4Network) or isinstance(net, ipaddress.IPv6Network):
                if ip in net:
                    return True
            elif ip == net:
                return True
    except ValueError:
        pass
    return False


def _get_real_ip(request: Request) -> str:
    """
    Extract the real client IP, respecting X-Forwarded-For only when the
    direct connection comes from a trusted proxy. This prevents IP spoofing
    by untrusted clients sending forged X-Forwarded-For headers.
    """
    direct_ip: Optional[str] = request.client.host if request.client else None

    if direct_ip and _is_trusted_proxy(direct_ip):
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            # X-Forwarded-For: client, proxy1, proxy2 — take leftmost (real client)
            real_ip = forwarded_for.split(",")[0].strip()
            if real_ip:
                return real_ip

    return direct_ip or get_remote_address(request)


# ---------------------------------------------------------------------------
# Limiter construction
# ---------------------------------------------------------------------------

if not _RATE_LIMIT_ENABLED:
    logger.info("rate_limiter_init | backend=disabled")
    limiter = Limiter(key_func=_get_real_ip, default_limits=[])

elif _USE_REDIS:
    try:
        limiter = Limiter(
            key_func=_get_real_ip,
            storage_uri=_REDIS_URL,
        )
        logger.info("rate_limiter_init | backend=redis | url_prefix=%s", _REDIS_URL[:20])
    except Exception as e:
        if _DEBUG:
            logger.warning(
                "rate_limiter_redis_failed | error=%s | falling_back_to_memory (dev only)",
                type(e).__name__,
            )
            limiter = Limiter(key_func=_get_real_ip)
        else:
            # Production: Redis is required — crash fast rather than silently downgrade
            raise RuntimeError(
                f"Rate limiter Redis connection failed in production: {e}. "
                "Set USE_REDIS=false to disable Redis OR fix REDIS_URL."
            ) from e

else:
    if not _DEBUG:
        logger.warning(
            "rate_limiter_init | backend=memory | RISK: per-worker limits in production! "
            "Set USE_REDIS=true for global rate limiting across workers."
        )
    else:
        logger.info("rate_limiter_init | backend=memory (development mode)")
    limiter = Limiter(key_func=_get_real_ip)

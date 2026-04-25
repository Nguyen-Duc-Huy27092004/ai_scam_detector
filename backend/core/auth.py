"""
API Key Authentication — FastAPI Dependency

Usage:
    @router.post("/endpoint")
    async def endpoint(request: Request, _: None = Depends(require_api_key)):
        ...

Keys are set via API_KEYS env var (comma-separated).
If REQUIRE_AUTH=false (dev mode only), auth is skipped entirely.
"""
import os
import secrets
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader

from utils.logger import logger

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# Load valid keys at startup — never reload at runtime
_RAW_KEYS = os.getenv("API_KEYS", "")
_VALID_KEYS: set[str] = {k.strip() for k in _RAW_KEYS.split(",") if k.strip()}

REQUIRE_AUTH: bool = os.getenv("REQUIRE_AUTH", "true").lower() != "false"


def _is_valid_key(key: Optional[str]) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    if not key or not _VALID_KEYS:
        return False
    return any(secrets.compare_digest(key, valid) for valid in _VALID_KEYS)


async def require_api_key(
    request: Request,
    api_key: Optional[str] = Depends(_API_KEY_HEADER),
) -> None:
    """
    FastAPI dependency — raises 401/403 if key is missing or invalid.
    Attach with: Depends(require_api_key)
    """
    if not REQUIRE_AUTH:
        return  # Dev/test mode only

    if not api_key:
        logger.warning(
            "auth_missing_key | path=%s | ip=%s",
            request.url.path,
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if not _is_valid_key(api_key):
        logger.warning(
            "auth_invalid_key | path=%s | ip=%s | key_prefix=%.8s",
            request.url.path,
            request.client.host if request.client else "unknown",
            api_key,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )

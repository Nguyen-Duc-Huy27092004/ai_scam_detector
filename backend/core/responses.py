"""
Standardized JSON response helpers.

All API handlers should use these helpers to ensure a consistent
response schema across all endpoints.

  json_success(data, status_code) → 2xx JSONResponse
  json_error(message, status_code, extra) → 4xx/5xx JSONResponse
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi.responses import JSONResponse


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def json_success(
    data: Any,
    status_code: int = 200,
    *,
    meta: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    """Return a successful JSON response with a consistent envelope."""
    body: Dict[str, Any] = {
        "success": True,
        "data": data,
        "timestamp": _timestamp(),
    }
    if meta:
        body["meta"] = meta
    return JSONResponse(status_code=status_code, content=body)


def json_error(
    message: str,
    status_code: int = 400,
    extra: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    """Return an error JSON response with a consistent envelope.

    NOTE: Never put raw exception text into ``message`` when the endpoint is
    public — caller should sanitize before passing here.
    """
    body: Dict[str, Any] = {
        "success": False,
        "error": message,
        "timestamp": _timestamp(),
    }
    if extra:
        body.update(extra)
    return JSONResponse(status_code=status_code, content=body)

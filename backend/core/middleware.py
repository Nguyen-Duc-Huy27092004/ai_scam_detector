"""
Production Middleware

RequestIDMiddleware  — injects a UUID X-Request-ID into every request/response.
RequestLoggingMiddleware — structured access log with latency, status, request_id.

Both middlewares propagate request_id via the ContextVar defined in utils.logger
so that all log records in the same request automatically include request_id.
"""
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from utils.logger import logger, get_request_id_ctx

# Reference the shared ContextVar from logger (avoids circular import)
request_id_ctx = get_request_id_ctx()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Injects a unique X-Request-ID into every request.

    Priority:
      1. Use existing X-Request-ID header (if client / upstream proxy provides one)
      2. Generate a new UUID4

    The ID is stored in:
      - request.state.request_id
      - request_id_ctx ContextVar  (accessible from any coroutine / thread in this request)
      - X-Request-ID response header
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = req_id
        token = request_id_ctx.set(req_id)
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = req_id
            return response
        finally:
            request_id_ctx.reset(token)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Structured access log for every HTTP request.

    Log format (JSON-compatible key=value):
      access | method=POST path=/api/url/analyze status=200 latency_ms=342 request_id=<uuid>
    """

    # Paths to skip (health probes generate too much noise)
    _SKIP_PATHS = {"/api/health", "/api/health/"}

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in self._SKIP_PATHS:
            return await call_next(request)

        start = time.perf_counter()
        req_id = getattr(request.state, "request_id", "-")
        status_code = 500

        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception:
            raise
        finally:
            latency_ms = round((time.perf_counter() - start) * 1000, 1)
            logger.info(
                "access | method=%s path=%s status=%d latency_ms=%.1f request_id=%s",
                request.method,
                request.url.path,
                status_code,
                latency_ms,
                req_id,
            )

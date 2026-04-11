"""
Health check endpoint.

L5: Extended health checks — now verifies Redis connectivity and ML model
file existence so degraded states are visible to load balancers and operators.
Returns HTTP 200 with status='degraded' on partial failures so upstream
health-checkers still route traffic while ops teams investigate.
"""

from datetime import datetime
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from utils.logger import logger
from utils.config import PHISHING_MODEL_PATH, SCALER_PATH
from core.cache import cache

router = APIRouter()


@router.get("/health")
async def health_check():
    """
    Health check endpoint.

    Returns:
        200 healthy   — all components operational
        200 degraded  — app is up but one or more components failed
        500 unhealthy — catastrophic failure
    """
    components = {}
    overall = "healthy"

    # ── API ──────────────────────────────────────────────────────────────────
    components["api"] = "operational"

    # ── Redis ─────────────────────────────────────────────────────────────────
    try:
        if cache.redis_client:
            await cache.redis_client.ping()
            components["redis"] = "operational"
        else:
            components["redis"] = "unavailable"
            overall = "degraded"
    except Exception as e:
        logger.warning("health_redis_failed | %s", str(e))
        components["redis"] = f"error: {type(e).__name__}"
        overall = "degraded"

    # ── ML models ─────────────────────────────────────────────────────────────
    try:
        model_ok  = Path(PHISHING_MODEL_PATH).exists()
        scaler_ok = Path(SCALER_PATH).exists()
        if model_ok and scaler_ok:
            components["ml_models"] = "loaded"
        else:
            missing = []
            if not model_ok:  missing.append("phishing_model")
            if not scaler_ok: missing.append("scaler")
            components["ml_models"] = f"missing: {', '.join(missing)}"
            overall = "degraded"
    except Exception as e:
        logger.warning("health_model_check_failed | %s", str(e))
        components["ml_models"] = f"error: {type(e).__name__}"
        overall = "degraded"

    response = {
        "status":     overall,
        "service":    "AI Scam Detector API",
        "version":    "2.0.0",
        "timestamp":  datetime.utcnow().isoformat() + "Z",
        "components": components,
    }

    if overall == "unhealthy":
        return JSONResponse(status_code=500, content=response)

    return response


@router.get("/version")
async def get_version():
    return {
        "version":   "2.0.0",
        "api":       "AI Scam Detector API",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

"""
Health check endpoints.

Public `/health` returns only aggregate status (no per-component detail).
Full component diagnostics: `GET /health/internal` with header `X-Internal-Token`
when `INTERNAL_HEALTH_TOKEN` is set in the environment.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import JSONResponse

from utils.logger import logger
from utils.config import PHISHING_MODEL_PATH, SCALER_PATH, INTERNAL_HEALTH_TOKEN
from core.cache import cache

router = APIRouter()


async def _build_components() -> tuple[str, Dict[str, Any]]:
    components: Dict[str, Any] = {}
    overall = "healthy"

    components["api"] = "operational"

    try:
        if cache.redis_client:
            await cache.redis_client.ping()
            components["redis"] = "operational"
        else:
            components["redis"] = "unavailable"
            overall = "degraded"
    except Exception as e:
        logger.warning("health_redis_failed | type=%s", type(e).__name__)
        components["redis"] = "degraded"
        overall = "degraded"

    try:
        model_ok = Path(PHISHING_MODEL_PATH).exists()
        scaler_ok = Path(SCALER_PATH).exists()
        if model_ok and scaler_ok:
            components["ml_models"] = "loaded"
        else:
            missing = []
            if not model_ok:
                missing.append("phishing_model")
            if not scaler_ok:
                missing.append("scaler")
            components["ml_models"] = f"missing: {', '.join(missing)}"
            overall = "degraded"
    except Exception as e:
        logger.warning("health_model_check_failed | type=%s", type(e).__name__)
        components["ml_models"] = "degraded"
        overall = "degraded"

    return overall, components


@router.get("/health")
async def health_check():
    """Public health: minimal body suitable for internet-facing load balancers."""
    overall, _ = await _build_components()
    return {
        "status": overall,
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@router.get("/health/internal")
async def health_internal(
    x_internal_token: Optional[str] = Header(None, alias="X-Internal-Token"),
):
    """Detailed component status. Disabled unless INTERNAL_HEALTH_TOKEN is configured."""
    if not INTERNAL_HEALTH_TOKEN:
        raise HTTPException(status_code=404, detail="Not found")
    if x_internal_token != INTERNAL_HEALTH_TOKEN:
        raise HTTPException(status_code=404, detail="Not found")

    overall, components = await _build_components()
    response = {
        "status": overall,
        "service": "AI Scam Detector API",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "components": components,
    }

    if overall == "unhealthy":
        return JSONResponse(status_code=500, content=response)
    return response


@router.get("/version")
async def get_version():
    return {
        "version": "2.0.0",
        "api": "AI Scam Detector API",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

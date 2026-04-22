import asyncio
from datetime import datetime
from typing import Any, Optional, Dict

from pydantic import BaseModel

from fastapi import APIRouter, Query, Request

from core.limiter import limiter
from core.responses import json_error, json_success
from utils.logger import logger
from ml.url.db import AnalysisHistory

router = APIRouter()


class CleanupRequest(BaseModel):
    days: int = 90


@router.get("/all")
@limiter.limit("30/minute")
async def get_all_history(
    request: Request,
    limit: int = Query(50, le=200, ge=1),
    offset: int = Query(0, ge=0),
):
    """Get all analysis history with pagination."""
    try:
        logger.info("history_request | limit=%d | offset=%d", limit, offset)

        records = await asyncio.to_thread(AnalysisHistory.get_all, limit=limit, offset=offset)

        return json_success({
            "total_records": len(records),
            "limit": limit,
            "offset": offset,
            "records": records,
        }, 200)
    except Exception as e:
        logger.error("history_endpoint_error | error=%s", str(e))
        return json_error("Failed to retrieve history", 500)


@router.get("/by-type/{analysis_type}")
@limiter.limit("30/minute")
async def get_history_by_type(
    request: Request,
    analysis_type: str,
    limit: int = Query(50, le=200, ge=1),
    offset: int = Query(0, ge=0),
):
    """Get analysis history by type."""
    try:
        valid_types = ["url", "image", "text"]
        if analysis_type not in valid_types:
            return json_error(
                f"Invalid analysis type. Must be one of: {', '.join(valid_types)}",
                400,
            )

        logger.info("history_by_type_request | type=%s | limit=%d", analysis_type, limit)
        records = await asyncio.to_thread(
            AnalysisHistory.get_by_type, analysis_type, limit=limit, offset=offset
        )

        return json_success({
            "type": analysis_type,
            "total_records": len(records),
            "limit": limit,
            "offset": offset,
            "records": records,
        }, 200)
    except Exception as e:
        logger.error("history_by_type_error | error=%s", str(e))
        return json_error("Failed to retrieve history", 500)


@router.get("/by-risk/{risk_level}")
@limiter.limit("30/minute")
async def get_history_by_risk(
    request: Request,
    risk_level: str,
    limit: int = Query(50, le=200, ge=1),
    offset: int = Query(0, ge=0),
):
    """Get analysis history by risk level."""
    try:
        valid_levels = ["low", "medium", "high"]
        if risk_level not in valid_levels:
            return json_error(
                f"Invalid risk level. Must be one of: {', '.join(valid_levels)}",
                400,
            )

        logger.info("history_by_risk_request | risk=%s | limit=%d", risk_level, limit)
        records = await asyncio.to_thread(
            AnalysisHistory.get_by_risk_level, risk_level, limit=limit, offset=offset
        )

        return json_success({
            "risk_level": risk_level,
            "total_records": len(records),
            "limit": limit,
            "offset": offset,
            "records": records,
        }, 200)
    except Exception as e:
        logger.error("history_by_risk_error | error=%s", str(e))
        return json_error("Failed to retrieve history", 500)


@router.get("/record/{record_id}")
@limiter.limit("60/minute")
async def get_record(request: Request, record_id: int):
    """Get specific analysis record by ID."""
    try:
        logger.info("record_request | id=%d", record_id)
        record = await asyncio.to_thread(AnalysisHistory.get_by_id, record_id)

        if not record:
            return json_error("Record not found", 404)

        return json_success({"record": record}, 200)
    except Exception as e:
        logger.error("record_endpoint_error | error=%s", str(e))
        return json_error("Failed to retrieve record", 500)


@router.get("/statistics")
@limiter.limit("20/minute")
async def get_statistics(request: Request):
    """Get analysis statistics and summary."""
    try:
        logger.info("statistics_request")
        stats = await asyncio.to_thread(AnalysisHistory.get_stats)

        return json_success({
            "statistics": stats,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }, 200)
    except Exception as e:
        logger.error("statistics_endpoint_error | error=%s", str(e))
        return json_error("Failed to retrieve statistics", 500)


@router.post("/cleanup")
@limiter.limit("1/minute")
async def cleanup_old_records(request: Request, body: CleanupRequest):
    """Delete analysis records older than specified days."""
    try:
        days = body.days
        if days > 365 or days < 1:
            return json_error("Days must be between 1 and 365", 400)

        logger.info("cleanup_request | days=%d", days)
        deleted_count = await asyncio.to_thread(AnalysisHistory.delete_old_records, days)

        return json_success({
            "deleted_records": deleted_count,
            "older_than_days": days,
        }, 200)
    except Exception as e:
        logger.error("cleanup_endpoint_error | error=%s", str(e))
        return json_error("Cleanup failed", 500)

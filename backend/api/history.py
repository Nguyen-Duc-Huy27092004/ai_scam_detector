import asyncio
from datetime import datetime
from typing import Any, Optional, Dict
from pydantic import BaseModel

from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import JSONResponse

from utils.logger import logger
from ml.url.db import AnalysisHistory

router = APIRouter()

def _success_response(data: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            'success': True,
            'data': data,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    )

def _error_response(message: str, status_code: int = 400, details: Optional[Dict] = None) -> JSONResponse:
    content = {
        'success': False,
        'error': message,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    if details:
        content['details'] = details
    return JSONResponse(status_code=status_code, content=content)

class CleanupRequest(BaseModel):
    days: int = 90


@router.get("/all")
async def get_all_history(limit: int = Query(100, le=500, ge=1), offset: int = Query(0, ge=0)):
    """
    Get all analysis history with pagination.
    """
    try:
        logger.info("history_request | limit=%d | offset=%d", limit, offset)
        
        # Async wrap the blocking DB call
        records = await asyncio.to_thread(AnalysisHistory.get_all, limit=limit, offset=offset)
        
        return _success_response({
            'total_records': len(records),
            'limit': limit,
            'offset': offset,
            'records': records
        }, 200)
    except Exception as e:
        logger.error("history_endpoint_error | error=%s", str(e))
        return _error_response("Failed to retrieve history", 500)


@router.get("/by-type/{analysis_type}")
async def get_history_by_type(
    analysis_type: str, 
    limit: int = Query(100, le=500, ge=1), 
    offset: int = Query(0, ge=0)
):
    """
    Get analysis history by type.
    """
    try:
        valid_types = ['url', 'image', 'text']
        if analysis_type not in valid_types:
            return _error_response(f"Invalid analysis type. Must be one of: {', '.join(valid_types)}", 400)
            
        logger.info("history_by_type_request | type=%s | limit=%d", analysis_type, limit)
        records = await asyncio.to_thread(AnalysisHistory.get_by_type, analysis_type, limit=limit, offset=offset)
        
        return _success_response({
            'type': analysis_type,
            'total_records': len(records),
            'limit': limit,
            'offset': offset,
            'records': records
        }, 200)
    except Exception as e:
        logger.error("history_by_type_error | error=%s", str(e))
        return _error_response("Failed to retrieve history", 500)


@router.get("/by-risk/{risk_level}")
async def get_history_by_risk(
    risk_level: str, 
    limit: int = Query(100, le=500, ge=1), 
    offset: int = Query(0, ge=0)
):
    """
    Get analysis history by risk level.
    """
    try:
        valid_levels = ['low', 'medium', 'high']
        if risk_level not in valid_levels:
            return _error_response(f"Invalid risk level. Must be one of: {', '.join(valid_levels)}", 400)
            
        logger.info("history_by_risk_request | risk=%s | limit=%d", risk_level, limit)
        records = await asyncio.to_thread(AnalysisHistory.get_by_risk_level, risk_level, limit=limit, offset=offset)
        
        return _success_response({
            'risk_level': risk_level,
            'total_records': len(records),
            'limit': limit,
            'offset': offset,
            'records': records
        }, 200)
    except Exception as e:
        logger.error("history_by_risk_error | error=%s", str(e))
        return _error_response("Failed to retrieve history", 500)


@router.get("/record/{record_id}")
async def get_record(record_id: int):
    """
    Get specific analysis record by ID.
    """
    try:
        logger.info("record_request | id=%d", record_id)
        record = await asyncio.to_thread(AnalysisHistory.get_by_id, record_id)
        
        if not record:
            return _error_response("Record not found", 404)
            
        return _success_response({'record': record}, 200)
    except Exception as e:
        logger.error("record_endpoint_error | error=%s", str(e))
        return _error_response("Failed to retrieve record", 500)


@router.get("/statistics")
async def get_statistics():
    """
    Get analysis statistics and summary.
    """
    try:
        logger.info("statistics_request")
        stats = await asyncio.to_thread(AnalysisHistory.get_stats)
        
        return _success_response({
            'statistics': stats,
            'generated_at': datetime.utcnow().isoformat() + 'Z'
        }, 200)
    except Exception as e:
        logger.error("statistics_endpoint_error | error=%s", str(e))
        return _error_response("Failed to retrieve statistics", 500)


@router.post("/cleanup")
async def cleanup_old_records(request: CleanupRequest):
    """
    Delete analysis records older than specified days.
    """
    try:
        days = request.days
        if days > 365 or days < 1:
            return _error_response("Days must be between 1 and 365", 400)
            
        logger.info("cleanup_request | days=%d", days)
        deleted_count = await asyncio.to_thread(AnalysisHistory.delete_old_records, days)
        
        return _success_response({
            'deleted_records': deleted_count,
            'older_than_days': days
        }, 200)
    except Exception as e:
        logger.error("cleanup_endpoint_error | error=%s", str(e))
        return _error_response("Cleanup failed", 500)

"""
Analysis history endpoints.

HTTP routes for retrieving analysis history and statistics.
"""

from flask import Blueprint, request, jsonify
from datetime import datetime

from utils.logger import logger
from ml.url.db import AnalysisHistory

history_bp = Blueprint('history', __name__, url_prefix='/api/history')


def _success_response(data, status=200):
    """Format success response."""
    return jsonify({
        'success': True,
        'data': data,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), status


def _error_response(message, status=400, details=None):
    """Format error response."""
    response = {
        'success': False,
        'error': message,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    if details:
        response['details'] = details
    return jsonify(response), status


@history_bp.route('/all', methods=['GET'])
def get_all_history():
    """
    Get all analysis history with pagination.
    
    Query parameters:
        limit: Number of records (default: 100, max: 500)
        offset: Records to skip (default: 0)
    
    Returns:
        JSON: List of analysis records
    """
    try:
        # Get pagination parameters
        limit = min(int(request.args.get('limit', 100)), 500)
        offset = int(request.args.get('offset', 0))
        
        if limit < 1:
            return _error_response("limit must be >= 1", 400)
        
        if offset < 0:
            return _error_response("offset must be >= 0", 400)
        
        logger.info("history_request | limit=%d | offset=%d", limit, offset)
        
        # Get records
        records = AnalysisHistory.get_all(limit=limit, offset=offset)
        
        return _success_response({
            'total_records': len(records),
            'limit': limit,
            'offset': offset,
            'records': records
        }, 200)
        
    except Exception as e:
        logger.error("history_endpoint_error | error=%s", str(e))
        return _error_response("Failed to retrieve history", 500)


@history_bp.route('/by-type/<analysis_type>', methods=['GET'])
def get_history_by_type(analysis_type):
    """
    Get analysis history by type.
    
    Path parameters:
        analysis_type: Type of analysis (url, image, text)
    
    Query parameters:
        limit: Number of records (default: 100)
        offset: Records to skip (default: 0)
    
    Returns:
        JSON: List of analysis records
    """
    try:
        # Validate analysis type
        valid_types = ['url', 'image', 'text']
        if analysis_type not in valid_types:
            return _error_response(
                f"Invalid analysis type. Must be one of: {', '.join(valid_types)}",
                400
            )
        
        # Get pagination parameters
        limit = min(int(request.args.get('limit', 100)), 500)
        offset = int(request.args.get('offset', 0))
        
        logger.info("history_by_type_request | type=%s | limit=%d", analysis_type, limit)
        
        # Get records
        records = AnalysisHistory.get_by_type(analysis_type, limit=limit, offset=offset)
        
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


@history_bp.route('/by-risk/<risk_level>', methods=['GET'])
def get_history_by_risk(risk_level):
    """
    Get analysis history by risk level.
    
    Path parameters:
        risk_level: Risk level (low, medium, high)
    
    Query parameters:
        limit: Number of records (default: 100)
        offset: Records to skip (default: 0)
    
    Returns:
        JSON: List of analysis records
    """
    try:
        # Validate risk level
        valid_levels = ['low', 'medium', 'high']
        if risk_level not in valid_levels:
            return _error_response(
                f"Invalid risk level. Must be one of: {', '.join(valid_levels)}",
                400
            )
        
        # Get pagination parameters
        limit = min(int(request.args.get('limit', 100)), 500)
        offset = int(request.args.get('offset', 0))
        
        logger.info("history_by_risk_request | risk=%s | limit=%d", risk_level, limit)
        
        # Get records
        records = AnalysisHistory.get_by_risk_level(risk_level, limit=limit, offset=offset)
        
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


@history_bp.route('/record/<int:record_id>', methods=['GET'])
def get_record(record_id):
    """
    Get specific analysis record by ID.
    
    Path parameters:
        record_id: ID of the analysis record
    
    Returns:
        JSON: Analysis record details
    """
    try:
        logger.info("record_request | id=%d", record_id)
        
        # Get record
        record = AnalysisHistory.get_by_id(record_id)
        
        if not record:
            return _error_response("Record not found", 404)
        
        return _success_response({
            'record': record
        }, 200)
        
    except Exception as e:
        logger.error("record_endpoint_error | error=%s", str(e))
        return _error_response("Failed to retrieve record", 500)


@history_bp.route('/statistics', methods=['GET'])
def get_statistics():
    """
    Get analysis statistics and summary.
    
    Returns:
        JSON: Statistics summary
    """
    try:
        logger.info("statistics_request")
        
        # Get statistics
        stats = AnalysisHistory.get_stats()
        
        return _success_response({
            'statistics': stats,
            'generated_at': datetime.utcnow().isoformat() + 'Z'
        }, 200)
        
    except Exception as e:
        logger.error("statistics_endpoint_error | error=%s", str(e))
        return _error_response("Failed to retrieve statistics", 500)


@history_bp.route('/cleanup', methods=['POST'])
def cleanup_old_records():
    """
    Delete analysis records older than specified days.
    
    Request body:
        {
            "days": 90
        }
    
    Returns:
        JSON: Number of deleted records
    """
    try:
        # Validate request
        data = request.get_json(silent=True) or {}
        days = data.get('days', 90)
        
        if not isinstance(days, int) or days < 1:
            return _error_response("days must be a positive integer", 400)
        
        if days > 365:
            return _error_response("Maximum 365 days", 400)
        
        logger.info("cleanup_request | days=%d", days)
        
        # Delete old records
        deleted_count = AnalysisHistory.delete_old_records(days)
        
        return _success_response({
            'deleted_records': deleted_count,
            'older_than_days': days
        }, 200)
        
    except Exception as e:
        logger.error("cleanup_endpoint_error | error=%s", str(e))
        return _error_response("Cleanup failed", 500)

"""
Health check endpoint.

Provides service health and status information.
"""

from datetime import datetime
from flask import Blueprint, jsonify

from utils.logger import logger

health_bp = Blueprint('health', __name__, url_prefix='/api')


@health_bp.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint.
    
    Returns:
        JSON: Service status and information
    """
    try:
        logger.info("health_check_requested")
        
        return jsonify({
            'status': 'healthy',
            'service': 'AI Scam Detector API',
            'version': '2.0.0',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'components': {
                'api': 'operational',
                'database': 'operational',
                'models': 'loaded'
            }
        }), 200
        
    except Exception as e:
        logger.error("health_check_failed | error=%s", str(e))
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 500


@health_bp.route('/version', methods=['GET'])
def get_version():
    """
    Get API version.
    
    Returns:
        JSON: Version information
    """
    return jsonify({
        'version': '2.0.0',
        'api': 'AI Scam Detector API',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), 200

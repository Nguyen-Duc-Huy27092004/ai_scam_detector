"""
Text analysis endpoints.

HTTP routes for text scam detection.
"""

from flask import Blueprint, request, jsonify
from datetime import datetime

from utils.logger import logger
from utils.validators import validate_text_input, validate_json_request
from services.text_pipeline import analyze_text

text_bp = Blueprint('text', __name__, url_prefix='/api/text')


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


@text_bp.route('/analyze', methods=['POST'])
def analyze_text_endpoint():
    """
    Analyze text for scam indicators.
    
    Request body:
        {
            "text": "Your text to analyze..."
        }
    
    Returns:
        JSON: Text analysis result
    """
    try:
        # Validate request
        data = request.get_json(silent=True) or {}
        is_valid, error_msg = validate_json_request(data, ['text'])
        
        if not is_valid:
            return _error_response(error_msg, 400)
        
        text = data.get('text', '').strip()
        
        # Validate text input
        is_valid, error_msg = validate_text_input(text)
        if not is_valid:
            return _error_response(error_msg, 400)
        
        logger.info("text_analysis_requested | length=%d", len(text))
        
        # Perform analysis
        result = analyze_text(text)
        
        # Check for errors in analysis
        if result.get('status') == 'error':
            logger.error("text_analysis_error | error=%s", result.get('error'))
            return _error_response(
                "Analysis failed",
                500,
                {'error': result.get('error')}
            )
        
        # Build response
        response_data = {
            'text_preview': text[:100] + ('...' if len(text) > 100 else ''),
            'text_length': len(text),
            'analysis': {
                'risk_level': result.get('risk_level'),
                'overall_score': result.get('overall_score'),
                'label': result.get('label'),
                'confidence': result.get('classification', {}).get('confidence'),
            },
            'details': {
                'classification': result.get('classification'),
                'keywords_found': result.get('keywords', []),
            },
            'advice': result.get('advice'),
            'recommendations': result.get('recommendations', []),
            'risk_factors': result.get('risk_factors', []),
            'record_id': result.get('record_id')
        }
        
        return _success_response(response_data, 200)
        
    except Exception as e:
        logger.exception("text_endpoint_error | error=%s", str(e))
        return _error_response("Internal server error", 500)


@text_bp.route('/batch-analyze', methods=['POST'])
def batch_analyze_texts():
    """
    Analyze multiple text samples.
    
    Request body:
        {
            "texts": ["Text 1...", "Text 2..."]
        }
    
    Returns:
        JSON: List of analysis results
    """
    try:
        data = request.get_json(silent=True) or {}
        is_valid, error_msg = validate_json_request(data, ['texts'])
        
        if not is_valid:
            return _error_response(error_msg, 400)
        
        texts = data.get('texts', [])
        
        if not isinstance(texts, list):
            return _error_response("texts must be a list", 400)
        
        if len(texts) == 0:
            return _error_response("texts list cannot be empty", 400)
        
        if len(texts) > 50:
            return _error_response("Maximum 50 texts per batch", 400)
        
        # Validate all texts
        invalid_texts = []
        for i, text in enumerate(texts):
            is_valid, _ = validate_text_input(text)
            if not is_valid:
                invalid_texts.append(i)
        
        if invalid_texts:
            return _error_response(
                "Some texts are invalid",
                400,
                {'invalid_indices': invalid_texts[:5]}
            )
        
        logger.info("batch_text_analysis_requested | count=%d", len(texts))
        
        # Analyze all texts
        results = []
        for i, text in enumerate(texts):
            try:
                result = analyze_text(text)
                results.append({
                    'index': i,
                    'text_length': len(text),
                    'risk_level': result.get('risk_level'),
                    'overall_score': result.get('overall_score'),
                    'confidence': result.get('classification', {}).get('confidence'),
                    'keywords': result.get('keywords', []),
                    'record_id': result.get('record_id'),
                    'status': result.get('status')
                })
            except Exception as e:
                logger.error("batch_text_failed | index=%d | error=%s", i, str(e))
                results.append({
                    'index': i,
                    'error': str(e),
                    'status': 'error'
                })
        
        return _success_response({
            'total': len(texts),
            'completed': sum(1 for r in results if r.get('status') != 'error'),
            'results': results
        }, 200)
        
    except Exception as e:
        logger.exception("batch_text_endpoint_error | error=%s", str(e))
        return _error_response("Internal server error", 500)


@text_bp.route('/keywords', methods=['GET'])
def get_suspicious_keywords():
    """
    Get list of suspicious keywords used in analysis.
    
    Returns:
        JSON: List of keywords by category
    """
    try:
        from ml.text.text_classifier import TextScamClassifier
        
        keywords_by_weight = {}
        for keyword, weight in TextScamClassifier.SCAM_KEYWORDS.items():
            if weight not in keywords_by_weight:
                keywords_by_weight[weight] = []
            keywords_by_weight[weight].append(keyword)
        
        return _success_response({
            'keywords_by_weight': keywords_by_weight,
            'total_keywords': len(TextScamClassifier.SCAM_KEYWORDS)
        }, 200)
        
    except Exception as e:
        logger.error("keywords_endpoint_error | error=%s", str(e))
        return _error_response("Failed to retrieve keywords", 500)

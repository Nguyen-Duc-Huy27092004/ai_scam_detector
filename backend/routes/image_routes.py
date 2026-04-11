"""
Image analysis endpoints.

HTTP routes for image scam detection.
"""

from flask import Blueprint, request, jsonify
from pathlib import Path
from datetime import datetime

from utils.logger import logger
from utils.validators import validate_image_upload, validate_json_request
from utils.file_utils import save_uploaded_file
from config import SCREENSHOTS_DIR, MAX_IMAGE_SIZE_BYTES
from services.image_pipeline import analyze_image

image_bp = Blueprint('image', __name__, url_prefix='/api/image')


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


@image_bp.route('/analyze', methods=['POST'])
def analyze_image_endpoint():
    """
    Analyze uploaded image for scams.
    
    Form data:
        image: Image file (JPEG, PNG, GIF, WebP)
    
    Returns:
        JSON: Image analysis result
    """
    try:
        # Check if file is present
        if 'image' not in request.files:
            return _error_response("No image file provided", 400)
        
        file = request.files['image']
        
        # Validate file
        is_valid, error_msg = validate_image_upload(file)
        if not is_valid:
            return _error_response(error_msg, 400)
        
        # Check file size
        if len(file.read()) > MAX_IMAGE_SIZE_BYTES:
            return _error_response(
                f"File size exceeds maximum of {MAX_IMAGE_SIZE_BYTES / (1024*1024):.1f}MB",
                413
            )
        file.seek(0)  # Reset file pointer
        
        logger.info("image_analysis_requested | filename=%s", file.filename)
        
        # Save uploaded file
        image_path = save_uploaded_file(file, SCREENSHOTS_DIR)
        if not image_path:
            return _error_response("Failed to save image file", 500)
        
        # Perform analysis
        result = analyze_image(image_path)
        
        # Check for errors in analysis
        if result.get('status') == 'error':
            logger.error("image_analysis_error | error=%s", result.get('error'))
            return _error_response(
                "Analysis failed",
                500,
                {'error': result.get('error')}
            )
        
        # Build response
        response_data = {
            'filename': file.filename,
            'image_path': image_path,
            'analysis': {
                'risk_level': result.get('risk_level'),
                'overall_score': result.get('overall_score'),
                'label': result.get('label'),
                'confidence': result.get('image_prediction', {}).get('confidence'),
            },
            'details': {
                'image_prediction': result.get('image_prediction'),
                'ocr_metadata': result.get('ocr_metadata'),
                'text_analysis': result.get('text_analysis'),
            },
            'ocr_text': result.get('ocr_text', '')[:500],  # Limit length
            'advice': result.get('advice'),
            'recommendations': result.get('recommendations', []),
            'risk_factors': result.get('risk_factors', []),
            'record_id': result.get('record_id')
        }
        
        return _success_response(response_data, 200)
        
    except Exception as e:
        logger.exception("image_endpoint_error | error=%s", str(e))
        return _error_response("Internal server error", 500)


@image_bp.route('/batch-analyze', methods=['POST'])
def batch_analyze_images():
    """
    Analyze multiple image files.
    
    Form data:
        images: Multiple image files
    
    Returns:
        JSON: List of analysis results
    """
    try:
        if 'images' not in request.files:
            return _error_response("No images provided", 400)
        
        files = request.files.getlist('images')
        
        if len(files) == 0:
            return _error_response("At least one image required", 400)
        
        if len(files) > 20:
            return _error_response("Maximum 20 images per batch", 400)
        
        logger.info("batch_image_analysis_requested | count=%d", len(files))
        
        # Analyze all images
        results = []
        for file in files:
            try:
                # Validate file
                is_valid, error_msg = validate_image_upload(file)
                if not is_valid:
                    results.append({
                        'filename': file.filename,
                        'error': error_msg,
                        'status': 'error'
                    })
                    continue
                
                # Save and analyze
                image_path = save_uploaded_file(file, SCREENSHOTS_DIR)
                if not image_path:
                    results.append({
                        'filename': file.filename,
                        'error': 'Failed to save file',
                        'status': 'error'
                    })
                    continue
                
                result = analyze_image(image_path)
                results.append({
                    'filename': file.filename,
                    'risk_level': result.get('risk_level'),
                    'overall_score': result.get('overall_score'),
                    'record_id': result.get('record_id'),
                    'status': result.get('status')
                })
                
            except Exception as e:
                logger.error("batch_image_failed | filename=%s | error=%s", file.filename, str(e))
                results.append({
                    'filename': file.filename,
                    'error': str(e),
                    'status': 'error'
                })
        
        return _success_response({
            'total': len(files),
            'completed': sum(1 for r in results if r.get('status') != 'error'),
            'results': results
        }, 200)
        
    except Exception as e:
        logger.exception("batch_image_endpoint_error | error=%s", str(e))
        return _error_response("Internal server error", 500)

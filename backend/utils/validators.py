"""
Input validation utilities.

Provides validation functions for various input types.
"""

import re
from pathlib import Path
from urllib.parse import urlparse
from config import MIN_URL_LENGTH, MAX_URL_LENGTH, ALLOWED_IMAGE_EXTENSIONS
from utils.logger import logger


def is_valid_url(url):
    """
    Validate URL format and structure.
    
    Args:
        url: URL string to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not url or not isinstance(url, str):
        return False
    
    url = url.strip()
    
    # Check length
    if not (MIN_URL_LENGTH <= len(url) <= MAX_URL_LENGTH):
        logger.debug("url_validation_failed | reason=length | url_length=%d", len(url))
        return False
    
    # Check basic URL pattern
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IPv4
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if not url_pattern.match(url):
        logger.debug("url_validation_failed | reason=pattern | url=%s", url[:50])
        return False
    
    try:
        result = urlparse(url)
        # Check required components
        if not all([result.scheme, result.netloc]):
            logger.debug("url_validation_failed | reason=components | url=%s", url[:50])
            return False
    except Exception as e:
        logger.debug("url_validation_failed | reason=parse_error | error=%s", str(e))
        return False
    
    return True


def validate_image_upload(file):
    """
    Validate uploaded image file.
    
    Args:
        file: Flask file object
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not file:
        return False, "No file provided"
    
    if not file.filename:
        return False, "No filename"
    
    # Check file extension
    file_ext = Path(file.filename).suffix.lower().lstrip('.')
    if file_ext not in ALLOWED_IMAGE_EXTENSIONS:
        return False, f"Invalid file extension. Allowed: {', '.join(ALLOWED_IMAGE_EXTENSIONS)}"
    
    # Check file size (Flask limits request size)
    # Additional size check can be done here if needed
    
    return True, None


def validate_text_input(text):
    """
    Validate text input for analysis.
    
    Args:
        text: Text string to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not text or not isinstance(text, str):
        return False, "Text input is required"
    
    text = text.strip()
    
    if len(text) < 10:
        return False, "Text must be at least 10 characters"
    
    if len(text) > 10000:
        return False, "Text must not exceed 10000 characters"
    
    return True, None


def sanitize_filename(filename):
    """
    Sanitize filename to prevent directory traversal attacks.
    
    Args:
        filename: Original filename
        
    Returns:
        str: Sanitized filename
    """
    # Remove path separators and suspicious characters
    dangerous_chars = ['/', '\\', '..', '\0', '\n', '\r']
    for char in dangerous_chars:
        filename = filename.replace(char, '')
    
    return filename


def validate_json_request(data, required_fields):
    """
    Validate JSON request data.
    
    Args:
        data: JSON data dictionary
        required_fields: List of required field names
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not data or not isinstance(data, dict):
        return False, "Invalid JSON request"
    
    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"
        
        if data[field] is None:
            return False, f"Field '{field}' cannot be null"
    
    return True, None

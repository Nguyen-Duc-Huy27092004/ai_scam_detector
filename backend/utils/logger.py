"""
Logging configuration module.

Provides centralized logging setup and logger instances.
"""

import logging
import logging.handlers
from pathlib import Path
from config import LOG_FILE, LOG_LEVEL, LOG_FORMAT, LOG_MAX_BYTES, LOG_BACKUP_COUNT

# Ensure log directory exists
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


def setup_logging(level=LOG_LEVEL):
    """
    Configure logging for the application.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatters
    formatter = logging.Formatter(LOG_FORMAT)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        str(LOG_FILE),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)


def get_logger(name):
    """
    Get a logger instance for a module.
    
    Args:
        name: Module name (typically __name__)
        
    Returns:
        logging.Logger: Configured logger instance
    """
    return logging.getLogger(name)


# Create module logger
logger = get_logger(__name__)


def log_analysis_request(analysis_type, input_value):
    """
    Log an analysis request with masking for sensitive data.
    
    Args:
        analysis_type: Type of analysis (url, image, text)
        input_value: The input being analyzed
    """
    if analysis_type == "url":
        masked_value = input_value[:50] + "..." if len(input_value) > 50 else input_value
    else:
        masked_value = f"{analysis_type}_{len(str(input_value))}_bytes"
    
    logger.info("analysis_request | type=%s | input=%s", analysis_type, masked_value)


def log_analysis_result(analysis_type, risk_level, confidence):
    """
    Log an analysis result.
    
    Args:
        analysis_type: Type of analysis
        risk_level: Calculated risk level
        confidence: Model confidence score
    """
    logger.info(
        "analysis_result | type=%s | risk_level=%s | confidence=%.2f",
        analysis_type,
        risk_level,
        confidence
    )

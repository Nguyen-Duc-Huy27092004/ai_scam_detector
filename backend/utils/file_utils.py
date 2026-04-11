"""
File utilities for handling file operations.

Provides helper functions for file management and cleanup.
"""

import os
import hashlib
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
from utils.logger import logger


def save_uploaded_file(file, upload_dir: Path, max_age_days: int = 30) -> Optional[str]:
    """
    Save uploaded file with unique naming and cleanup of old files.
    
    Args:
        file: Flask file object
        upload_dir: Directory to save file
        max_age_days: Remove files older than this
        
    Returns:
        str: Path to saved file or None if failed
    """
    try:
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_hash = hashlib.md5(file.read()).hexdigest()[:8]
        file.seek(0)  # Reset file pointer
        
        file_ext = Path(file.filename).suffix
        unique_filename = f"{timestamp}_{file_hash}{file_ext}"
        file_path = upload_dir / unique_filename
        
        # Save file
        file.save(str(file_path))
        logger.info("file_saved | path=%s", unique_filename)
        
        # Cleanup old files
        cleanup_old_files(upload_dir, max_age_days)
        
        return str(file_path)
        
    except Exception as e:
        logger.error("file_save_failed | error=%s", str(e))
        return None


def cleanup_old_files(directory: Path, max_age_days: int = 30):
    """
    Remove files older than specified days from directory.
    
    Args:
        directory: Directory to clean
        max_age_days: Remove files older than this many days
    """
    try:
        cutoff_time = datetime.now() - timedelta(days=max_age_days)
        
        for file_path in directory.glob("*"):
            if file_path.is_file():
                file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                if file_mtime < cutoff_time:
                    file_path.unlink()
                    logger.debug("old_file_removed | file=%s", file_path.name)
    except Exception as e:
        logger.warning("cleanup_failed | error=%s", str(e))


def load_json_file(file_path: Path) -> Optional[dict]:
    """
    Load JSON file safely.
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        dict: Parsed JSON or None if failed
    """
    try:
        if file_path.exists():
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.error("json_load_failed | file=%s | error=%s", file_path, str(e))
    
    return None


def save_json_file(data: dict, file_path: Path) -> bool:
    """
    Save data as JSON file safely.
    
    Args:
        data: Dictionary to save
        file_path: Path to save to
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error("json_save_failed | file=%s | error=%s", file_path, str(e))
        return False


def get_file_size_mb(file_path: Path) -> float:
    """
    Get file size in megabytes.
    
    Args:
        file_path: Path to file
        
    Returns:
        float: File size in MB
    """
    try:
        return file_path.stat().st_size / (1024 * 1024)
    except Exception:
        return 0.0

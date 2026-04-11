"""
File utilities for handling file operations.

Provides helper functions for file management, saving uploads, and cleanup.

Public API
----------
save_uploaded_bytes(data, filename, upload_dir)  → str | None  (FastAPI-style)
save_uploaded_file(file, upload_dir)             → str | None  (Flask-style, legacy)
cleanup_old_files(directory, max_age_days)
load_json_file(file_path)                        → dict | None
save_json_file(data, file_path)                  → bool
get_file_size_mb(file_path)                      → float
"""

import os
import hashlib
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

from utils.logger import logger


# ---------------------------------------------------------------------------
# FastAPI-compatible helper (accepts raw bytes)
# ---------------------------------------------------------------------------

def save_uploaded_bytes(
    data: bytes,
    filename: str,
    upload_dir: Path,
    max_age_days: int = 30,
) -> Optional[str]:
    """
    Save raw bytes from a FastAPI ``UploadFile`` with unique naming.

    Args:
        data: Raw file bytes (from ``await upload_file.read()``)
        filename: Original filename (used for extension only)
        upload_dir: Directory to save file
        max_age_days: Trigger cleanup of files older than this many days

    Returns:
        str: Absolute path to the saved file, or None on error
    """
    try:
        upload_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_hash = hashlib.md5(data).hexdigest()[:8]
        file_ext = Path(filename).suffix
        unique_filename = f"{timestamp}_{file_hash}{file_ext}"
        file_path = upload_dir / unique_filename

        file_path.write_bytes(data)
        logger.info("file_saved | path=%s", unique_filename)

        cleanup_old_files(upload_dir, max_age_days)
        return str(file_path)

    except Exception as e:
        logger.error("save_uploaded_bytes_failed | error=%s", str(e))
        return None


# ---------------------------------------------------------------------------
# Legacy Flask-style helper (accepts file-like objects)
# ---------------------------------------------------------------------------

def save_uploaded_file(file, upload_dir: Path, max_age_days: int = 30) -> Optional[str]:
    """
    Save a Flask-style uploaded file object with unique naming.

    .. deprecated::
        Use :func:`save_uploaded_bytes` for FastAPI ``UploadFile`` objects.
        This function expects a Flask ``FileStorage``-like object with
        ``.read()``, ``.seek()``, ``.save()`` and ``.filename`` attributes.

    Returns:
        str: Absolute path to the saved file, or None on error
    """
    try:
        upload_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        raw = file.read()
        file_hash = hashlib.md5(raw).hexdigest()[:8]
        file.seek(0)

        file_ext = Path(file.filename).suffix
        unique_filename = f"{timestamp}_{file_hash}{file_ext}"
        file_path = upload_dir / unique_filename

        file.save(str(file_path))
        logger.info("file_saved | path=%s", unique_filename)

        cleanup_old_files(upload_dir, max_age_days)
        return str(file_path)

    except Exception as e:
        logger.error("file_save_failed | error=%s", str(e))
        return None


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def cleanup_old_files(directory: Path, max_age_days: int = 30) -> None:
    """Remove files older than *max_age_days* from *directory*."""
    try:
        cutoff = datetime.now() - timedelta(days=max_age_days)
        for fp in directory.glob("*"):
            if fp.is_file():
                mtime = datetime.fromtimestamp(fp.stat().st_mtime)
                if mtime < cutoff:
                    fp.unlink()
                    logger.debug("old_file_removed | file=%s", fp.name)
    except Exception as e:
        logger.warning("cleanup_failed | error=%s", str(e))


def load_json_file(file_path: Path) -> Optional[dict]:
    """Load and parse a JSON file; returns None on failure."""
    try:
        if file_path.exists():
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.error("json_load_failed | file=%s | error=%s", file_path, str(e))
    return None


def save_json_file(data: dict, file_path: Path) -> bool:
    """Serialize *data* to *file_path* as pretty-printed JSON; returns success flag."""
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error("json_save_failed | file=%s | error=%s", file_path, str(e))
        return False


def get_file_size_mb(file_path: Path) -> float:
    """Return the size of *file_path* in megabytes (0.0 on error)."""
    try:
        return file_path.stat().st_size / (1024 * 1024)
    except Exception:
        return 0.0

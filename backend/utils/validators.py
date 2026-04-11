"""
Input validation utilities — FastAPI + Flask compatible.

Public API
----------
is_valid_url(url)                       → bool
validate_text_input(text)               → (bool, str | None)
validate_json_request(data, fields)     → (bool, str | None)
sanitize_filename(filename)             → str

FastAPI helpers (UploadFile-aware)
----------------------------------
validate_image_file(filename, size_bytes) → (bool, str | None)
"""

import re
from pathlib import Path
from urllib.parse import urlparse
from typing import Tuple, Optional

from utils.config import (
    MIN_URL_LENGTH,
    MAX_URL_LENGTH,
    ALLOWED_IMAGE_EXTENSIONS,
    MAX_IMAGE_SIZE_MB,
)
from utils.logger import logger


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------

_URL_RE = re.compile(
    r"^https?://"
    r"(?:(?:[A-Z0-9](?:[A-Z0-9\-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"   # domain
    r"localhost|"                                                          # localhost
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"                              # IPv4
    r"(?::\d+)?"                                                           # port
    r"(?:/?|[/?]\S+)$",
    re.IGNORECASE,
)


def is_valid_url(url: object) -> bool:
    """Return True if *url* is a well-formed http/https URL within length limits."""
    if not url or not isinstance(url, str):
        return False

    url = url.strip()

    if not (MIN_URL_LENGTH <= len(url) <= MAX_URL_LENGTH):
        logger.debug("url_validation_failed | reason=length | len=%d", len(url))
        return False

    if not _URL_RE.match(url):
        logger.debug("url_validation_failed | reason=pattern | url=%.50s", url)
        return False

    try:
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            logger.debug("url_validation_failed | reason=components | url=%.50s", url)
            return False
    except Exception as exc:
        logger.debug("url_validation_failed | reason=parse_error | error=%s", str(exc))
        return False

    return True


# ---------------------------------------------------------------------------
# Image validation — generic (works with filename + size in bytes)
# ---------------------------------------------------------------------------

def validate_image_file(
    filename: Optional[str],
    size_bytes: int = 0,
) -> Tuple[bool, Optional[str]]:
    """
    Validate an uploaded image by filename extension and file size.

    Compatible with both FastAPI (UploadFile.filename) and plain strings.

    Returns:
        (True, None)            – valid
        (False, error_message)  – invalid
    """
    if not filename:
        return False, "No filename provided"

    ext = Path(filename).suffix.lower().lstrip(".")
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        return False, (
            f"Invalid file type '.{ext}'. "
            f"Allowed: {', '.join(sorted(ALLOWED_IMAGE_EXTENSIONS))}"
        )

    max_bytes = MAX_IMAGE_SIZE_MB * 1024 * 1024
    if size_bytes > max_bytes:
        return False, f"File size exceeds maximum of {MAX_IMAGE_SIZE_MB} MB"

    return True, None


# ---------------------------------------------------------------------------
# Image validation — legacy Flask-style (accepts file-like objects)
# ---------------------------------------------------------------------------

def validate_image_upload(file: object, actual_size: int = 0) -> Tuple[bool, Optional[str]]:
    """
    Validate a Flask-style uploaded file object.

    Kept for backward compatibility. New code should prefer
    validate_image_file(filename, size_bytes).
    """
    if file is None:
        return False, "No file provided"

    filename = getattr(file, "filename", None)
    return validate_image_file(filename, actual_size)


# ---------------------------------------------------------------------------
# Text validation
# ---------------------------------------------------------------------------

def validate_text_input(text: object) -> Tuple[bool, Optional[str]]:
    """Return (True, None) for valid text, (False, error) otherwise."""
    if not text or not isinstance(text, str):
        return False, "Text input is required"

    text = text.strip()

    if len(text) < 10:
        return False, "Text must be at least 10 characters"

    if len(text) > 10_000:
        return False, "Text must not exceed 10,000 characters"

    return True, None


# ---------------------------------------------------------------------------
# JSON request validation
# ---------------------------------------------------------------------------

def validate_json_request(
    data: object,
    required_fields: list,
) -> Tuple[bool, Optional[str]]:
    """Check that *data* is a dict and all *required_fields* are present and non-null."""
    if not data or not isinstance(data, dict):
        return False, "Invalid JSON request body"

    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: '{field}'"
        if data[field] is None:
            return False, f"Field '{field}' must not be null"

    return True, None


# ---------------------------------------------------------------------------
# Filename sanitisation
# ---------------------------------------------------------------------------

def sanitize_filename(filename: str) -> str:
    """Remove path traversal characters and other dangerous sequences."""
    dangerous = ["/", "\\", "..", "\0", "\n", "\r", "\t"]
    for ch in dangerous:
        filename = filename.replace(ch, "")
    return filename

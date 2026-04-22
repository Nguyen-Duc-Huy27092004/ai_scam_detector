"""Model file integrity and permission checks before loading serialized ML artifacts."""

from __future__ import annotations

import hashlib
import stat
from pathlib import Path
from typing import Optional

from utils.logger import logger


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_sha256(path: Path, expected_hex: str) -> bool:
    if not expected_hex or not expected_hex.strip():
        return True
    expected = expected_hex.strip().lower()
    actual = compute_sha256(path).lower()
    if actual != expected:
        logger.critical(
            "model_integrity_FAIL | path=%s | expected=%s | got=%s",
            path,
            expected[:16],
            actual[:16],
        )
        return False
    logger.info("model_integrity_ok | path=%s", path)
    return True


def assert_not_world_writable(path: Path) -> None:
    """Refuse to load model files that are world-writable (tampering indicator)."""
    if not path.exists():
        return
    mode = path.stat().st_mode
    if mode & stat.S_IWOTH:
        raise PermissionError(
            f"Model file is world-writable (refusing to load): {path}"
        )


def assert_readable_model_file(path: Path, name: str = "model") -> None:
    assert_not_world_writable(path)


def optional_verify_before_load(
    path: Path,
    expected_sha256: Optional[str],
    *,
    name: str = "model",
) -> bool:
    """
    If expected_sha256 is set, verify hash. Always check world-writable bit.
    Returns False if verification fails (caller should skip load).
    """
    if not path.exists():
        return True
    try:
        assert_not_world_writable(path)
    except PermissionError as e:
        logger.critical("model_permission_denied | %s", e)
        return False
    if expected_sha256 and not verify_sha256(path, expected_sha256):
        return False
    return True

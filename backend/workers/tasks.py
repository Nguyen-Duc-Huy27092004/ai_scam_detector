"""
Background task workers using a shared ThreadPoolExecutor.

These helpers submit CPU/IO-bound work to a thread pool so the FastAPI
event loop is not blocked.  They are thin wrappers that keep the error
handling uniform and ensure the executor is shared across the process.

If a Celery-based distributed queue is needed in the future, replace the
_EXECUTOR.submit() calls with Celery task decorators pointing to the same
underlying service functions.
"""

from concurrent.futures import ThreadPoolExecutor, Future
from typing import Dict, Any

from services.url_pipeline import URLAnalysisPipeline
from services.file_analyzer import FileAnalyzer
from services.network_analyzer import NetworkAnalyzer
from utils.logger import logger


# Shared pool — size tuned so heavy tasks (ML inference, crawling) don't
# starve lightweight tasks.  Adjust via the WORKER_THREADS env variable
# if needed.
import os
_POOL_SIZE = int(os.getenv("WORKER_THREADS", "5"))
_EXECUTOR = ThreadPoolExecutor(max_workers=_POOL_SIZE, thread_name_prefix="scam_worker")


# ---------------------------------------------------------------------------
# Task implementations
# ---------------------------------------------------------------------------

def analyze_url_task(url: str) -> Dict[str, Any]:
    """Run the full URL analysis pipeline synchronously (for thread use)."""
    try:
        return URLAnalysisPipeline.analyze(url)
    except Exception as e:
        logger.error("url_task_failed | url=%.80s | error=%s", url, str(e))
        return {"status": "error", "error": str(e), "url": url}


def analyze_file_task(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """Analyse a file for malicious indicators."""
    try:
        return FileAnalyzer.analyze(file_bytes, filename)
    except Exception as e:
        logger.error("file_task_failed | filename=%s | error=%s", filename, str(e))
        return {"status": "error", "error": str(e), "filename": filename}


def analyze_network_task(url: str) -> Dict[str, Any]:
    """Perform DNS/SSL/port analysis for a URL."""
    try:
        return NetworkAnalyzer.analyze(url)
    except Exception as e:
        logger.error("network_task_failed | url=%.80s | error=%s", url, str(e))
        return {"status": "error", "error": str(e), "url": url}


# ---------------------------------------------------------------------------
# Async submission helpers
# ---------------------------------------------------------------------------

def submit_url_analysis(url: str) -> Future:
    """Submit URL analysis to the thread pool; returns a Future."""
    return _EXECUTOR.submit(analyze_url_task, url)


def submit_file_analysis(file_bytes: bytes, filename: str) -> Future:
    """Submit file analysis to the thread pool; returns a Future."""
    return _EXECUTOR.submit(analyze_file_task, file_bytes, filename)


def submit_network_analysis(url: str) -> Future:
    """Submit network analysis to the thread pool; returns a Future."""
    return _EXECUTOR.submit(analyze_network_task, url)
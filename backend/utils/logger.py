"""
Advanced Logging System (SOC / SIEM Ready)

Features:
- UTF-8 safe (fix Unicode error)
- JSON logging (for ELK / SIEM)
- Rotating logs
- Request tracing (trace_id)
- Clean console + file separation
"""

import logging
import logging.handlers
import json
import sys
from pathlib import Path
from datetime import datetime
import uuid

from utils.config import LOG_FILE, LOG_LEVEL, LOG_MAX_BYTES, LOG_BACKUP_COUNT


# ==========================
# Ensure log directory
# ==========================

LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


# ==========================
# JSON Formatter
# ==========================

class JsonFormatter(logging.Formatter):

    def format(self, record):
        log_record = {
            "time": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.name,
        }

        # optional fields
        if hasattr(record, "trace_id"):
            log_record["trace_id"] = record.trace_id

        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_record, ensure_ascii=False)


# ==========================
# Text Formatter (console)
# ==========================

class SafeFormatter(logging.Formatter):
    def format(self, record):
        try:
            return super().format(record)
        except UnicodeEncodeError:
            record.msg = record.msg.encode("utf-8", "ignore").decode("utf-8")
            return super().format(record)


# ==========================
# Setup logging
# ==========================

def setup_logging(level=LOG_LEVEL):

    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # clear old handlers
    logger.handlers.clear()

    # ======================
    # FILE (JSON)
    # ======================

    file_handler = logging.handlers.RotatingFileHandler(
        str(LOG_FILE),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8"   # 🔥 FIX Unicode
    )

    file_handler.setFormatter(JsonFormatter())
    logger.addHandler(file_handler)

    # ======================
    # CONSOLE (READABLE)
    # ======================

    console_handler = logging.StreamHandler(sys.stdout)
    console_format = SafeFormatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)


# ==========================
# Logger getter
# ==========================

def get_logger(name):
    return logging.getLogger(name)


# ==========================
# Trace helper
# ==========================

def generate_trace_id():
    return str(uuid.uuid4())[:8]


def log_with_trace(logger, level, message, trace_id=None, **kwargs):
    extra = {"trace_id": trace_id or generate_trace_id()}
    logger.log(level, message, extra=extra, **kwargs)


# ==========================
# Global logger
# ==========================

logger = get_logger(__name__)


# ==========================
# Business logs
# ==========================

def log_analysis_request(analysis_type, input_value):

    if analysis_type == "url":
        masked_value = input_value[:50] + "..." if len(input_value) > 50 else input_value
    else:
        masked_value = f"{analysis_type}_{len(str(input_value))}_bytes"

    log_with_trace(
        logger,
        logging.INFO,
        f"analysis_request | type={analysis_type} | input={masked_value}"
    )


def log_analysis_result(analysis_type, risk_level, confidence):

    log_with_trace(
        logger,
        logging.INFO,
        f"analysis_result | type={analysis_type} | risk_level={risk_level} | confidence={confidence:.2f}"
    )
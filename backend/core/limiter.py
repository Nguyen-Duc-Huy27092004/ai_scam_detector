"""
Rate limiter singleton.

Development: in-memory. Production multi-worker: set USE_REDIS=true.
`REDIS_URL` is read from `utils.config` so cache and limiter stay aligned.
"""

import os

from slowapi import Limiter
from slowapi.util import get_remote_address

from utils.logger import logger
from utils.config import REDIS_URL

RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
USE_REDIS = os.getenv("USE_REDIS", "false").lower() == "true"

if not RATE_LIMIT_ENABLED:
    logger.info("rate_limiter_init | backend=disabled")
    limiter = Limiter(key_func=get_remote_address, default_limits=[])
elif USE_REDIS:
    try:
        limiter = Limiter(
            key_func=get_remote_address,
            storage_uri=REDIS_URL,
        )
        logger.info("rate_limiter_init | backend=redis")
    except Exception as e:
        logger.warning(
            "rate_limiter_redis_failed | error_type=%s | falling_back_to_memory",
            type(e).__name__,
        )
        limiter = Limiter(key_func=get_remote_address)
else:
    logger.info("rate_limiter_init | backend=memory (development mode)")
    limiter = Limiter(key_func=get_remote_address)

"""
Rate limiter singleton.

H5 Fix: Use in-memory rate limiting for development. 
For production with multiple workers, set USE_REDIS=true and ensure Redis is running.
"""

import os
from slowapi import Limiter
from slowapi.util import get_remote_address

from utils.logger import logger

RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
USE_REDIS = os.getenv("USE_REDIS", "false").lower() == "true"
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# If rate limiting is disabled, use a no-op limiter
if not RATE_LIMIT_ENABLED:
    logger.info("rate_limiter_init | backend=disabled")
    limiter = Limiter(key_func=get_remote_address, default_limits=[])
# Use Redis for production multi-worker setups
elif USE_REDIS:
    try:
        limiter = Limiter(
            key_func=get_remote_address,
            storage_uri=REDIS_URL,
        )
        logger.info("rate_limiter_init | backend=redis | uri=%s", REDIS_URL)
    except Exception as e:
        logger.warning(
            "rate_limiter_redis_failed | error=%s | falling_back_to_memory", str(e)
        )
        limiter = Limiter(key_func=get_remote_address)
# Default to in-memory for development
else:
    logger.info("rate_limiter_init | backend=memory (development mode)")
    limiter = Limiter(key_func=get_remote_address)

import json
import time
from typing import Any, Optional

import redis.asyncio as redis

from utils.config import REDIS_URL
from utils.logger import logger


class CacheManager:
    def __init__(self):
        self.redis_client = None
        self._memory_cache = {}

    async def init(self):
        try:
            self.redis_client = redis.from_url(REDIS_URL, decode_responses=True)
            await self.redis_client.ping()
            logger.info("redis_connected")
        except Exception as e:
            logger.error("redis_connect_failed | error_type=%s", type(e).__name__)
            self.redis_client = None

    async def get(self, key: str) -> Optional[Any]:
        if self.redis_client:
            try:
                val = await self.redis_client.get(key)
                if val:
                    return json.loads(val)
            except Exception as e:
                logger.error(
                    "redis_get_error | key_prefix=%.20s | error_type=%s",
                    key,
                    type(e).__name__,
                )
        
        # Memory fallback
        if key in self._memory_cache:
            entry = self._memory_cache[key]
            if time.time() < entry["expire_at"]:
                return entry["value"]
            else:
                del self._memory_cache[key]
        return None

    async def set(self, key: str, value: Any, expire_seconds: int = 86400):
        if self.redis_client:
            try:
                await self.redis_client.set(key, json.dumps(value), ex=expire_seconds)
            except Exception as e:
                logger.error("redis_set_error | error_type=%s", type(e).__name__)
        
        # Memory fallback
        self._memory_cache[key] = {
            "value": value,
            "expire_at": time.time() + expire_seconds
        }

    async def close(self):
        if self.redis_client:
            await self.redis_client.close()
        self._memory_cache.clear()


cache = CacheManager()

import asyncio
import os
import pathlib
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from core.limiter import limiter

from utils.config import (
    CORS_ORIGINS, DEBUG, LOG_LEVEL, SCREENSHOTS_DIR, SCREENSHOT_MAX_AGE_HOURS
)
from utils.logger import logger, setup_logging
from core.cache import cache

from api.health import router as health_router
from api.url import router as url_router
from api.image import router as image_router
from api.text import router as text_router
from api.history import router as history_router
from api.chat import router as chat_router

def _start_screenshot_cleanup(directory: str, max_age_hours: int = 24):
    """Background task to delete old screenshots."""
    async def cleanup_loop():
        while True:
            try:
                cutoff = time.time() - max_age_hours * 3600
                target = pathlib.Path(directory)
                if target.exists():
                    deleted: int = 0
                    for f in target.glob("*.png"):
                        if f.stat().st_mtime < cutoff:
                            f.unlink(missing_ok=True)
                            deleted += 1
                    if deleted:
                        logger.info("screenshot_cleanup | deleted=%d", deleted)
            except Exception as e:
                logger.warning("screenshot_cleanup_error | %s", str(e))
            await asyncio.sleep(3600)  # Sleep for 1 hour

    asyncio.create_task(cleanup_loop(), name="screenshot-cleanup")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Setup logging
    setup_logging(LOG_LEVEL)
    logger.info("Initializing FastAPI application...")
    
    # Initialize Cache
    await cache.init()
    
    # Start background cleanup
    _start_screenshot_cleanup(str(SCREENSHOTS_DIR), SCREENSHOT_MAX_AGE_HOURS)
    
    yield
    
    # Cleanup on shutdown
    await cache.close()
    logger.info("FastAPI application shutdown.")


app = FastAPI(
    title="AI Scam Detector API",
    description="Asynchronous Backend API for detecting phishing URLs and scams.",
    version="2.0.0",
    lifespan=lifespan,
    # FIX: Disable Swagger/ReDoc in production to prevent exposing full API schema.
    # Attackers can use API schema to discover all endpoints, input formats, and error messages.
    docs_url="/docs" if DEBUG else None,
    redoc_url="/redoc" if DEBUG else None,
)

# Rate Limiter setup
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
logger.info("CORS configured for origins: %s", CORS_ORIGINS)

# Global exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": "Internal Server Error", "message": "An unexpected error occurred."}
    )

# Include Routers
app.include_router(health_router, prefix="/api", tags=["Health"])
app.include_router(url_router, prefix="/api/url", tags=["URL Analysis"])
app.include_router(image_router, prefix="/api/image", tags=["Image Analysis"])
app.include_router(text_router, prefix="/api/text", tags=["Text Analysis"])
app.include_router(history_router, prefix="/api/history", tags=["History"])
app.include_router(chat_router, prefix="/api/chat", tags=["Chatbot"])

if __name__ == "__main__":
    import uvicorn
    from utils.config import HOST, PORT
    logger.info("Starting FastAPI server on %s:%d", HOST, PORT)
    uvicorn.run("main:app", host=HOST, port=PORT, reload=DEBUG)

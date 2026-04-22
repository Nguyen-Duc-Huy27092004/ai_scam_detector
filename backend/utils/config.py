from pathlib import Path
import os
import json

# ========================
# Base directories
# ========================
BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"

SQLITE_DB_PATH = DATA_DIR / "analysis.db"

# 🔥 FIX QUAN TRỌNG
SCREENSHOTS_DIR = DATA_DIR / "screenshots"
IMAGES_DIR = DATA_DIR / "images"

DATABASE_TYPE = "sqlite"
TEXT_SCAM_CONFIDENCE_THRESHOLD = 0.7

# ========================
# FastAPI / Uvicorn
# ========================
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# ========================
# Redis / Celery
# ========================
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)

CORS_ORIGINS = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
).split(",")

# ========================
# Models
# ========================
PHISHING_MODEL_PATH = MODELS_DIR / "phishing_detector.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"

IMAGE_MODEL_PATH = MODELS_DIR / "image_model" / "scam_image_model.pth"
IMAGE_LABELS_PATH = MODELS_DIR / "image_model" / "labels.json"

URL_MODEL_PATH = MODELS_DIR / "phishing_detector.pkl"
URL_SCALER_PATH = MODELS_DIR / "scaler.pkl"

# Optional SHA-256 (hex) for joblib models — set in production to detect tampering.
URL_MODEL_SHA256 = os.getenv("URL_MODEL_SHA256", "").strip()
URL_SCALER_SHA256 = os.getenv("URL_SCALER_SHA256", "").strip()

URL_MODEL_VERSION = os.getenv("URL_MODEL_VERSION", "2.0")
TEXT_MODEL_VERSION = os.getenv("TEXT_MODEL_VERSION", "text-v1")
IMAGE_MODEL_VERSION = os.getenv("IMAGE_MODEL_VERSION", "2.0")

# ========================
# Limits
# ========================
MAX_URL_CONTENT_LENGTH = 50000
MAX_IMAGE_SIZE_MB = 10

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "bmp"}

IMAGE_SCAM_CONFIDENCE_THRESHOLD = 0.7
PHISHING_CONFIDENCE_THRESHOLD = 0.7

# ========================
# Logging
# ========================
LOG_FILE = LOGS_DIR / "app.log"

LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3

# ========================
# URL validation
# ========================
MIN_URL_LENGTH = 10
MAX_URL_LENGTH = 2048

# ========================
# Crawl / Screenshot
# ========================
SCREENSHOT_TIMEOUT = 10

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# ========================
# OCR
# ========================
OCR_LANGUAGE = "vie"
OCR_TIMEOUT = 15

# ========================
# Rate limit
# ========================
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
RATE_LIMIT_ANALYZE = os.getenv("RATE_LIMIT_ANALYZE", "10 per minute")
RATE_LIMIT_DEFAULT = os.getenv("RATE_LIMIT_DEFAULT", "100 per hour")

# ========================
# Threat intel
# ========================
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "")
OPENPHISH_FEED_PATH = DATA_DIR / "openphish_feed.txt"
BLACKLIST_DB_PATH = DATA_DIR / "blacklist.db"

# ========================
# LLM Configuration
# ========================
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama")
LLM_MODEL = os.getenv("LLM_MODEL", "gemma:2b")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://localhost:11434")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")

# ========================
# Internal ops (optional — unset disables /api/health/internal)
# ========================
INTERNAL_HEALTH_TOKEN = os.getenv("INTERNAL_HEALTH_TOKEN", "").strip()

# ========================
# Cleanup
# ========================
SCREENSHOT_MAX_AGE_HOURS = int(os.getenv("SCREENSHOT_MAX_AGE_HOURS", "24"))
# ========================
# Content extraction
# ========================
CONTENT_EXTRACTION_TIMEOUT = 10


def validate_image_labels_file(path: Path, name: str = "image_model") -> None:
    """Ensure labels JSON exists and is non-empty (avoids silent Keras/Torch failure)."""
    if not path.exists():
        raise FileNotFoundError(f"{name} labels not found: {path}")
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        raise ValueError(f"{name} labels file is EMPTY: {path}")
    data = json.loads(content)
    if not data:
        raise ValueError(f"{name} labels file has no entries: {path}")

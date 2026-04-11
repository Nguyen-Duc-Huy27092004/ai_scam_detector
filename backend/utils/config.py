import os
from pathlib import Path

# ========================
# Base directories
# ========================
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = _BACKEND_DIR
SQLITE_DB_PATH = Path(BASE_DIR) / "data" / "analysis.db"
DATABASE_TYPE = "sqlite"
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")
SCREENSHOTS_DIR = os.path.join(DATA_DIR, "screenshots")
IMAGES_DIR = os.path.join(DATA_DIR, "images")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
TEXT_SCAM_CONFIDENCE_THRESHOLD = 0.7
# ========================
# Flask App Config
# ========================
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 5000))
DEBUG = os.getenv("DEBUG", "true").lower() == "true"

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# CORS origins (comma separated env var support)
CORS_ORIGINS = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000"
).split(",")

# ========================
# ML / Model paths
# ========================
PHISHING_MODEL_PATH = os.path.join(MODELS_DIR, "phishing_detector.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
IMAGE_MODEL_DIR = os.path.join(MODELS_DIR, "image_model")

IMAGE_MODEL_PATH = Path("models/image_model/scam_image_model.pth")
IMAGE_LABELS_PATH = Path("models/image_model/labels.json")

# ========================
# Limits & thresholds
# ========================
MAX_URL_CONTENT_LENGTH = 50000
MAX_IMAGE_SIZE_MB = 10
ALLOWED_IMAGE_EXTENSIONS = frozenset({"png", "jpg", "jpeg", "webp", "bmp"})

IMAGE_SCAM_CONFIDENCE_THRESHOLD = 0.7
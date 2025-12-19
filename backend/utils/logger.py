import logging
import os
from datetime import datetime
# Create log directory
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

log_file = os.path.join(
    LOG_DIR,
    f"app_{datetime.now().strftime('%Y-%m-%d')}.log"
)
# Set up logging
logging.basicConfig (
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[
        logging.FileHandler(log_file, encoding="utf-8"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("AI-Scam-Detector")

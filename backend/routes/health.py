from flask import Blueprint, jsonify
from datetime import datetime

from backend.services.greeting import get_greeting
from backend.utils.logger import logger

health_bp = Blueprint("health", __name__)
# Health check endpoint
@health_bp.route("/", methods=["GET"])
def health_check():
    logger.info("Health check endpoint accessed")

    return jsonify({
        "status": "running",
        "service": "AI Scam Detector API",
        "message": get_greeting(),
        "timestamp": datetime.utcnow().isoformat()
    })

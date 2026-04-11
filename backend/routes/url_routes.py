from flask import Blueprint, request, jsonify
from datetime import datetime
from utils.logger import logger
from utils.validators import is_valid_url, validate_json_request
from services.url_pipeline import analyze_url
from services.advisor import generate_advice
import base64
import os

url_bp = Blueprint('url', __name__, url_prefix='/api/url')


def success(data, status=200):
    return jsonify({
        "success": True,
        "data": data,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }), status


def error(message, status=400, details=None):
    res = {
        "success": False,
        "error": message,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    if details:
        res["details"] = details
    return jsonify(res), status


@url_bp.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json(silent=True) or {}
    is_valid, msg = validate_json_request(data, ['url'])

    if not is_valid:
        return error(msg)

    url = data['url'].strip()

    if not is_valid_url(url):
        return error("Invalid URL format")

    logger.info(f"url_analyze | {url}")

    result = analyze_url(url)

    if result.get("status") == "error":
        return error("Analysis failed", 500, result)

    # load screenshot
    screenshot_data = None
    screenshot_path = result.get("screenshot_path")
    if screenshot_path and os.path.exists(screenshot_path):
        with open(screenshot_path, "rb") as f:
            screenshot_data = base64.b64encode(f.read()).decode()

    # ✅ Generate advice
    advice_result = generate_advice(
        analysis_type="url",
        risk_level=result.get("risk_level"),
        risk_factors=result.get("risk_factors", []),
        confidence=result.get("ml_prediction", {}).get("confidence", 0.0)
    )

    response = {
        "url": url,
        "is_scam": result.get("risk_level") == "high",
        "risk_score": result.get("overall_score"),
        "risk_level": result.get("risk_level"),
        "confidence": result.get("ml_prediction", {}).get("confidence"),
        "reasons": result.get("risk_factors", []),
        "signals": result.get("metadata", {}),
        "screenshot": screenshot_data,
        "record_id": result.get("record_id"),

        # ✅ advisor output
        "advice": advice_result.get("advice"),
        "risk_summary": advice_result.get("risk_summary"),
        "recommendations": advice_result.get("recommendations")
    }

    return success(response)
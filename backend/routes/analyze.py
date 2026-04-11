from flask import Blueprint, request, jsonify
import tempfile
import os

from backend.utils.validators import is_valid_url, validate_image_upload
from backend.utils.logger import logger, log_analysis_request
from backend.utils.config import MAX_IMAGE_SIZE_MB
from backend.services.analysis_orchestrator import analyze_url, analyze_image

analyze_bp = Blueprint("analyze", __name__)


def _response(result: dict, status: int = 200):
    return jsonify(result), status


def _error(message: str, status: int = 400):
    return jsonify({"error": message}), status


@analyze_bp.route("/api/analyze/url", methods=["POST"])
def analyze_url_route():
    try:
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()

        if not url:
            return _error("URL is required", 400)
        if not is_valid_url(url):
            return _error("Invalid URL format", 400)

        log_analysis_request("url", url)

        result = analyze_url(url)
        return _response(result.to_dict())

    except Exception as e:
        logger.exception("analyze_url_error | error=%s", str(e))
        return _error("Internal server error", 500)


@analyze_bp.route("/api/analyze/image", methods=["POST"])
def analyze_image_route():
    try:
        if "file" not in request.files and "image" not in request.files:
            return _error("No image file provided", 400)

        file = request.files.get("file") or request.files.get("image")
        if not file or not file.filename:
            return _error("No image file selected", 400)

        content = file.read()
        if not content:
            return _error("Empty image file", 400)

        ok, err = validate_image_upload(file.filename, actual_size=len(content))
        if not ok:
            if err == "invalid_extension":
                return _error("Invalid image format. Allowed: png, jpg, jpeg, webp, bmp", 400)
            if err == "file_too_large":
                return _error(f"File too large. Max size: {MAX_IMAGE_SIZE_MB} MB", 400)
            return _error("Invalid upload", 400)

        log_analysis_request("image", file.filename)

        # Save temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp:
            tmp.write(content)
            temp_path = tmp.name

        result = analyze_image(temp_path)

        os.remove(temp_path)

        return _response(result.to_dict())

    except Exception as e:
        logger.exception("analyze_image_error | error=%s", str(e))
        return _error("Internal server error", 500)
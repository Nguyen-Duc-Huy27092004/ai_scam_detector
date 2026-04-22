import asyncio
import os
import uuid
import re
from typing import List, Any, Dict

from fastapi import APIRouter, UploadFile, File, Request

from core.limiter import limiter
from core.responses import json_error, json_success
from utils.logger import logger
from utils.validators import validate_image_upload
from utils.config import SCREENSHOTS_DIR, MAX_IMAGE_SIZE_MB
from services.image_pipeline import analyze_image

router = APIRouter()


def _save_upload(contents: "bytes | bytearray", original_filename: str) -> str:
    """Save uploaded bytes to SCREENSHOTS_DIR and return path."""
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", original_filename)
    filename = safe_name if safe_name else f"image_{uuid.uuid4().hex[:8]}.png"
    image_path = os.path.join(SCREENSHOTS_DIR, f"{uuid.uuid4().hex[:8]}_{filename}")
    with open(image_path, "wb") as buffer:
        buffer.write(contents)
    return image_path


def _build_image_response(filename: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a flat, frontend-compatible response dict.
    Frontend reads: risk_level, risk_score, risk_score_percent, advice, ocr_text, risk_factors
    """
    overall_score = result.get("overall_score", 0)
    return {
        "filename": filename,
        "risk_level": result.get("risk_level", "unknown"),
        "risk_score": overall_score,
        "risk_score_percent": round(overall_score),
        "label": result.get("label"),
        "confidence": result.get("image_prediction", {}).get("confidence"),
        "ocr_text": result.get("ocr_text", "")[:500],
        "advice": result.get("advice"),
        "recommendations": result.get("recommendations", []),
        "risk_factors": result.get("risk_factors", []),
        "record_id": result.get("record_id"),
        "details": {
            "image_prediction": result.get("image_prediction"),
            "ocr_metadata": result.get("ocr_metadata"),
            "text_analysis": result.get("text_analysis"),
        },
    }


@router.post("/analyze")
@limiter.limit("5/minute")
async def analyze_image_endpoint(request: Request, image: UploadFile = File(...)):
    """Analyze uploaded image for scams."""
    try:
        contents = await image.read()
        file_size = len(contents)

        max_bytes = MAX_IMAGE_SIZE_MB * 1024 * 1024
        if file_size > max_bytes:
            return json_error(f"File size exceeds maximum of {MAX_IMAGE_SIZE_MB}MB", 413)

        original_filename = image.filename or "unknown.png"
        image_path = _save_upload(contents, original_filename)

        logger.info("image_analysis_requested | filename=%s", original_filename)

        result = await asyncio.to_thread(analyze_image, image_path)

        if result.get("status") == "error":
            logger.error("image_analysis_error | error=%s", result.get("error"))
            return json_error("Analysis failed", 500, {"error": result.get("error")})

        response_data = _build_image_response(original_filename, result)
        return json_success(response_data, 200)

    except Exception as e:
        logger.exception("image_endpoint_error | error=%s", str(e))
        return json_error("Internal server error", 500)


@router.post("/batch-analyze")
@limiter.limit("2/minute")
async def batch_analyze_images(request: Request, images: List[UploadFile] = File(...)):
    """Analyze multiple image files."""
    try:
        if not images:
            return json_error("At least one image required", 400)

        if len(images) > 20:
            return json_error("Maximum 20 images per batch", 400)

        logger.info("batch_image_analysis_requested | count=%d", len(images))

        results = []
        for file in images:
            try:
                contents = await file.read()
                file_size = len(contents)
                original_filename = file.filename or "unknown.png"

                if file_size > MAX_IMAGE_SIZE_MB * 1024 * 1024:
                    results.append({"filename": original_filename, "error": "File too large", "status": "error"})
                    continue

                image_path = _save_upload(contents, original_filename)
                result = await asyncio.to_thread(analyze_image, image_path)

                results.append({
                    "filename": original_filename,
                    "risk_level": result.get("risk_level"),
                    "risk_score": result.get("overall_score"),
                    "risk_score_percent": round(result.get("overall_score", 0)),
                    "record_id": result.get("record_id"),
                    "status": result.get("status", "completed"),
                })

            except Exception as e:
                orig_name = getattr(file, "filename", "unknown") or "unknown"
                logger.error("batch_image_failed | filename=%s | error=%s", orig_name, str(e))
                results.append({"filename": orig_name, "error": "Analysis failed", "status": "error"})

        return json_success({
            "total": len(images),
            "completed": sum(1 for r in results if r.get("status") != "error"),
            "results": results,
        }, 200)

    except Exception as e:
        logger.exception("batch_image_endpoint_error | error=%s", str(e))
        return json_error("Internal server error", 500)

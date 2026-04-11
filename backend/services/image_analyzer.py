from typing import Dict, Any, BinaryIO

from backend.ml.image.ocr import extract_text_from_image
from backend.services.content_analyzer import analyze_content
from backend.services.risk_level import calculate_risk
from backend.services.advisor import generate_advice
from backend.utils.logger import logger

SCAM_THRESHOLD = 0.45


def analyze_image(image_source, *, filename: str = "image") -> Dict[str, Any]:
    """
    image_source: path (str), bytes, or file-like object.
    Returns same structure as URL analysis: input, label, risk_level, confidence, evidence, ai_advice.
    """
    evidence: Dict[str, Any] = {
        "url_features": {},
        "domain_info": {},
        "content_flags": [],
        "ocr_preview": None,
    }

    text = extract_text_from_image(image_source)
    evidence["ocr_preview"] = (text[:500].strip() or None) if text else None

    content_score = 0.0
    content_flags: list = []

    if text:
        result = analyze_content(text)
        content_score = result["score"]
        content_flags = result.get("flags") or []
        evidence["content_flags"] = content_flags

    if content_score >= SCAM_THRESHOLD:
        prediction = 1
        confidence = content_score
        label = "scam"
    else:
        prediction = 0
        confidence = 1.0 - content_score if content_score < 1.0 else 0.0
        label = "safe"

    risk_level = calculate_risk(
        prediction=prediction,
        confidence=confidence,
        content_score=content_score,
        domain_info=None,
        content_flags=content_flags,
    )

    ai_advice = generate_advice(
        label=label,
        risk_level=risk_level,
        evidence=evidence,
        confidence=confidence,
        input_repr=filename,
    )

    return {
        "input": filename,
        "label": label,
        "risk_level": risk_level,
        "confidence": round(confidence, 4),
        "evidence": evidence,
        "ai_advice": ai_advice,
    }

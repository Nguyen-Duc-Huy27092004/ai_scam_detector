from typing import Dict, Any

from ocr.ocr_engine import extract_text_from_image
from services.content_analyzer import analyze_content
from services.risk_level import calculate_risk
from services.advisor import generate_advice
from utils.logger import logger

SCAM_THRESHOLD = 0.45


def _content_score_and_flags(text: str) -> tuple[float, list]:
    evidences = analyze_content(text)
    if not evidences:
        return 0.0, []

    flags = []
    severity_weights = {"low": 0.25, "medium": 0.6, "high": 1.0}
    weighted_sum = 0.0
    for ev in evidences:
        flag = getattr(ev, "flag_name", None) or getattr(ev, "keyword", "")
        if flag:
            flags.append(flag)
        sev = str(getattr(ev, "severity", "low")).lower()
        weighted_sum += severity_weights.get(sev, 0.3)

    score = min(1.0, weighted_sum / max(len(evidences), 1))
    return score, list(dict.fromkeys(flags))


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
        content_score, content_flags = _content_score_and_flags(text)
        evidence["content_flags"] = content_flags

    if content_score >= SCAM_THRESHOLD:
        prediction = 1
        confidence = content_score
        label = "scam"
    else:
        prediction = 0
        confidence = 1.0 - content_score if content_score < 1.0 else 0.0
        label = "safe"

    risk_level, _, _ = calculate_risk(
        url_ml_confidence=confidence,
        image_risk=content_score,
        suspicious_patterns=content_flags,
    )

    ai_advice = generate_advice(
        analysis_type="image",
        risk_level=risk_level,
        risk_factors=content_flags,
        confidence=confidence,
    )

    return {
        "input": filename,
        "label": label,
        "risk_level": risk_level,
        "confidence": round(confidence, 4),
        "evidence": evidence,
        "ai_advice": ai_advice,
    }

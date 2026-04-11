from typing import Dict, Any, Optional

from backend.ml.url.feature_extraction import url_features_for_evidence
from backend.ml.url.predict import predict_url
from backend.services.domain_intel import get_domain_intel
from backend.services.content_extractor import extract_from_url
from backend.services.screenshot import capture_website
from backend.services.content_analyzer import analyze_content
from backend.services.risk_level import calculate_risk
from backend.services.advisor import generate_advice
from backend.utils.logger import logger


def analyze_url(url: str) -> Dict[str, Any]:
    url = url.strip()
    evidence: Dict[str, Any] = {
        "url_features": {},
        "domain_info": {},
        "content_flags": [],
        "screenshot_path": None,
        "content_preview": None,
    }

    domain_info = get_domain_intel(url)
    evidence["domain_info"] = domain_info

    url_feat = url_features_for_evidence(url)
    evidence["url_features"] = url_feat

    try:
        ml_result = predict_url(url)
    except Exception as e:
        logger.error("url_ml_predict_failed | url=%s | error=%s", url[:80], str(e))
        ml_result = {
            "prediction": 0,
            "label": "safe",
            "confidence": 0.0,
        }

    content_score = 0.0
    content_flags: list = []
    html_text = ""

    try:
        _, html_text = extract_from_url(url)
        if html_text:
            content_result = analyze_content(html_text)
            content_score = content_result["score"]
            content_flags = content_result.get("flags") or []
            evidence["content_flags"] = content_flags
            evidence["content_preview"] = html_text[:500].strip()
    except Exception as e:
        logger.warning("content_extract_or_analyze_failed | url=%s | error=%s", url[:80], str(e))

    try:
        path = capture_website(url)
        evidence["screenshot_path"] = path
    except Exception as e:
        logger.warning("screenshot_failed | url=%s | error=%s", url[:80], str(e))

    prediction = ml_result["prediction"]
    confidence = ml_result["confidence"]
    label = ml_result["label"]

    risk_level = calculate_risk(
        prediction=prediction,
        confidence=confidence,
        content_score=content_score,
        domain_info=domain_info,
        content_flags=content_flags,
    )

    ai_advice = generate_advice(
        label=label,
        risk_level=risk_level,
        evidence=evidence,
        confidence=confidence,
        input_repr=url,
    )

    return {
        "input": url,
        "label": label,
        "risk_level": risk_level,
        "confidence": confidence,
        "evidence": evidence,
        "ai_advice": ai_advice,
    }

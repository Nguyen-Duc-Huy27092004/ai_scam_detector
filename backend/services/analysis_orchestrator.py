from typing import Optional

from backend.entities.analysis_result import AnalysisResult
from backend.entities.scam_evidence import ScamEvidence
from backend.ml.url.feature_extraction import url_features_for_evidence
from backend.ml.url.predict import predict_url
from backend.services.domain_intel import get_domain_intel
from backend.services.content_extractor import extract_from_url
from backend.services.screenshot import capture_website
from backend.services.content_analyzer import analyze_content
from backend.services.risk_level import calculate_risk
from backend.services.advisor import generate_advice
from backend.utils.logger import logger


def analyze_url(url: str) -> AnalysisResult:
    url = url.strip()

    domain_info = get_domain_intel(url)
    url_features = url_features_for_evidence(url)

    try:
        ml_result = predict_url(url)
        url_label = ml_result["label"]
        confidence = ml_result["confidence"]
        prediction = ml_result["prediction"]
    except Exception as e:
        logger.error("url_ml_predict_failed | url=%s | error=%s", url[:80], str(e))
        url_label = "safe"
        confidence = 0.0
        prediction = 0

    screenshot_path: Optional[str] = None
    try:
        screenshot_path = capture_website(url)
    except Exception as e:
        logger.warning("screenshot_failed | url=%s | error=%s", url[:80], str(e))

    content_findings: list[ScamEvidence] = []
    content_score = 0.0

    try:
        _, html_text = extract_from_url(url)
        if html_text:
            content_findings = analyze_content(html_text, source="website")
            if content_findings:
                from backend.ml.text.analyzer import analyze_text
                text_result = analyze_text(html_text)
                content_score = text_result.get("score", 0.0)
    except Exception as e:
        logger.warning("content_extract_or_analyze_failed | url=%s | error=%s", url[:80], str(e))

    content_flags_for_risk = [f.flag_name for f in content_findings if f.flag_name]

    risk_level = calculate_risk(
        prediction=prediction,
        confidence=confidence,
        content_score=content_score,
        domain_info=domain_info,
        content_flags=content_flags_for_risk,
    )

    evidence_dict = {
        "url_features": url_features,
        "domain_info": domain_info,
        "content_flags": [e.to_dict() for e in content_findings],
        "screenshot_path": screenshot_path,
    }

    advice = generate_advice(
        label=url_label,
        risk_level=risk_level,
        evidence=evidence_dict,
        confidence=confidence,
        input_repr=url,
    )

    result = AnalysisResult(
        url=url,
        domain_info=domain_info,
        screenshot_path=screenshot_path,
        url_label=url_label,
        confidence=confidence,
        content_findings=content_findings,
        risk_level=risk_level,
        advice=advice,
        url_features=url_features,
    )
    return result


def analyze_image(image_source, *, filename: str = "image") -> AnalysisResult:
    from backend.ml.image.ocr import extract_text_from_image
    from backend.services.content_analyzer import analyze_content
    from backend.services.risk_level import calculate_risk
    from backend.services.advisor import generate_advice

    text = extract_text_from_image(image_source)
    content_findings: list[ScamEvidence] = []

    if text:
        content_findings = analyze_content(text, source="image")
        from backend.ml.text.analyzer import analyze_text
        text_result = analyze_text(text)
        content_score = text_result.get("score", 0.0)
    else:
        content_score = 0.0

    if content_score >= 0.45:
        prediction = 1
        confidence = content_score
        url_label = "scam"
    else:
        prediction = 0
        confidence = 1.0 - content_score if content_score < 1.0 else 0.0
        url_label = "safe"

    content_flags_for_risk = [f.flag_name for f in content_findings if f.flag_name]

    risk_level = calculate_risk(
        prediction=prediction,
        confidence=confidence,
        content_score=content_score,
        domain_info=None,
        content_flags=content_flags_for_risk,
    )

    evidence_dict = {
        "url_features": {},
        "domain_info": {},
        "content_flags": [e.to_dict() for e in content_findings],
        "ocr_preview": text[:500].strip() if text else None,
    }

    advice = generate_advice(
        label=url_label,
        risk_level=risk_level,
        evidence=evidence_dict,
        confidence=confidence,
        input_repr=filename,
    )

    result = AnalysisResult(
        url=filename,
        domain_info={},
        screenshot_path=None,
        url_label=url_label,
        confidence=confidence,
        content_findings=content_findings,
        risk_level=risk_level,
        advice=advice,
        url_features={},
        ocr_preview=text[:500].strip() if text else None,
    )
    return result

from typing import Dict, Any
import warnings

from ml.url.feature_extraction import URLFeatureExtractor
from ml.url.predict import predict_url
from services.domain_intel import get_domain_intel
from services.content_extractor import extract_from_url
from services.screenshot import capture_website
from services.content_analyzer import analyze_content
from services.risk_level import calculate_risk
from services.advisor import generate_advice
from utils.logger import logger


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


def analyze_url(url: str) -> Dict[str, Any]:
    warnings.warn(
        "web_analyzer.analyze_url() is deprecated. Use url_pipeline.analyze_url() instead.",
        DeprecationWarning,
        stacklevel=2,
    )
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

    url_feat = URLFeatureExtractor.extract_features(url)
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
            content_score, content_flags = _content_score_and_flags(html_text)
            evidence["content_flags"] = content_flags
            evidence["content_preview"] = html_text[:500].strip()
    except Exception as e:
        logger.warning("content_extract_or_analyze_failed | url=%s | error=%s", url[:80], str(e))

    try:
        path = capture_website(url)
        evidence["screenshot_path"] = path
    except Exception as e:
        logger.warning("screenshot_failed | url=%s | error=%s", url[:80], str(e))

    confidence = float(ml_result.get("confidence", 0.0))
    label = ml_result.get("label", "safe")
    domain_patterns = domain_info.get("suspicious_patterns", [])

    risk_level, _, _ = calculate_risk(
        url_ml_confidence=confidence,
        text_risk=content_score,
        domain_age_days=domain_info.get("age_days"),
        is_https=url.startswith("https://"),
        suspicious_patterns=(domain_patterns + content_flags),
        domain=domain_info.get("domain", ""),
    )

    ai_advice = generate_advice(
        analysis_type="url",
        risk_level=risk_level,
        risk_factors=(domain_patterns + content_flags),
        confidence=confidence,
    )

    return {
        "input": url,
        "label": label,
        "risk_level": risk_level,
        "confidence": confidence,
        "evidence": evidence,
        "ai_advice": ai_advice,
    }

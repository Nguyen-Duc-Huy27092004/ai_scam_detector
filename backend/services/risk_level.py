from typing import List, Tuple
from utils.logger import logger
import math

WEIGHTS = {
    "ml_confidence": 0.45,
    "domain_age": 0.2,
    "https": 0.05,
    "suspicious_patterns": 0.15,
    "content_score": 0.15
}

RISK_THRESHOLDS = {
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75
}


def calculate_url_risk(
    phishing_confidence: float,
    domain_age_days: int = None,
    is_https: bool = False,
    suspicious_patterns: List[str] = None,
    content_score: float = 0.0
) -> Tuple[str, float]:

    try:
        suspicious_patterns = suspicious_patterns or []
        score = 0.0

        # ML confidence
        ml_score = phishing_confidence * 100
        score += ml_score * WEIGHTS["ml_confidence"]

        # Domain age
        if domain_age_days is None:
            domain_age_score = 50
        elif domain_age_days < 7:
            domain_age_score = 100
        elif domain_age_days < 30:
            domain_age_score = 70
        elif domain_age_days < 180:
            domain_age_score = 30
        else:
            domain_age_score = 0

        score += domain_age_score * WEIGHTS["domain_age"]

        # HTTPS
        https_score = 0 if is_https else 100
        score += https_score * WEIGHTS["https"]

        # Suspicious patterns
        pattern_score = min(len(suspicious_patterns) * 15, 100)
        score += pattern_score * WEIGHTS["suspicious_patterns"]

        # Content score
        score += content_score * 100 * WEIGHTS["content_score"]

        overall_score = min(round(score, 2), 100)

        # Risk level
        if overall_score >= RISK_THRESHOLDS["HIGH"]:
            risk_level = "CRITICAL"
        elif overall_score >= RISK_THRESHOLDS["MEDIUM"]:
            risk_level = "HIGH"
        elif overall_score >= RISK_THRESHOLDS["LOW"]:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        logger.info("risk_calculated | score=%.2f | level=%s", overall_score, risk_level)
        return risk_level, overall_score

    except Exception as e:
        logger.error("risk_calculation_failed | error=%s", str(e))
        return "UNKNOWN", 0.0
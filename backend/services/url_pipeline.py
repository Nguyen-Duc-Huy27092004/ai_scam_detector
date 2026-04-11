import json
from typing import Dict, Any, Optional, Tuple
from utils.logger import logger, log_analysis_result
from ml.url.predict import predict_url
from services.screenshot import capture_website
from services.content_extractor import extract_from_url, extract_metadata
from services.domain_intel import get_domain_intel
from services.risk_level import calculate_url_risk
from services.advisor import generate_advice, get_recommendations
from database.analysis_history import AnalysisHistory


class URLAnalysisPipeline:

    @staticmethod
    def analyze(url: str) -> Dict[str, Any]:
        logger.info("url_analysis_started | url=%s", url[:100])

        try:
            # 1. ML prediction
            ml_result = predict_url(url)
            confidence = ml_result.get("confidence", 0.0)

            # 2. Domain intel
            domain_intel = get_domain_intel(url)

            # 3. Content
            html, text = extract_from_url(url)
            metadata = extract_metadata(html) if html else {}

            # 4. Screenshot
            screenshot_path = capture_website(url)

            # 5. Content analysis
            content_score, content_flags, scam_type = URLAnalysisPipeline._analyze_content(text, metadata)

            # 6. Risk score
            risk_level, overall_score = calculate_url_risk(
                phishing_confidence=confidence,
                domain_age_days=domain_intel.get("age_days"),
                is_https=domain_intel.get("is_https"),
                suspicious_patterns=domain_intel.get("suspicious_patterns"),
                content_score=content_score
            )

            # 7. Risk factors
            risk_factors = URLAnalysisPipeline._gather_risk_factors(
                domain_intel, ml_result, content_flags
            )

            is_scam = overall_score >= 0.7

            advice = generate_advice("url", risk_level, risk_factors, confidence)
            recommendations = get_recommendations(risk_level, "url")

            summary = "Website có dấu hiệu lừa đảo" if is_scam else "Website có vẻ an toàn"

            evidence_json = json.dumps({
                "domain_intel": domain_intel,
                "ml_prediction": ml_result,
                "metadata": metadata,
                "risk_factors": risk_factors,
                "scam_type": scam_type
            }, default=str)

            record_id = AnalysisHistory.create(
                input_type="url",
                input_value=url,
                label="scam" if is_scam else "safe",
                risk_level=risk_level,
                confidence=confidence,
                advice=advice,
                screenshot_path=screenshot_path,
                ocr_text=None,
                evidence_json=evidence_json
            )

            return {
                "status": "completed",
                "url": url,
                "is_scam": is_scam,
                "risk_level": risk_level,
                "overall_score": overall_score,
                "confidence": confidence,
                "scam_type": scam_type,
                "summary": summary,
                "risk_factors": risk_factors,
                "metadata": metadata,
                "screenshot_path": screenshot_path,
                "advice": advice,
                "recommendations": recommendations,
                "record_id": record_id
            }

        except Exception as e:
            logger.exception("url_analysis_failed | %s", str(e))
            return {"status": "error", "error": str(e)}

    # ==============================
    # Content reasoning (not keyword only)
    # ==============================
    @staticmethod
    def _analyze_content(text: Optional[str], metadata: dict) -> Tuple[float, list, str]:
        score = 0.0
        flags = []
        scam_type = "unknown"

        if not text:
            return score, flags, scam_type

        t = text.lower()

        if any(x in t for x in ["verify account", "login now", "reset password"]):
            score += 0.3
            flags.append("credential_request")
            scam_type = "banking_phishing"

        if any(x in t for x in ["transfer money", "send money", "payment now"]):
            score += 0.4
            flags.append("money_request")
            scam_type = "financial_scam"

        if any(x in t for x in ["you won", "lottery", "prize"]):
            score += 0.3
            flags.append("lottery_scam")
            scam_type = "lottery_scam"

        if any(x in t for x in ["urgent", "act now", "limited time"]):
            score += 0.2
            flags.append("urgency_language")

        forms = metadata.get("forms", [])
        if forms:
            score += 0.2
            flags.append("login_form_detected")

        return min(score,1.0), flags, scam_type

    # ==============================
    # Risk factors explainable
    # ==============================
    @staticmethod
    def _gather_risk_factors(domain_intel: dict, ml_result: dict, content_flags: list) -> list:
        factors = []

        if not domain_intel.get("is_https"):
            factors.append("Không có HTTPS")

        if domain_intel.get("age_days") and domain_intel["age_days"] < 30:
            factors.append("Domain mới đăng ký")

        if domain_intel.get("is_ip"):
            factors.append("Sử dụng IP thay vì tên miền")

        if ml_result.get("confidence",0) > 0.7:
            factors.append("ML phát hiện nguy cơ cao")

        for f in content_flags:
            factors.append(f)

        return factors


def analyze_url(url: str) -> Dict[str, Any]:
    return URLAnalysisPipeline.analyze(url)
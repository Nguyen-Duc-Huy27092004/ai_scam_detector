import re
from typing import Dict, Any, List
from utils.logger import logger
from utils.config import TEXT_SCAM_CONFIDENCE_THRESHOLD
from ml.text.analyzer import analyze_text
from ml.text.predict_text import predict_text_scam


class TextScamClassifier:
    """
    High-level text scam classifier (ChongLuaDao style)
    """

    @staticmethod
    def classify(text: str) -> Dict[str, Any]:
        try:
            analysis = analyze_text(text)
            score = analysis.get("score", 0.0)
            flags = analysis.get("flags", [])
            patterns = analysis.get("patterns", [])

            evidences = predict_text_scam(text)

            confidence = min(1.0, score)

            high_t = float(TEXT_SCAM_CONFIDENCE_THRESHOLD)
            med_t = high_t * 0.57

            if confidence >= high_t:
                risk_level = "high"
                is_scam = True
            elif confidence >= med_t:
                risk_level = "medium"
                is_scam = False
            else:
                risk_level = "low"
                is_scam = False

            label = "scam" if is_scam else "safe"

            logger.info(
                "text_classified | label=%s | confidence=%.2f | flags=%d",
                label, confidence, len(flags)
            )

            return {
                "prediction": 1 if is_scam else 0,
                "label": label,
                "is_scam": is_scam,
                "confidence": round(confidence, 4),
                "risk_level": risk_level,
                "flags": flags,
                "patterns": patterns,
                "evidence": [e.to_dict() for e in evidences],
                "threshold": TEXT_SCAM_CONFIDENCE_THRESHOLD,
                "raw_length": analysis.get("raw_length", 0),
            }

        except Exception as e:
            logger.error("text_classification_failed | error=%s", str(e))
            return {
                "prediction": 0,
                "label": "unknown",
                "is_scam": False,
                "confidence": 0.0,
                "risk_level": "unknown",
                "flags": [],
                "patterns": [],
                "evidence": [],
                "error": str(e),
            }

    @staticmethod
    def extract_suspicious_keywords(text: str) -> List[str]:
        analysis = analyze_text(text)
        return analysis.get("flags", [])

    @staticmethod
    def get_summary(result: Dict[str, Any]) -> str:
        label = result.get("label", "unknown")
        confidence = result.get("confidence", 0)
        flags = result.get("flags", [])

        summary = f"Kết quả: {label.upper()} (độ tin cậy {confidence*100:.1f}%)"

        if flags:
            summary += ". Dấu hiệu phát hiện: " + ", ".join(flags[:5])
            if len(flags) > 5:
                summary += f" (+{len(flags)-5} dấu hiệu khác)"

        return summary


def classify_text(text: str) -> Dict[str, Any]:
    return TextScamClassifier.classify(text)
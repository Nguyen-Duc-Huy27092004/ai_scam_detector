from typing import Dict, Any, Optional


class FullAnalysisResult:
    def __init__(
        self,
        input_value: str,
        input_type: str,
        risk_level: str,
        score: float,
        is_scam: bool,
        confidence: float,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.input_value = input_value
        self.input_type = input_type
        self.risk_level = risk_level
        self.score = score
        self.is_scam = is_scam
        self.confidence = confidence
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input": self.input_value,
            "type": self.input_type,
            "risk_level": self.risk_level,
            "score": self.score,
            "is_scam": self.is_scam,
            "confidence": self.confidence,
            "details": self.details,
        }
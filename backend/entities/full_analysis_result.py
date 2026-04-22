from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FullAnalysisResult:
    """
    Unified analysis envelope for url / text / image pipelines.
    Use `to_dict()` for persistence and API-aligned JSON.
    """

    input_value: str
    input_type: str
    risk_level: str
    overall_score: float
    is_scam: bool
    confidence: float
    advice: str = ""
    risk_factors: List[Any] = field(default_factory=list)
    record_id: Optional[int] = None
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "input": self.input_value,
            "type": self.input_type,
            "risk_level": (self.risk_level or "unknown").lower(),
            "overall_score": self.overall_score,
            "is_scam": self.is_scam,
            "confidence": self.confidence,
            "advice": self.advice,
            "risk_factors": self.risk_factors,
        }
        if self.record_id is not None:
            d["record_id"] = self.record_id
        if self.details:
            d["details"] = self.details
        return d

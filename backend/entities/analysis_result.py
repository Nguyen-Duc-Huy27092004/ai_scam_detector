from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from entities.scam_evidence import ScamEvidence


@dataclass
class AnalysisResult:
    """Canonical analysis shape for URL/content inspection (align `to_dict` with API pipelines)."""

    url: str
    domain_info: Dict[str, Any]
    screenshot_path: Optional[str]
    url_label: str
    confidence: float
    content_findings: List[ScamEvidence] = field(default_factory=list)
    risk_level: str = "low"
    advice: str = ""
    url_features: Dict[str, Any] = field(default_factory=dict)
    ocr_preview: Optional[str] = None
    overall_score: float = 0.0
    record_id: Optional[int] = None

    def to_dict(self) -> dict:
        evidence: Dict[str, Any] = {
            "url_features": self.url_features,
            "domain_info": self.domain_info,
            "content_flags": [e.to_dict() for e in self.content_findings],
            "risk_factors": [e.flag_name for e in self.content_findings],
        }

        if self.screenshot_path:
            evidence["screenshot_path"] = self.screenshot_path

        if self.ocr_preview:
            evidence["ocr_preview"] = self.ocr_preview

        score = self.overall_score if self.overall_score else round(self.confidence * 100, 2)
        rl = (self.risk_level or "low").lower()

        out: Dict[str, Any] = {
            "url": self.url,
            "risk_level": rl,
            "label": self.url_label,
            "overall_score": float(score),
            "confidence": round(self.confidence, 4),
            "advice": self.advice,
            "evidence": evidence,
        }
        if self.record_id is not None:
            out["record_id"] = self.record_id
        return out

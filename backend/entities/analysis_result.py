from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from entities.scam_evidence import ScamEvidence


@dataclass
class AnalysisResult:
    url: str
    domain_info: Dict[str, Any]
    screenshot_path: Optional[str]
    url_label: str  # safe | scam | unknown
    confidence: float
    content_findings: List[ScamEvidence] = field(default_factory=list)
    risk_level: str = "LOW"
    advice: str = ""
    url_features: Dict[str, Any] = field(default_factory=dict)
    ocr_preview: Optional[str] = None

    def to_dict(self) -> dict:
        evidence = {
            "url_features": self.url_features,
            "domain_info": self.domain_info,
            "content_flags": [e.to_dict() for e in self.content_findings],
            "risk_factors": [e.flag_name for e in self.content_findings],
        }

        if self.screenshot_path:
            evidence["screenshot_path"] = self.screenshot_path

        if self.ocr_preview:
            evidence["ocr_preview"] = self.ocr_preview

        return {
            "input": self.url,
            "label": self.url_label,
            "risk_level": self.risk_level,
            "confidence": round(self.confidence, 3),
            "evidence": evidence,
            "ai_advice": self.advice,
        }
from dataclasses import dataclass


@dataclass
class ScamEvidence:
    source: str  # domain | content | ml | url
    keyword: str
    explanation: str
    severity: str  # low | medium | high (stored uppercase allowed; normalized in to_dict)
    flag_name: str = ""

    def to_dict(self) -> dict:
        sev = (self.severity or "low").lower()
        return {
            "source": self.source,
            "keyword": self.keyword,
            "explanation": self.explanation,
            "severity": sev,
            "flag_name": self.flag_name,
        }

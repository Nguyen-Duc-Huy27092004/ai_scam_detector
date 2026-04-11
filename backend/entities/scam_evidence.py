from dataclasses import dataclass

@dataclass
class ScamEvidence:
    source: str        # domain | content | ml | url
    keyword: str
    explanation: str
    severity: str      # LOW | MEDIUM | HIGH
    flag_name: str = ""

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "keyword": self.keyword,
            "explanation": self.explanation,
            "severity": self.severity,
            "flag_name": self.flag_name,
        }
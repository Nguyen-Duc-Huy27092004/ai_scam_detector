from typing import List

from ml.text.predict_text import predict_text_scam
from entities.scam_evidence import ScamEvidence


def analyze_content(text: str, source: str = "website") -> List[ScamEvidence]:
    if not text or not isinstance(text, str):
        return []

    return predict_text_scam(text, source=source)

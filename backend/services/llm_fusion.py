"""
LLM Fusion Module — Production v2
===================================
Merges AI content/behavior analysis with the authoritative risk engine result.

Separation of concerns:
  Risk Engine  → risk_level, score (AUTHORITATIVE — never overridden)
  AI           → content_summary, behavior_summary, analysis_summary, site_type

New output schema:
  {
    "risk_level": str,           ← risk engine only
    "score": float,              ← risk engine only
    "confidence": float,
    "site_type": str,            ← AI-classified, validated by signals
    "risk_factors": list,
    "content_summary": str,      ← AI: what this site is about
    "behavior_summary": str,     ← AI: technical behaviors (form, redirect…)
    "analysis_summary": str,     ← AI: why the score is what it is
    "recommended_action": str,   ← rule engine only
    "warnings": list[str],       ← conflict warnings (AI vs engine)
    "consistent": bool,
  }
"""

from typing import Dict, List, Optional
from utils.logger import logger


# ========================
# SITE TYPE CLASSIFIER
# ========================

_ADULT_SIGNALS  = {"adult_content", "explicit_content", "18plus"}
_SCAM_SIGNALS   = {
    "brand_impersonation", "blacklisted_url", "http_login_form",
    "external_form", "suspicious_password_form", "payment_form",
}
_SUSPICIOUS_SIGNALS = {
    "login_form", "new_domain", "young_domain", "punycode_domain",
    "suspicious_tld", "suspicious_js", "hidden_iframe",
    "suspicious_keywords", "many_external_links",
}

_VALID_SITE_TYPES = {"safe", "suspicious", "scam", "adult", "unknown"}


def classify_site_type(
    risk_level: str,
    score: float,
    signals: List[str],
    ai_hint: Optional[str] = None,
) -> str:
    """
    Classify site_type using risk engine output + signals as authority.
    AI hint is only accepted for 'adult' (content classification the engine cannot do).
    All other AI hints are ignored to prevent hallucination-driven misclassification.
    """
    signals_set = set(s.lower() for s in (signals or []))

    # Adult: trust AI hint only for this specific classification
    if ai_hint == "adult" and _ADULT_SIGNALS & signals_set:
        return "adult"
    if _ADULT_SIGNALS & signals_set:
        return "adult"

    level = (risk_level or "").upper()

    if level in ("CRITICAL", "HIGH") or score >= 60:
        return "scam" if _SCAM_SIGNALS & signals_set else "suspicious"

    if level == "MEDIUM" or score >= 30:
        return "suspicious"

    # LOW — check for suspicious signals
    if _SUSPICIOUS_SIGNALS & signals_set:
        return "suspicious"

    return "safe"


# ========================
# CONFLICT DETECTION
# ========================

def detect_conflict(
    engine_level: str,
    ai_conflict_hint: Optional[str],
    signals: List[str],
) -> List[str]:
    """
    Detect disagreements between Risk Engine and AI content analysis.
    Returns list of warning strings. Empty = no conflict.

    Conflict cases:
      - Engine says LOW but AI says scam/suspicious → warn
      - AI says adult → warn (engine has no adult detection)
    """
    warnings: List[str] = []
    if not ai_conflict_hint:
        return warnings

    hint = ai_conflict_hint.lower().strip()
    if hint not in _VALID_SITE_TYPES:
        return warnings

    bucket = _level_bucket(engine_level)

    # Case 1: Engine LOW but AI suspects scam content
    if bucket == "low" and hint == "scam":
        warnings.append(
            "Phân tích nội dung phát hiện dấu hiệu lừa đảo trong văn bản trang web. "
            "Risk Engine đánh giá kỹ thuật thấp, nhưng hãy thận trọng với nội dung."
        )

    # Case 2: Engine LOW but AI flags suspicious
    elif bucket == "low" and hint == "suspicious":
        warnings.append(
            "Nội dung trang web có một số đặc điểm đáng ngờ dù tín hiệu kỹ thuật thấp. "
            "Nên kiểm tra kỹ trước khi cung cấp thông tin."
        )

    # Case 3: Adult content detected (engine cannot detect this)
    if hint == "adult":
        warnings.append(
            "Phân tích nội dung phát hiện dấu hiệu nội dung người lớn (18+). "
            "Không phù hợp cho trẻ em."
        )

    # Case 4: Engine HIGH but AI says safe (AI being overconfident/hallucinating)
    if bucket == "high" and hint == "safe":
        warnings.append(
            "Lưu ý: AI đánh giá nội dung có vẻ an toàn nhưng Risk Engine phát hiện "
            "nhiều tín hiệu kỹ thuật nguy hiểm. Tin theo Risk Engine."
        )

    return warnings


# ========================
# RECOMMENDED ACTION RULES
# ========================

_ACTION_RULES: Dict[tuple, str] = {
    ("high",   True):  "Không nên truy cập website này. Xóa link ngay và cảnh báo người thân. Nếu đã nhập thông tin, hãy đổi mật khẩu.",
    ("high",   False): "Hệ thống phát hiện tín hiệu rủi ro cao. Không nhập thông tin cá nhân hoặc tài khoản ngân hàng.",
    ("medium", True):  "Cần thận trọng khi truy cập. Không nhập mật khẩu hoặc thông tin tài chính cho đến khi xác minh.",
    ("medium", False): "Có một số dấu hiệu đáng ngờ. Kiểm tra kỹ URL và truy cập qua kênh chính thức.",
    ("low",    True):  "Có thể truy cập, nhưng nên kiểm tra thông tin trước khi nhập dữ liệu.",
    ("low",    False): "Không đủ dữ liệu để đánh giá chắc chắn. Xác minh URL trước khi nhập bất kỳ thông tin nào.",
}


def _level_bucket(risk_level: str) -> str:
    level = (risk_level or "low").upper()
    if level in ("CRITICAL", "HIGH"):
        return "high"
    if level == "MEDIUM":
        return "medium"
    return "low"


def generate_recommended_action(risk_level: str, confidence: float) -> str:
    """Rule-based only — LLM never generates this."""
    bucket   = _level_bucket(risk_level)
    conf_ok  = float(confidence or 0) >= 0.3
    return _ACTION_RULES.get((bucket, conf_ok), _ACTION_RULES[(bucket, False)])


# ========================
# FALLBACKS (user-friendly)
# ========================

_NO_DATA = "Không đủ dữ liệu."

_FALLBACK_CONTENT: Dict[str, str] = {
    "low":      "Không có đủ dữ liệu để mô tả nội dung website.",
    "medium":   "Không có đủ dữ liệu để mô tả nội dung website.",
    "high":     "Không có đủ dữ liệu để mô tả nội dung website.",
}

_FALLBACK_BEHAVIOR: Dict[str, str] = {
    "low":      "Không phát hiện hành vi đáng chú ý.",
    "medium":   "Phát hiện một số tín hiệu kỹ thuật — xem chi tiết bên dưới.",
    "high":     "Nhiều hành vi nguy hiểm được phát hiện — xem tín hiệu bên dưới.",
}

_FALLBACK_ANALYSIS: Dict[str, str] = {
    "low":      "Điểm rủi ro thấp: ML model và rule engine không phát hiện tín hiệu nguy hiểm.",
    "medium":   "Điểm rủi ro trung bình: phát hiện một số tín hiệu cần chú ý.",
    "high":     "Điểm rủi ro cao: nhiều tín hiệu nguy hiểm được xác nhận bởi ML model và rule engine.",
    "critical": "Điểm rủi ro cực cao: tất cả hệ thống đều cảnh báo. URL này rất nguy hiểm.",
}


# ========================
# TEXT GUARD
# ========================

_REJECT_PATTERNS = [
    "AI không trả về", "LLM offline", "explanation unavailable",
    "Bạn là chuyên gia", "EXPECTED JSON", "You are a cybersecurity",
    "=== LUẬT BẮT BUỘC ===", "=== DATA ===", "OUTPUT FORMAT",
]


def _safe_text(val: Optional[str]) -> Optional[str]:
    """Return val if it looks like legitimate AI output, else None."""
    if not val or not isinstance(val, str):
        return None
    val = val.strip()
    if len(val) < 8:
        return None
    if any(p in val for p in _REJECT_PATTERNS):
        logger.warning("llm_fusion_text_rejected | prefix=%s", val[:60])
        return None
    return val


# ========================
# MAIN FUSION FUNCTION
# ========================

def fuse_llm_with_risk(
    risk_level: str,
    score: float,
    confidence: float,
    signals: List[str],
    llm_raw: Optional[Dict],
) -> Dict:
    """
    Produce the final unified output by merging risk engine and AI analysis.

    Invariants:
      - risk_level, score  → ALWAYS from risk engine (never from llm_raw)
      - recommended_action → ALWAYS from rule engine
      - site_type          → computed from signals + engine, AI hint only for adult
      - warnings           → populated when AI/engine disagree
      - All text fields    → LLM-provided when available and clean; fallback otherwise
    """
    bucket  = _level_bucket(risk_level)
    conf_ok = float(confidence or 0) >= 0.3

    # Extract AI fields (AI is purely explanatory, so we extract it regardless of ML confidence)
    ai_content_summary   = None
    ai_behavior_summary  = None
    ai_analysis_summary  = None
    ai_conflict_hint     = None

    if isinstance(llm_raw, dict):
        ai_content_summary  = _safe_text(llm_raw.get("content_summary"))
        ai_behavior_summary = _safe_text(llm_raw.get("behavior_summary"))
        ai_analysis_summary = _safe_text(llm_raw.get("analysis_summary"))

        # conflict_hint is just used internally — not shown to user directly
        raw_hint = str(llm_raw.get("conflict_hint") or "").lower().strip()
        if raw_hint in _VALID_SITE_TYPES:
            ai_conflict_hint = raw_hint

    # site_type: engine + signals authoritative; AI hint for adult only
    site_type = classify_site_type(risk_level, score, signals, ai_conflict_hint)

    # Conflict detection → warnings
    warnings = detect_conflict(risk_level, ai_conflict_hint, signals)

    # Recommended action: rule engine
    recommended_action = generate_recommended_action(risk_level, confidence)

    # Apply fallbacks for text fields
    content_summary  = ai_content_summary  or _FALLBACK_CONTENT.get(bucket, _NO_DATA)
    behavior_summary = ai_behavior_summary or _FALLBACK_BEHAVIOR.get(bucket, _NO_DATA)
    analysis_summary = ai_analysis_summary or (
        _FALLBACK_ANALYSIS.get(bucket, _FALLBACK_ANALYSIS["low"])
        + (f" Tín hiệu: {', '.join(signals[:4])}." if signals else "")
    )

    return {
        "risk_level":        risk_level,
        "score":             round(float(score or 0), 2),
        "confidence":        round(float(confidence or 0), 4),
        "site_type":         site_type,
        "risk_factors":      signals,
        "content_summary":   content_summary,
        "behavior_summary":  behavior_summary,
        "analysis_summary":  analysis_summary,
        "recommended_action": recommended_action,
        "warnings":          warnings,
        "consistent":        True,
    }

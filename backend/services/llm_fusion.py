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
# SIGNAL LABEL MAP
# ========================

_SIGNAL_LABELS: Dict[str, str] = {
    # URL / Domain
    "ip_address":                "URL dùng địa chỉ IP thô",
    "punycode_domain":           "Tên miền mã hoá (Punycode)",
    "high_entropy_domain":       "Tên miền ngẫu nhiên, khó đọc",
    "suspicious_tld":            "Đuôi tên miền đáng ngờ",
    "new_domain":                "Tên miền mới tạo (< 7 ngày)",
    "young_domain":              "Tên miền còn rất mới (< 90 ngày)",
    "too_many_subdomains":       "Quá nhiều tên miền phụ",
    "long_redirect_chain":       "Chuỗi chuyển hướng dài bất thường",
    "datacenter_ip":             "IP tại trung tâm dữ liệu ẩn danh",
    "many_external_links":       "Quá nhiều liên kết ra ngoài",
    # SSL / HTTPS
    "no_https":                  "Không có mã hoá HTTPS",
    "invalid_ssl":               "Chứng chỉ SSL không hợp lệ",
    "expired_ssl":               "Chứng chỉ SSL đã hết hạn",
    "ssl_expiring_soon":         "Chứng chỉ SSL sắp hết hạn",
    "ssl_verification_failed":   "Không xác minh được SSL",
    "ssl_connection_failed":     "Kết nối SSL thất bại",
    "self_signed_certificate":   "Chứng chỉ tự ký (không đáng tin)",
    "certificate_expired":       "Chứng chỉ bảo mật đã hết hạn",
    "certificate_expiring_soon": "Chứng chỉ bảo mật sắp hết hạn",
    "low_trust_issuer":          "Nhà phát hành chứng chỉ kém uy tín",
    "ssl_inspection_error":      "Lỗi khi kiểm tra SSL",
    # DNS
    "dns_not_resolved":          "Không phân giải được tên miền (DNS)",
    "no_safe_ip":                "Không tìm thấy IP hợp lệ",
    "domain_not_exist":          "Tên miền không tồn tại",
    "no_a_record":               "Không có bản ghi DNS (A record)",
    "no_nameservers":            "Không có máy chủ tên miền (NS)",
    # WHOIS
    "whois_failed":              "Không tra được thông tin chủ sở hữu (WHOIS)",
    "whois_missing":             "Thiếu thông tin đăng ký tên miền",
    # Port / Network
    "port_closed":               "Cổng kết nối bị đóng",
    # Forms / Behavior
    "login_form":                "Phát hiện biểu mẫu đăng nhập",
    "http_login_form":           "Form đăng nhập trên kết nối không mã hoá",
    "payment_form":              "Phát hiện biểu mẫu thanh toán",
    "external_form":             "Biểu mẫu gửi dữ liệu ra ngoài",
    "suspicious_password_form":  "Biểu mẫu mật khẩu đáng ngờ",
    "many_iframes":              "Nhiều khung nhúng ẩn (iframe)",
    "many_hidden_inputs":        "Nhiều trường ẩn trong form",
    "hidden_iframe":             "Iframe ẩn phát hiện trong trang",
    "otp_request":               "Trang yêu cầu mã OTP/xác minh",
    # Content
    "brand_impersonation":       "Giả mạo thương hiệu nổi tiếng",
    "suspicious_keywords":       "Từ khoá lừa đảo trong nội dung",
    "suspicious_js":             "Mã JavaScript đáng ngờ",
    "urgency_detected":          "Tạo cảm giác gấp rút, thúc ép",
    "gambling_site":             "Dấu hiệu website cờ bạc/cá cược",
    # Blacklist & Threat Intel
    "blacklisted_url":           "URL có trong danh sách đen",
    "hudson_rock_employee_credentials_stolen":      "Lộ lọt thông tin nhân viên (Hudson Rock)",
    "hudson_rock_high_volume_credentials_stolen":   "Lộ lọt nhiều tài khoản (Hudson Rock)",
    "hudson_rock_credentials_stolen":               "Lộ lọt thông tin tài khoản (Hudson Rock)",
}


def _label(signal: str) -> str:
    """Chuyển raw signal key sang nhãn tiếng Việt dễ đọc."""
    if signal in _SIGNAL_LABELS:
        return _SIGNAL_LABELS[signal]
    if signal.startswith("keyword_"):
        return f"Từ khoá: {signal[8:]}"
    if signal.startswith("suspicious_nameserver:"):
        return f"Máy chủ tên miền đáng ngờ: {signal.split(':', 1)[1]}"
    return signal.replace("_", " ").capitalize()


def _labels(signals: List[str], limit: int = 4) -> str:
    """Trả về chuỗi các nhãn tiếng Việt, ngăn cách bằng dấu phẩy."""
    return ", ".join(_label(s) for s in signals[:limit])


# ========================
# SITE TYPE CLASSIFIER
# ========================

_ADULT_SIGNALS  = {"adult_content", "explicit_content", "18plus"}
_SCAM_SIGNALS   = {
    "brand_impersonation", "blacklisted_url", "http_login_form",
    "external_form", "suspicious_password_form", "payment_form",
}
_GAMBLING_SIGNALS = {
    "gambling_site", "online_casino", "betting_site",
}
_SUSPICIOUS_SIGNALS = {
    "login_form", "new_domain", "young_domain", "punycode_domain",
    "suspicious_tld", "suspicious_js", "hidden_iframe",
    "suspicious_keywords", "many_external_links",
}

_VALID_SITE_TYPES = {"safe", "suspicious", "scam", "adult", "gambling", "unknown"}


def classify_site_type(
    risk_level: str,
    score: float,
    signals: List[str],
    ai_hint: Optional[str] = None,
) -> str:
    """
    Classify site_type using risk engine output + signals as authority.

    Priority order:
      1. Adult   — trust AI hint OR explicit adult signals → never show screenshot
      2. Gambling — AI hint 'gambling' → always DANGEROUS regardless of score
      3. Scam    — high score + scam signals
      4. Suspicious — medium score or suspicious signals
      5. Safe
    """
    signals_set = set(s.lower() for s in (signals or []))

    # 1. Adult: trust AI hint (content the engine cannot detect from URL alone)
    if ai_hint == "adult" or _ADULT_SIGNALS & signals_set:
        return "adult"

    # 2. Gambling: AI classifies as gambling site → treat as dangerous
    if ai_hint == "gambling" or _GAMBLING_SIGNALS & signals_set:
        return "gambling"

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

    # Case 3: Adult content detected
    if hint == "adult":
        warnings.append(
            "⚠️ Phân tích AI phát hiện đây là website chứa nội dung người lớn (18+). "
            "Không phù hợp cho trẻ em và không hiển thị ảnh chụp màn hình."
        )

    # Case 4: Gambling detected
    if hint == "gambling":
        warnings.append(
            "🎰 Phân tích AI phát hiện đây là website cờ bạc/cá cược trực tuyến. "
            "Hoạt động này vi phạm pháp luật tại Việt Nam."
        )

    # Case 5: Engine HIGH but AI says safe
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
    ("high",     True):  "Không nên truy cập website này. Xóa link ngay và cảnh báo người thân. Nếu đã nhập thông tin, hãy đổi mật khẩu.",
    ("high",     False): "Hệ thống phát hiện tín hiệu rủi ro cao. Không nhập thông tin cá nhân hoặc tài khoản ngân hàng.",
    ("medium",   True):  "Cần thận trọng khi truy cập. Không nhập mật khẩu hoặc thông tin tài chính cho đến khi xác minh.",
    ("medium",   False): "Có một số dấu hiệu đáng ngờ. Kiểm tra kỹ URL và truy cập qua kênh chính thức.",
    ("low",      True):  "Có thể truy cập, nhưng nên kiểm tra thông tin trước khi nhập dữ liệu.",
    ("low",      False): "Điểm rủi ro thấp. Tuy nhiên hãy luôn cẩn thận khi nhập thông tin cá nhân.",
    # Special site types
    ("gambling", True):  "🚫 Website cờ bạc/cá cược trực tuyến — hoạt động này vi phạm pháp luật tại Việt Nam. Không tham gia.",
    ("gambling", False): "🚫 Website cờ bạc/cá cược trực tuyến — hoạt động này vi phạm pháp luật tại Việt Nam. Không tham gia.",
    ("adult",    True):  "🔞 Website chứa nội dung người lớn (18+). Không phù hợp cho người chưa đủ 18 tuổi.",
    ("adult",    False): "🔞 Website chứa nội dung người lớn (18+). Không phù hợp cho người chưa đủ 18 tuổi.",
}


def _level_bucket(risk_level: str) -> str:
    level = (risk_level or "low").upper()
    if level in ("CRITICAL", "HIGH"):
        return "high"
    if level == "MEDIUM":
        return "medium"
    return "low"


def generate_recommended_action(risk_level: str, confidence: float, site_type: str = "") -> str:
    """Rule-based only — LLM never generates this."""
    # Site-type-specific actions take highest priority
    if site_type in ("gambling", "adult"):
        conf_ok = float(confidence or 0) >= 0.3
        key = (site_type, conf_ok)
        if key in _ACTION_RULES:
            return _ACTION_RULES[key]
    bucket  = _level_bucket(risk_level)
    conf_ok = float(confidence or 0) >= 0.3
    return _ACTION_RULES.get((bucket, conf_ok), _ACTION_RULES[(bucket, False)])


# ========================
# FALLBACKS (user-friendly)
# ========================

_NO_DATA = "Chưa thu thập được nội dung trang web."

_FALLBACK_CONTENT: Dict[str, str] = {
    "low":      "Không thu thập được nội dung trang web (có thể do timeout hoặc site chặn crawler).",
    "medium":   "Không thu thập được nội dung trang web. Đánh giá dựa trên tín hiệu kỹ thuật.",
    "high":     "Không thu thập được nội dung trang web. Cảnh báo dựa trên tín hiệu kỹ thuật nguy hiểm.",
}

_FALLBACK_BEHAVIOR: Dict[str, str] = {
    "low":      "Không phát hiện hành vi kỹ thuật đáng chú ý.",
    "medium":   "Phát hiện một số tín hiệu kỹ thuật đáng ngờ — xem chi tiết bên dưới.",
    "high":     "Nhiều hành vi kỹ thuật nguy hiểm được phát hiện — xem tín hiệu bên dưới.",
}

_FALLBACK_ANALYSIS: Dict[str, str] = {
    "low":      "Điểm rủi ro thấp: ML model và rule engine không phát hiện tín hiệu nguy hiểm đáng kể.",
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
      - site_type          → computed from signals + engine, AI hint for adult/gambling
      - warnings           → populated when AI/engine disagree
      - All text fields    → LLM-provided when available and clean; fallback otherwise
    """
    bucket  = _level_bucket(risk_level)
    conf_ok = float(confidence or 0) >= 0.3

    # Extract AI fields
    ai_content_summary   = None
    ai_behavior_summary  = None
    ai_analysis_summary  = None
    ai_conflict_hint     = None

    if isinstance(llm_raw, dict):
        ai_content_summary  = _safe_text(llm_raw.get("content_summary"))
        ai_behavior_summary = _safe_text(llm_raw.get("behavior_summary"))
        ai_analysis_summary = _safe_text(llm_raw.get("analysis_summary"))

        raw_hint = str(llm_raw.get("conflict_hint") or "").lower().strip()
        if raw_hint in _VALID_SITE_TYPES:
            ai_conflict_hint = raw_hint

    # site_type: engine + signals authoritative; AI hint for adult/gambling
    site_type = classify_site_type(risk_level, score, signals, ai_conflict_hint)

    # Override risk level for gambling sites — always treat as HIGH/dangerous
    effective_risk_level = risk_level
    effective_score      = score
    if site_type == "gambling":
        effective_risk_level = "HIGH"
        effective_score      = max(score, 70.0)
        logger.warning("gambling_site_detected | score_overridden_to=%.1f", effective_score)

    # Conflict detection → warnings
    warnings = detect_conflict(effective_risk_level, ai_conflict_hint, signals)

    # Adult site: add special warning if not already from detect_conflict
    is_adult = (site_type == "adult")
    if is_adult and not any("18+" in w for w in warnings):
        warnings.append(
            "🔞 Đây là website chứa nội dung người lớn (18+). "
            "Không hiển thị ảnh chụp màn hình. Không phù hợp cho người chưa đủ 18 tuổi."
        )

    # Recommended action: rule engine (with site_type awareness)
    recommended_action = generate_recommended_action(effective_risk_level, confidence, site_type)

    # Apply fallbacks for text fields
    content_summary  = ai_content_summary  or _FALLBACK_CONTENT.get(bucket, _NO_DATA)
    behavior_summary = ai_behavior_summary or _FALLBACK_BEHAVIOR.get(bucket, _NO_DATA)
    analysis_summary = ai_analysis_summary or (
        _FALLBACK_ANALYSIS.get(bucket, _FALLBACK_ANALYSIS["low"])
        + (f" Tín hiệu phát hiện: {_labels(signals)}." if signals else "")
    )

    # Adult site: override content/behavior summary
    if is_adult:
        content_summary  = "🔞 Website này chứa nội dung người lớn (18+). Không thu thập và hiển thị nội dung."
        behavior_summary = "Không phân tích hành vi — website 18+ có hình ảnh/nội dung người lớn không thể hiển thị."

    # Gambling site: override analysis summary
    if site_type == "gambling":
        analysis_summary = (
            f"🎰 Website cờ bạc/cá cược trực tuyến được phát hiện. "
            f"Hoạt động này vi phạm pháp luật tại Việt Nam (điểm rủi ro điều chỉnh lên {round(effective_score)}%). "
            + (f"Tín hiệu phát hiện: {_labels(signals)}." if signals else "")
        )

    return {
        "risk_level":         effective_risk_level,
        "score":              round(float(effective_score or 0), 2),
        "confidence":         round(float(confidence or 0), 4),
        "site_type":          site_type,
        "risk_factors":       signals,
        "content_summary":    content_summary,
        "behavior_summary":   behavior_summary,
        "analysis_summary":   analysis_summary,
        "recommended_action": recommended_action,
        "warnings":           warnings,
        "consistent":         True,
        "is_adult":           is_adult,       # Used by API to suppress screenshot
    }

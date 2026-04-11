import re
from typing import Dict, Any, List, Tuple

# ========================
# Scam patterns (VI + EN)
# ========================

_SCAM_PATTERNS_VI = [
    (r"(?i)xác\s*minh\s*tài\s*khoản", "verify_account"),
    (r"(?i)đăng\s*nhập\s*ngay", "login_urgent"),
    (r"(?i)bị\s*khóa", "account_locked"),
    (r"(?i)khẩn\s*cấp", "urgent_action"),
    (r"(?i)cập\s*nhật\s*thông\s*tin", "update_info"),
    (r"(?i)chuyển\s*(tiền|khoản)", "transfer_money"),
    (r"(?i)mã\s*otp|otp\s*của\s*bạn", "otp_request"),
    (r"(?i)nhấn\s*vào\s*link|bấm\s*vào\s*đây", "click_link"),
    (r"(?i)trúng\s*thưởng|nhận\s*quà", "prize_claim"),
    (r"(?i)hết\s*hạn\s*trong\s*\d+\s*(phút|giờ|ngày)", "urgency_deadline"),
]

_SCAM_PATTERNS_EN = [
    (r"(?i)verify\s*(your\s*)?account", "verify_account"),
    (r"(?i)login\s*now|sign\s*in\s*immediately", "login_urgent"),
    (r"(?i)account\s*(has\s*been\s*)?(locked|suspended)", "account_locked"),
    (r"(?i)urgent|asap|immediately", "urgent_action"),
    (r"(?i)update\s*(your\s*)?(info|information)", "update_info"),
    (r"(?i)transfer\s*(money|funds)", "transfer_money"),
    (r"(?i)(your\s*)?otp|one[- ]?time\s*password", "otp_request"),
    (r"(?i)click\s*(here|the\s*link)", "click_link"),
    (r"(?i)you\s*(have\s*)?won|claim\s*(your\s*)?prize", "prize_claim"),
]

_ALL_PATTERNS = _SCAM_PATTERNS_VI + _SCAM_PATTERNS_EN


# ========================
# Pattern scoring
# ========================
def _pattern_score(flags: List[str]) -> float:
    weights = {
        "urgent_action": 0.35,
        "verify_account": 0.25,
        "login_urgent": 0.2,
        "account_locked": 0.25,
        "update_info": 0.2,
        "transfer_money": 0.3,
        "otp_request": 0.35,
        "click_link": 0.15,
        "prize_claim": 0.25,
        "urgency_deadline": 0.4,
    }
    return min(1.0, sum(weights.get(f, 0.15) for f in flags))


# ========================
# Analyzer core
# ========================
def analyze_text(text: str) -> Dict[str, Any]:
    if not text or not isinstance(text, str):
        return {
            "score": 0.0,
            "flags": [],
            "patterns": [],
            "raw_length": 0,
        }

    text = text.strip()
    raw_length = len(text)

    if raw_length > 50000:
        text = text[:50000]

    flags: List[str] = []
    patterns: List[Tuple[str, str]] = []

    for pattern, name in _ALL_PATTERNS:
        match = re.search(pattern, text)
        if match:
            if name not in flags:
                flags.append(name)
            patterns.append((name, match.group(0)[:100]))

    score = _pattern_score(flags)

    return {
        "score": round(score, 4),
        "flags": flags,
        "patterns": patterns[:20],
        "raw_length": raw_length,
    }
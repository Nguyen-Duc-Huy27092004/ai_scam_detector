from typing import List
from backend.ml.text.analyzer import analyze_text
from backend.entities.scam_evidence import ScamEvidence


_SEVERITY_MAP = {
    "urgent_action": "high",
    "verify_account": "medium",
    "login_urgent": "medium",
    "account_locked": "medium",
    "update_info": "medium",
    "transfer_money": "high",
    "otp_request": "high",
    "click_link": "low",
    "prize_claim": "medium",
    "urgency_deadline": "high",
}

_EXPLANATION_MAP = {
    "urgent_action": "Nội dung tạo áp lực khẩn cấp để người dùng hành động vội vàng",
    "verify_account": "Yêu cầu xác minh tài khoản - dấu hiệu lừa đảo phổ biến",
    "login_urgent": "Yêu cầu đăng nhập ngay - thường dẫn tới trang giả mạo",
    "account_locked": "Thông báo tài khoản bị khóa - chiêu trò lừa đảo",
    "update_info": "Yêu cầu cập nhật thông tin cá nhân",
    "transfer_money": "Yêu cầu chuyển tiền - dấu hiệu lừa đảo tài chính",
    "otp_request": "Yêu cầu mã OTP - nguy cơ chiếm quyền tài khoản",
    "click_link": "Yêu cầu nhấn link - có thể dẫn tới website giả mạo",
    "prize_claim": "Thông báo trúng thưởng - chiêu trò lừa đảo",
    "urgency_deadline": "Tạo giới hạn thời gian để gây hoảng loạn",
}


def predict_text_scam(text: str, source: str = "text") -> List[ScamEvidence]:
    if not text or not isinstance(text, str):
        return []

    analysis = analyze_text(text)
    flags = analysis.get("flags", [])
    patterns = analysis.get("patterns", [])

    evidences: List[ScamEvidence] = []

    for flag in flags:
        severity = _SEVERITY_MAP.get(flag, "medium")
        explanation = _EXPLANATION_MAP.get(flag, f"Phát hiện dấu hiệu: {flag}")

        keyword_match = None
        for pat_name, pat_text in patterns:
            if pat_name == flag:
                keyword_match = pat_text
                break

        evidence = ScamEvidence(
            source=source,
            keyword=keyword_match or flag,
            explanation=explanation,
            severity=severity,
            flag_name=flag,
        )
        evidences.append(evidence)

    return evidences
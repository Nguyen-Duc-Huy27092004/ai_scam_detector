"""
Prompt templates for scam explanation and user advice.
Style inspired by chongluadao.vn
Rule-based explanation engine (no external LLM).
"""

from typing import List, Dict, Any


# ==============================
# Risk level templates
# ==============================

RISK_TEMPLATES = {
    "low": {
        "title": "Mức độ rủi ro thấp",
        "summary": "Chưa phát hiện dấu hiệu lừa đảo rõ ràng trong nội dung hoặc website này.",
        "advice": [
            "Bạn vẫn nên thận trọng khi cung cấp thông tin cá nhân.",
            "Kiểm tra kỹ tên miền và nguồn gửi liên kết.",
            "Ưu tiên truy cập website chính thức của tổ chức."
        ]
    },
    "medium": {
        "title": "Trang web có dấu hiệu đáng ngờ",
        "summary": "Phát hiện một số dấu hiệu thường xuất hiện trong các hình thức lừa đảo trực tuyến.",
        "advice": [
            "Không nên đăng nhập hoặc cung cấp thông tin cá nhân trên trang này.",
            "Không bấm vào các liên kết không rõ nguồn gốc.",
            "Tìm kiếm thêm thông tin hoặc đánh giá từ cộng đồng."
        ]
    },
    "high": {
        "title": "⚠️ CẢNH BÁO: Nguy cơ lừa đảo cao",
        "summary": "Nội dung chứa nhiều dấu hiệu đặc trưng của hành vi lừa đảo và có khả năng gây thiệt hại cho người dùng.",
        "advice": [
            "Tuyệt đối không nhập mật khẩu, mã OTP hoặc thông tin thẻ ngân hàng.",
            "Không chuyển tiền hoặc thực hiện bất kỳ giao dịch nào.",
            "Bạn nên báo cáo website/nội dung này cho cơ quan chức năng hoặc hệ thống chống lừa đảo."
        ]
    }
}


# ==============================
# Flag explanations
# ==============================

FLAG_EXPLANATIONS = {
    "urgent_action": "Nội dung tạo cảm giác khẩn cấp để thúc ép người dùng hành động ngay.",
    "verify_account": "Yêu cầu xác minh tài khoản – dấu hiệu phổ biến của lừa đảo.",
    "login_urgent": "Dụ người dùng đăng nhập ngay vào trang giả mạo.",
    "account_locked": "Thông báo tài khoản bị khóa nhằm gây hoang mang.",
    "update_info": "Yêu cầu cập nhật thông tin cá nhân có thể nhằm đánh cắp dữ liệu.",
    "transfer_money": "Yêu cầu chuyển tiền – dấu hiệu lừa đảo tài chính.",
    "otp_request": "Yêu cầu mã OTP – nguy cơ cao bị chiếm quyền tài khoản.",
    "click_link": "Dẫn dụ người dùng bấm vào liên kết không rõ nguồn gốc.",
    "prize_claim": "Thông báo trúng thưởng – chiêu trò lừa đảo phổ biến.",
    "urgency_deadline": "Đặt thời hạn ngắn để tạo áp lực tâm lý.",
    "new_domain": "Tên miền mới được đăng ký – thường được dùng cho các chiến dịch lừa đảo.",
    "suspicious_tld": "Tên miền thuộc nhóm TLD thường bị lợi dụng cho lừa đảo.",
    "too_many_subdomains": "Sử dụng nhiều subdomain bất thường để đánh lừa người dùng.",
    "invalid_ssl": "Website không có chứng chỉ bảo mật SSL hợp lệ.",
    "ip_address": "Sử dụng địa chỉ IP thay vì tên miền – dấu hiệu bất thường."
}


# ==============================
# Scam type explanation
# ==============================

SCAM_TYPE_EXPLANATION = {
    "banking_phishing": "Giả mạo ngân hàng hoặc tổ chức tài chính để đánh cắp thông tin đăng nhập.",
    "financial_scam": "Lừa đảo liên quan đến chuyển tiền hoặc thanh toán.",
    "lottery_scam": "Thông báo trúng thưởng giả mạo.",
    "impersonation": "Giả mạo tổ chức, cá nhân hoặc doanh nghiệp.",
    "unknown": "Chưa xác định rõ loại hình lừa đảo."
}


# ==============================
# Helper functions
# ==============================

def _build_reasons(flags: List[str]) -> List[str]:
    reasons = []
    for f in flags:
        if f in FLAG_EXPLANATIONS:
            reasons.append(FLAG_EXPLANATIONS[f])
        else:
            reasons.append(f"Phát hiện dấu hiệu đáng ngờ: {f}")
    return reasons


def _build_advice(risk_level: str) -> List[str]:
    tpl = RISK_TEMPLATES.get(risk_level, RISK_TEMPLATES["low"])
    return tpl["advice"]


# ==============================
# Main generators
# ==============================

def generate_text_advice(
    risk_level: str,
    flags: List[str],
    scam_type: str = "unknown"
) -> Dict[str, Any]:

    template = RISK_TEMPLATES.get(risk_level, RISK_TEMPLATES["low"])
    reasons = _build_reasons(flags)

    return {
        "title": template["title"],
        "summary": template["summary"],
        "scam_type": SCAM_TYPE_EXPLANATION.get(scam_type, SCAM_TYPE_EXPLANATION["unknown"]),
        "reasons": reasons,
        "advice": template["advice"]
    }


def generate_url_advice(
    risk_level: str,
    risk_factors: List[str],
    domain_info: Dict[str, Any] = None,
    scam_type: str = "unknown"
) -> Dict[str, Any]:

    template = RISK_TEMPLATES.get(risk_level, RISK_TEMPLATES["low"])
    reasons = _build_reasons(risk_factors)

    domain_notes = []
    if domain_info:
        if domain_info.get("age_days") is not None:
            domain_notes.append(f"Tuổi đời tên miền: {domain_info['age_days']} ngày")
        if not domain_info.get("is_https"):
            domain_notes.append("Website không sử dụng HTTPS")

    return {
        "title": template["title"],
        "summary": template["summary"],
        "scam_type": SCAM_TYPE_EXPLANATION.get(scam_type, SCAM_TYPE_EXPLANATION["unknown"]),
        "reasons": reasons,
        "domain_notes": domain_notes,
        "advice": template["advice"]
    }


def generate_image_advice(
    risk_level: str,
    ocr_flags: List[str]
) -> Dict[str, Any]:

    template = RISK_TEMPLATES.get(risk_level, RISK_TEMPLATES["low"])
    reasons = _build_reasons(ocr_flags)

    return {
        "title": template["title"],
        "summary": template["summary"],
        "reasons": reasons,
        "advice": template["advice"]
    }


def generate_final_advice(
    input_type: str,
    risk_level: str,
    flags: List[str],
    scam_type: str = "unknown",
    domain_info: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Unified advice generator for text / url / image
    """

    if input_type == "url":
        return generate_url_advice(risk_level, flags, domain_info, scam_type)
    elif input_type == "image":
        return generate_image_advice(risk_level, flags)
    else:
        return generate_text_advice(risk_level, flags, scam_type)
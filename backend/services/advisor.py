"""
Advisor Service — Production-hardened
Generates contextual security advice based on analysis results.
All paths are None-safe: risk_level, analysis_type, risk_factors can all be None.
"""

from typing import List, Dict, Optional
from utils.logger import logger


# ========================
# TEMPLATES
# ========================

ADVICE_TEMPLATES = {
    "url": {
        "low":      "Website này có vẻ an toàn. Tuy nhiên hãy kiểm tra kỹ nguồn gửi link trước khi nhập thông tin.",
        "medium":   "⚠️ Website có dấu hiệu đáng nghi. Không nên nhập thông tin cá nhân hoặc tài khoản ngân hàng.",
        "high":     "🚨 NGUY HIỂM: Website có dấu hiệu lừa đảo rõ ràng. Tuyệt đối không truy cập hoặc cung cấp thông tin.",
        "critical": "🚨 CỰC KỲ NGUY HIỂM: Website này là lừa đảo đã được xác nhận. Báo cáo ngay cho cơ quan chức năng.",
        "unknown":  "Không xác định được mức độ rủi ro. Hãy thận trọng và không cung cấp thông tin nhạy cảm.",
    },
    "text": {
        "low":      "Nội dung tin nhắn có vẻ an toàn. Tuy nhiên hãy luôn cảnh giác với thông tin không rõ nguồn gốc.",
        "medium":   "⚠️ Tin nhắn có dấu hiệu lừa đảo. Không làm theo hướng dẫn và không chuyển tiền.",
        "high":     "🚨 NGUY HIỂM: Đây rất có thể là tin nhắn lừa đảo. Xóa và báo cáo ngay.",
        "critical": "🚨 CỰC KỲ NGUY HIỂM: Tin nhắn lừa đảo đã được xác nhận. Không phản hồi và báo cáo ngay.",
        "unknown":  "Không xác định được. Hãy thận trọng và xác minh thông tin qua kênh chính thức.",
    },
    "image": {
        "low":      "Hình ảnh không phát hiện dấu hiệu lừa đảo rõ ràng.",
        "medium":   "⚠️ Hình ảnh có nội dung đáng nghi. Nên xác minh nguồn gốc trước khi tin tưởng.",
        "high":     "🚨 NGUY HIỂM: Hình ảnh chứa nội dung lừa đảo. Không chia sẻ và xóa ngay.",
        "critical": "🚨 CỰC KỲ NGUY HIỂM: Hình ảnh lừa đảo đã được xác nhận. Báo cáo ngay.",
        "unknown":  "Không xác định được. Hãy thận trọng với nguồn gốc hình ảnh này.",
    },
}

RISK_FACTORS_MAP = {
    "new_domain":            "Tên miền mới đăng ký (dưới 30 ngày)",
    "young_domain":          "Tên miền khá mới (dưới 90 ngày)",
    "no_https":              "Website không sử dụng HTTPS bảo mật",
    "http_login_form":       "Form đăng nhập qua HTTP (không mã hóa)",
    "ip_address":            "URL sử dụng địa chỉ IP thay vì tên miền",
    "multiple_dashes":       "Tên miền chứa nhiều dấu gạch ngang bất thường",
    "phishing_keywords":     "Tên miền chứa từ khóa giả mạo phổ biến",
    "suspicious_patterns":   "Phát hiện nhiều mẫu hành vi đáng nghi",
    "brand_impersonation":   "Tên miền giả mạo thương hiệu nổi tiếng",
    "login_form":            "Phát hiện form thu thập thông tin đăng nhập",
    "external_form":         "Form gửi dữ liệu đến server bên ngoài",
    "suspicious_password_form": "Form thu thập mật khẩu gửi ra ngoài",
    "blacklisted_url":       "URL có trong danh sách đen lừa đảo",
    "expired_ssl":           "Chứng chỉ SSL đã hết hạn",
    "invalid_ssl":           "Chứng chỉ SSL không hợp lệ",
    "no_safe_ip":            "Không tìm thấy địa chỉ IP hợp lệ cho tên miền",
    "many_iframes":          "Trang web chứa nhiều iframe ẩn bất thường",
    "many_hidden_inputs":    "Phát hiện nhiều input ẩn thu thập dữ liệu",
    "long_redirect_chain":   "Chuỗi redirect dài bất thường (che giấu đích thật)",
    "datacenter_ip":         "Máy chủ ở datacenter (không phải hosting thông thường)",
    "content_flags":         "Nội dung website có ngôn ngữ lừa đảo",
    "unusual_text":          "Văn bản chứa từ khóa lừa đảo điển hình",
    "high_entropy":          "Tên miền có entropy cao (có thể là tạo tự động)",
    "punycode_domain":       "Tên miền dùng Punycode (giả mạo ký tự tương tự)",
    "suspicious_tld":        "Đuôi tên miền bất thường, ít dùng",
}

RECOMMENDATIONS = {
    "url": {
        "high":   [
            "Không truy cập website này",
            "Không nhập thông tin đăng nhập hoặc tài khoản ngân hàng",
            "Báo cáo URL cho cơ quan chức năng hoặc nhà cung cấp dịch vụ",
            "Xóa tin nhắn chứa link này",
            "Cảnh báo người thân về link lừa đảo này",
        ],
        "medium": [
            "Kiểm tra chính tả kỹ của đường link",
            "Đảm bảo URL bắt đầu bằng https:// từ domain chính thức",
            "Không nhập mật khẩu hoặc thông tin tài chính",
            "Xác minh qua kênh liên lạc chính thức của tổ chức",
        ],
        "low": [
            "Vẫn nên kiểm tra kỹ URL trước khi cung cấp thông tin",
            "Đảm bảo website sử dụng HTTPS",
            "Không chia sẻ thông tin nhạy cảm nếu không chắc chắn",
        ],
    },
    "text": {
        "high":   [
            "Không làm theo bất kỳ hướng dẫn nào trong tin nhắn",
            "Không chuyển tiền hoặc cung cấp thông tin tài khoản",
            "Báo cáo tin nhắn lừa đảo cho cơ quan chức năng",
            "Chặn số điện thoại / tài khoản gửi tin này",
        ],
        "medium": [
            "Xác minh danh tính người gửi qua kênh khác",
            "Không cung cấp OTP hoặc thông tin đăng nhập",
            "Liên hệ trực tiếp tổ chức liên quan để xác nhận",
        ],
        "low": [
            "Tiếp tục thận trọng với thông tin nhận được",
            "Không chia sẻ thông tin cá nhân",
        ],
    },
    "image": {
        "high":   [
            "Không tin tưởng thông tin trong hình ảnh",
            "Không thực hiện giao dịch dựa trên hình ảnh này",
            "Báo cáo hình ảnh lừa đảo",
        ],
        "medium": [
            "Xác minh thông tin qua kênh chính thức",
            "Không chia sẻ hình ảnh này",
        ],
        "low": [
            "Vẫn nên xác minh nguồn gốc hình ảnh",
        ],
    },
}


# ========================
# SAFE HELPERS
# ========================

def _safe_str(value, default: str = "") -> str:
    """Chuyển đổi an toàn sang string, trả default nếu None hoặc exception."""
    if value is None:
        return default
    try:
        return str(value).lower().strip()
    except Exception:
        return default


def _normalize_risk_level(risk_level) -> str:
    """
    Chuẩn hóa risk_level từ các nguồn khác nhau.
    calculate_risk() trả 'LOW'/'MEDIUM'/'HIGH'/'CRITICAL'/'UNKNOWN'.
    advisor dùng lowercase: 'low'/'medium'/'high'/'critical'/'unknown'.
    """
    normalized = _safe_str(risk_level, "unknown")
    # Map các alias
    aliases = {
        "dangerous":   "high",
        "safe":        "low",
        "suspicious":  "medium",
        "very_high":   "critical",
    }
    return aliases.get(normalized, normalized)


def _get_risk_bucket(risk_level_norm: str) -> str:
    """Map risk level sang bucket high/medium/low cho recommendations."""
    if risk_level_norm in ("critical", "high"):
        return "high"
    if risk_level_norm == "medium":
        return "medium"
    return "low"


# ========================
# PUBLIC API
# ========================

class AdvisorService:
    """Generate human-readable advice from analysis results. All methods are None-safe."""

    @staticmethod
    def generate_advice(
        analysis_type: Optional[str],
        risk_level: Optional[str],
        risk_factors: Optional[List[str]] = None,
        confidence: float = 0.0,
    ) -> Dict:
        try:
            # FIX: Normalize inputs — None-safe throughout
            analysis_type_norm = _safe_str(analysis_type, "url")
            if analysis_type_norm not in ADVICE_TEMPLATES:
                analysis_type_norm = "url"

            risk_level_norm = _normalize_risk_level(risk_level)
            if risk_level_norm not in ADVICE_TEMPLATES[analysis_type_norm]:
                risk_level_norm = "unknown"

            # FIX: risk_factors luôn là list sạch (không có None)
            factors_clean: List[str] = []
            if risk_factors:
                for f in risk_factors:
                    if f and isinstance(f, str):
                        factors_clean.append(f.strip())

            advice_text = ADVICE_TEMPLATES[analysis_type_norm].get(
                risk_level_norm,
                f"Mức độ rủi ro: {risk_level_norm.upper()}"
            )

            risk_summary = AdvisorService.get_risk_factors_summary(factors_clean)

            bucket = _get_risk_bucket(risk_level_norm)
            recommendations = (
                RECOMMENDATIONS.get(analysis_type_norm, {}).get(bucket, [])
            )

            logger.info(
                "advice_generated | type=%s | risk=%s | confidence=%.2f | factors=%d",
                analysis_type_norm, risk_level_norm, float(confidence or 0), len(factors_clean)
            )

            return {
                "advice":          advice_text,
                "risk_summary":    risk_summary,
                "recommendations": recommendations,
                "confidence":      round(float(confidence or 0.0), 2),
            }

        except Exception as e:
            logger.error("advice_generation_failed | error=%s", str(e))
            return {
                "advice":          "Không thể sinh tư vấn. Vui lòng xem kết quả phân tích.",
                "risk_summary":    [],
                "recommendations": [],
                "confidence":      0.0,
            }

    @staticmethod
    def get_risk_factors_summary(risk_factors: List[str]) -> List[str]:
        if not risk_factors:
            return ["Không phát hiện yếu tố rủi ro nghiêm trọng."]
        summary = []
        seen = set()
        for factor in risk_factors:
            if not factor or factor in seen:
                continue
            seen.add(factor)
            label = RISK_FACTORS_MAP.get(factor)
            if not label:
                # Chuyển keyword_xxx → human readable
                if factor.startswith("keyword_"):
                    kw = factor[8:].replace("_", " ")
                    label = f"Từ khóa lừa đảo: '{kw}'"
                else:
                    label = factor.replace("_", " ").capitalize()
            summary.append(label)
            if len(summary) >= 7:
                break
        return summary

    @staticmethod
    def get_recommendations(
        risk_level: Optional[str],
        analysis_type: Optional[str],
    ) -> List[str]:
        analysis_type_norm = _safe_str(analysis_type, "url")
        if analysis_type_norm not in RECOMMENDATIONS:
            analysis_type_norm = "url"
        risk_level_norm = _normalize_risk_level(risk_level)
        bucket = _get_risk_bucket(risk_level_norm)
        return RECOMMENDATIONS.get(analysis_type_norm, {}).get(bucket, [])


# ========================
# CONVENIENCE FUNCTIONS (backward compatible)
# ========================

def generate_advice(
    analysis_type: Optional[str],
    risk_level: Optional[str],
    risk_factors=None,
    confidence: float = 0.0,
) -> Dict:
    return AdvisorService.generate_advice(
        analysis_type, risk_level, risk_factors, confidence
    )


def get_recommendations(
    risk_level: Optional[str],
    analysis_type: Optional[str],
) -> List[str]:
    return AdvisorService.get_recommendations(risk_level, analysis_type)
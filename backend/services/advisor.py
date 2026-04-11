"""
AI-powered advice generation service.
Generate contextual advice based on analysis results.
"""

from typing import List, Dict
from utils.logger import logger


class AdvisorService:

    ADVICE_TEMPLATES = {
        "url": {
            "low": [
                "Website này có vẻ an toàn. Tuy nhiên bạn vẫn nên kiểm tra kỹ nguồn gửi link."
            ],
            "medium": [
                "Website có một số dấu hiệu đáng nghi. Không nên nhập thông tin cá nhân."
            ],
            "high": [
                "⚠️ NGUY HIỂM: Website này có dấu hiệu lừa đảo rõ ràng. Tuyệt đối không truy cập."
            ]
        },
        "text": {
            "low": [
                "Nội dung tin nhắn có vẻ an toàn. Tuy nhiên hãy luôn cảnh giác."
            ],
            "medium": [
                "Tin nhắn có một số dấu hiệu lừa đảo. Không nên làm theo hướng dẫn."
            ],
            "high": [
                "⚠️ NGUY HIỂM: Đây rất có thể là tin nhắn lừa đảo."
            ]
        },
        "image": {
            "low": [
                "Hình ảnh không phát hiện dấu hiệu lừa đảo."
            ],
            "medium": [
                "Hình ảnh có nội dung đáng nghi. Nên xác minh nguồn gốc."
            ],
            "high": [
                "⚠️ NGUY HIỂM: Hình ảnh chứa nội dung lừa đảo."
            ]
        }
    }

    RISK_FACTORS_MAP = {
        "new_domain": "Tên miền mới đăng ký (dưới 30 ngày)",
        "no_https": "Website không sử dụng HTTPS",
        "ip_address": "URL sử dụng địa chỉ IP thay vì tên miền",
        "multiple_dashes": "Tên miền chứa nhiều dấu gạch ngang",
        "phishing_keywords": "Tên miền chứa từ khóa giả mạo",
        "suspicious_patterns": "Phát hiện nhiều mẫu hành vi đáng nghi",
        "content_flags": "Nội dung website có ngôn ngữ lừa đảo",
        "unusual_text": "Văn bản chứa từ khóa lừa đảo hoặc gây hoang mang"
    }

    @staticmethod
    def generate_advice(
        analysis_type: str,
        risk_level: str,
        risk_factors: List[str] = None,
        confidence: float = 0.0
    ) -> Dict:

        try:
            analysis_type = analysis_type.lower()
            risk_level = risk_level.lower()

            templates = AdvisorService.ADVICE_TEMPLATES.get(analysis_type, {})
            advice_list = templates.get(risk_level, [])

            advice_text = advice_list[0] if advice_list else f"Mức độ rủi ro: {risk_level.upper()}"

            risk_summary = AdvisorService.get_risk_factors_summary(risk_factors or [])
            recommendations = AdvisorService.get_recommendations(risk_level, analysis_type)

            logger.info(
                "advice_generated | type=%s | risk=%s | confidence=%.2f",
                analysis_type, risk_level, confidence
            )

            return {
                "advice": advice_text,
                "risk_summary": risk_summary,
                "recommendations": recommendations,
                "confidence": round(confidence, 2)
            }

        except Exception as e:
            logger.error("advice_generation_failed | error=%s", str(e))
            return {
                "advice": "Không thể sinh tư vấn. Vui lòng xem kết quả phân tích.",
                "risk_summary": "",
                "recommendations": []
            }

    @staticmethod
    def get_risk_factors_summary(risk_factors: List[str]) -> List[str]:
        if not risk_factors:
            return ["Không phát hiện yếu tố rủi ro nghiêm trọng."]

        summary = []
        for factor in risk_factors[:5]:
            summary.append(
                AdvisorService.RISK_FACTORS_MAP.get(factor, factor)
            )

        return summary

    @staticmethod
    def get_recommendations(risk_level: str, analysis_type: str) -> List[str]:
        recs = []

        if risk_level == "high":
            recs.extend([
                "Không truy cập hoặc tương tác với nội dung này",
                "Báo cáo cho quản trị hệ thống hoặc nhà cung cấp dịch vụ",
                "Không cung cấp thông tin cá nhân hoặc tài khoản",
                "Xóa nội dung này ngay lập tức"
            ])
        elif risk_level == "medium":
            recs.extend([
                "Kiểm tra lại nguồn gửi",
                "Xác minh thông tin qua kênh chính thức",
                "Không nhập thông tin nhạy cảm",
                "Tham khảo ý kiến chuyên gia"
            ])
        else:
            recs.extend([
                "Tiếp tục sử dụng nhưng cần cảnh giác",
                "Không chia sẻ thông tin cá nhân",
                "Luôn cập nhật phần mềm bảo mật"
            ])

        if analysis_type == "url":
            recs.extend([
                "Kiểm tra chính tả của đường link",
                "Đảm bảo website sử dụng HTTPS",
                "Không đăng nhập nếu không chắc chắn"
            ])

        return recs


# Convenience functions
def generate_advice(analysis_type: str, risk_level: str, risk_factors=None, confidence=0.0):
    return AdvisorService.generate_advice(analysis_type, risk_level, risk_factors, confidence)


def get_recommendations(risk_level: str, analysis_type: str):
    return AdvisorService.get_recommendations(risk_level, analysis_type)
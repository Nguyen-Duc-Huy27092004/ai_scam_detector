from typing import List, Dict, Any
from entities.scam_evidence import ScamEvidence


class EvidenceBuilder:

    @staticmethod
    def build(
        domain_intel: Dict[str, Any],
        ml_confidence: float,
        deep_signals: List[str],
        content_flags: List[str],
        redirect_chain: List[str],
        dns_result: Dict[str, Any],
        ssl_result: Dict[str, Any],
        brand_result: Dict[str, Any]
    ) -> List[ScamEvidence]:

        evidences: List[ScamEvidence] = []

        # =========================
        # 0. CLEAN DATA (🔥 quan trọng)
        # =========================
        deep_signals = list(set(deep_signals or []))
        content_flags = list(set(content_flags or []))

        domain_name = domain_intel.get("domain", "unknown")

        # =========================
        # 1. DOMAIN ANALYSIS
        # =========================
        if not domain_intel.get("is_https"):
            evidences.append(ScamEvidence(
                source="domain",
                keyword="no_https",
                explanation=f"Website {domain_name} không sử dụng HTTPS (kết nối không an toàn)",
                severity="HIGH"
            ))

        age = domain_intel.get("age_days")
        if age is not None and age < 30:
            evidences.append(ScamEvidence(
                source="domain",
                keyword="young_domain",
                explanation=f"Domain {domain_name} mới tạo ({age} ngày), độ tin cậy thấp",
                severity="HIGH"
            ))

        if domain_intel.get("is_suspicious_tld"):
            evidences.append(ScamEvidence(
                source="domain",
                keyword="suspicious_tld",
                explanation=f"Domain {domain_name} sử dụng TLD có rủi ro cao (.xyz, .top, ...)",
                severity="MEDIUM"
            ))

        # =========================
        # 2. MACHINE LEARNING
        # =========================
        if ml_confidence > 0.8:
            evidences.append(ScamEvidence(
                source="ml",
                keyword="ml_very_high_risk",
                explanation="Hệ thống AI đánh giá website có mức độ nguy hiểm rất cao",
                severity="HIGH"
            ))
        elif ml_confidence > 0.6:
            evidences.append(ScamEvidence(
                source="ml",
                keyword="ml_suspicious",
                explanation="Hệ thống AI đánh giá website có dấu hiệu đáng ngờ",
                severity="MEDIUM"
            ))

        # =========================
        # 3. REDIRECT
        # =========================
        if len(redirect_chain) > 2:
            evidences.append(ScamEvidence(
                source="redirect",
                keyword="long_redirect_chain",
                explanation="Website sử dụng nhiều bước chuyển hướng bất thường (có thể che giấu đích đến)",
                severity="MEDIUM"
            ))

        # =========================
        # 4. DEEP ANALYSIS (HTML/JS)
        # =========================
        for signal in deep_signals:
            evidences.append(ScamEvidence(
                source="content",
                keyword=signal,
                explanation=EvidenceBuilder._map_signal(signal),
                severity=EvidenceBuilder._get_severity(signal)
            ))

        # =========================
        # 5. CONTENT NLP
        # =========================
        for flag in content_flags:
            evidences.append(ScamEvidence(
                source="text",
                keyword=flag,
                explanation=EvidenceBuilder._map_content(flag),
                severity=EvidenceBuilder._get_severity(flag)
            ))

        # =========================
        # 6. DNS
        # =========================
        for s in dns_result.get("suspicious_signals", []):
            evidences.append(ScamEvidence(
                source="dns",
                keyword=s,
                explanation=f"Phát hiện bất thường DNS: {s}",
                severity="MEDIUM"
            ))

        # =========================
        # 7. SSL
        # =========================
        for s in ssl_result.get("suspicious_signals", []):
            evidences.append(ScamEvidence(
                source="ssl",
                keyword=s,
                explanation=f"Chứng chỉ SSL có dấu hiệu bất thường: {s}",
                severity="MEDIUM"
            ))

        if ssl_result.get("is_self_signed"):
            evidences.append(ScamEvidence(
                source="ssl",
                keyword="self_signed_ssl",
                explanation="Website sử dụng chứng chỉ SSL tự ký (không đáng tin cậy)",
                severity="HIGH"
            ))

        # =========================
        # 8. BRAND IMPERSONATION
        # =========================
        if brand_result.get("is_impersonating"):
            brand = brand_result.get("brand", "một thương hiệu")
            evidences.append(ScamEvidence(
                source="brand",
                keyword="brand_impersonation",
                explanation=f"Website có dấu hiệu giả mạo thương hiệu {brand} nhằm đánh lừa người dùng",
                severity="HIGH"
            ))

        return evidences

    # =========================
    # SIGNAL MAPPING
    # =========================

    @staticmethod
    def _map_signal(signal: str) -> str:
        mapping = {
            "login_form_detected": "Trang có form đăng nhập (có thể thu thập tài khoản người dùng)",
            "hidden_iframe": "Phát hiện iframe ẩn (kỹ thuật thường dùng để tấn công hoặc lừa đảo)",
            "suspicious_js": "Website chứa JavaScript đáng ngờ",
            "external_form_action": "Form gửi dữ liệu tới domain bên ngoài (nguy cơ đánh cắp thông tin)",
        }
        return mapping.get(signal, f"Phát hiện hành vi bất thường: {signal}")

    # =========================
    # CONTENT MAPPING
    # =========================

    @staticmethod
    def _map_content(flag: str) -> str:
        mapping = {
            "verify": "Website yêu cầu xác minh tài khoản",
            "otp_request": "Website yêu cầu nhập mã OTP",
            "money": "Website yêu cầu chuyển tiền",
            "urgency": "Website tạo cảm giác khẩn cấp để thúc ép người dùng",
            "lottery": "Website thông báo trúng thưởng (dấu hiệu lừa đảo phổ biến)",
            "login_form": "Website có form đăng nhập",
        }
        return mapping.get(flag, f"Nội dung có dấu hiệu đáng ngờ: {flag}")

    # =========================
    # SEVERITY LOGIC (🔥 QUAN TRỌNG)
    # =========================

    @staticmethod
    def _get_severity(keyword: str) -> str:
        high_risk = [
            "otp_request",
            "money",
            "login_form_detected",
            "external_form_action",
            "brand_impersonation",
            "self_signed_ssl"
        ]

        if keyword in high_risk:
            return "HIGH"

        return "MEDIUM"
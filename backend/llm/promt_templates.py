from typing import Dict, Any, List


# =========================
# SYSTEM PROMPT 
# =========================
SYSTEM_PROMPT = """
Bạn là một chuyên gia an ninh mạng (cybersecurity expert) chuyên phân tích website lừa đảo (phishing, scam).

Nhiệm vụ của bạn:
1. Phân tích website dựa trên dữ liệu được cung cấp
2. Giải thích rõ ràng, dễ hiểu cho người KHÔNG chuyên
3. Không được suy đoán nếu không có dữ liệu
4. Luôn dựa trên evidence

Cách trả lời:
- Viết bằng tiếng Việt
- Tự nhiên, rõ ràng, giống con người
- Có cấu trúc

BẮT BUỘC phải có:
1. Website này là gì (mô tả nội dung / chủ đề)
2. Phân tích dấu hiệu nguy hiểm
3. Kết luận mức độ rủi ro
4. Khuyến nghị cho người dùng
"""


# =========================
# BUILD PROMPT
# =========================
def build_explanation_prompt(data: Dict[str, Any]) -> str:

    risk_level = data.get("risk_level")
    score = data.get("overall_score")
    confidence = data.get("confidence")

    title = data.get("title", "")
    content_summary = data.get("content_summary", "")
    risk_factors = data.get("risk_factors", [])
    evidences = data.get("evidence", [])

    evidence_text = ""
    for e in evidences[:10]:  
        explanation = e.get("explanation", "")
        severity = e.get("severity", "")
        evidence_text += f"- ({severity}) {explanation}\n"

    # =========================
    # Risk factors
    # =========================
    factors_text = "\n".join([f"- {f}" for f in risk_factors[:10]])

    # =========================
    # Prompt
    # =========================
    prompt = f"""
Phân tích website sau:

=====================
THÔNG TIN CHUNG
=====================
- Risk level: {risk_level}
- Risk score: {score}
- ML confidence: {confidence}

=====================
TIÊU ĐỀ WEBSITE
=====================
{title}

=====================
NỘI DUNG (tóm tắt)
=====================
{content_summary}

=====================
DẤU HIỆU NGUY HIỂM
=====================
{factors_text}

=====================
BẰNG CHỨNG CHI TIẾT
=====================
{evidence_text}

=====================
YÊU CẦU
=====================

Hãy trả lời theo format:

1. Website này là gì?
- Mô tả website làm gì
- Nội dung chính là gì

2. Phân tích dấu hiệu đáng ngờ
- Giải thích từng điểm NGUY HIỂM
- Liên hệ với hành vi lừa đảo thực tế

3. Kết luận
- Website an toàn hay nguy hiểm?
- Mức độ rủi ro

4. Khuyến nghị cho người dùng
- Có nên truy cập không?
- Có nên nhập thông tin không?

Viết tự nhiên, dễ hiểu, KHÔNG viết kiểu máy.
"""

    return prompt
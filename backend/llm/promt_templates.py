"""
Prompt Templates — Anti-Hallucination Hardened v2
===================================================
LLM role:
  - EXPLAIN website content and behavior (context provider only)
  - Return: site_type, content_summary, behavior_summary, analysis_summary
  - NEVER return: risk_level, risk_score, recommended_action
  - NEVER guess: if data absent → return "Không đủ dữ liệu"
"""


def _determine_tone(score: int) -> str:
    if score >= 80:
        return "TONE: Nguy hiểm rõ ràng — tường minh, khẩn cấp."
    if score >= 50:
        return "TONE: Đáng ngờ — thận trọng, không phán xét tuyệt đối."
    return "TONE: Thông tin — trung lập, không kết luận mạnh."


# ============================================================
# ANTI-HALLUCINATION GUARD — injected into every prompt
# ============================================================
_ANTI_HALLUCINATION = """
=== LUẬT BẮT BUỘC ===
1. CHỈ dùng dữ liệu trong mục DATA bên dưới. KHÔNG suy diễn, đoán mò.
2. Nếu dữ liệu thiếu hoặc không rõ → trả về chuỗi "Không đủ dữ liệu".
3. KHÔNG mô tả nội dung website nếu không có trong Content Snippet.
4. KHÔNG kết luận website "an toàn tuyệt đối" hay "chắc chắn lừa đảo".
5. "site_type" chỉ được chọn từ: safe | suspicious | scam | adult | gambling | unknown
   - "adult": website chứa nội dung người lớn, 18+.
   - "gambling": website cờ bạc, cá cược trực tuyến (casino, betting, lô đề).
   - "unknown": khi không đủ dữ liệu để phân loại.
   - Mặc định: dùng "safe" với risk thấp, không có tín hiệu đáng ngờ.
6. KHÔNG trả về: risk_level, risk_score, score, recommended_action.
7. Output: JSON hợp lệ DUY NHẤT. Không markdown, không giải thích thêm.
"""


def build_url_explanation_prompt(meta: dict) -> str:
    score      = int(meta.get("overall_score", 0))
    risk_level = (meta.get("risk_level") or "unknown").upper()
    factors    = meta.get("risk_factors", []) or []
    domain     = meta.get("domain") or "unknown"
    title      = meta.get("title") or "Không có tiêu đề"
    content    = (meta.get("content_summary") or "")[:400]
    confidence = round(float(meta.get("confidence", 0)) * 100, 1)
    tone       = _determine_tone(score)

    # Page metadata from pipeline
    page        = meta.get("metadata") or {}
    has_login   = bool(page.get("has_login_form"))
    has_extform = bool(page.get("has_external_form"))
    has_pwd     = bool(page.get("password_inputs"))
    urgency     = ", ".join((page.get("urgency") or [])[:3]) or "none"
    keywords    = ", ".join((page.get("keywords") or [])[:3]) or "none"

    try:
        from services.llm_fusion import _label as get_signal_label
        signals_text = "\n".join(f"  - {get_signal_label(f)}" for f in factors[:12]) if factors else "  - (không có tín hiệu)"
    except ImportError:
        signals_text = "\n".join(f"  - {f}" for f in factors[:12]) if factors else "  - (không có tín hiệu)"

    return f"""Bạn là chuyên gia phân tích nội dung web cho hệ thống bảo mật. Viết bằng tiếng Việt.

{tone}
{_ANTI_HALLUCINATION}

=== DATA ===
Domain        : {domain}
Title         : {title}
Risk Score    : {score}/100  (do Risk Engine tính, KHÔNG phải bạn)
Risk Level    : {risk_level} (do Risk Engine quyết định, KHÔNG phải bạn)
ML Confidence : {confidence}%
Content Snip  : "{content}"
Has Login Form: {has_login}
Ext Form      : {has_extform}
Password Field: {has_pwd}
Urgency Words : {urgency}
Susp Keywords : {keywords}

Tín hiệu kỹ thuật đã phát hiện:
{signals_text}

=== VAI TRÒ CỦA BẠN ===
Bạn chỉ phân tích: NỘI DUNG và HÀNH VI website dựa trên dữ liệu trên.
Bạn KHÔNG được đưa ra kết luận về risk hay score.

=== OUTPUT FORMAT ===
Trả về JSON sau (tất cả giá trị bằng tiếng Việt):
{{
  "site_type": "safe | suspicious | scam | adult | gambling | unknown",
  "content_summary": "2-3 câu mô tả website làm gì, phục vụ ai — CHỈ dựa vào Title và Content Snip. Nếu không đủ dữ liệu → 'Không đủ dữ liệu'.",
  "behavior_summary": "Mô tả hành vi kỹ thuật: có form đăng nhập không? redirect? thu thập dữ liệu gì? Dựa VÀO tín hiệu kỹ thuật ở trên. Nếu không có tín hiệu → 'Không phát hiện hành vi đáng chú ý'.",
  "analysis_summary": "Giải thích tại sao score = {score}/100: liên hệ trực tiếp từng tín hiệu với điểm rủi ro. Không đoán thêm.",
  "conflict_hint": "safe | suspicious | scam | adult | gambling — đánh giá của bạn về nội dung (KHÔNG phải risk_level). Nếu là trang người lớn, hãy trả về 'adult'. Nếu là cờ bạc, trả về 'gambling'."
}}"""


def build_text_explanation_prompt(meta: dict) -> str:
    score   = int(meta.get("overall_score", 0))
    factors = meta.get("risk_factors", []) or []
    content = (meta.get("content_summary") or "")[:400]
    tone    = _determine_tone(score)

    try:
        from services.llm_fusion import _label as get_signal_label
        signals_text = "\n".join(f"  - {get_signal_label(f)}" for f in factors[:8]) if factors else "  - (không có tín hiệu)"
    except ImportError:
        signals_text = "\n".join(f"  - {f}" for f in factors[:8]) if factors else "  - (không có tín hiệu)"

    return f"""Bạn là chuyên gia phân tích nội dung tin nhắn/văn bản cho hệ thống bảo mật. Viết bằng tiếng Việt.

{tone}
{_ANTI_HALLUCINATION}

=== DỮ LIỆU ===
Điểm rủi ro  : {score}/100 (do Risk Engine tính)
Nội dung mẫu : "{content}"

Tín hiệu phát hiện:
{signals_text}

=== OUTPUT FORMAT ===
Trả về JSON (tiếng Việt):
{{
  "site_type": "safe | suspicious | scam | unknown",
  "content_summary": "2-3 câu mô tả loại tin nhắn/văn bản dựa vào nội dung mẫu. Nếu không đủ → 'Không đủ dữ liệu'.",
  "behavior_summary": "Mô tả hành vi: yêu cầu gì? có áp lực không? dựa vào tín hiệu. Không đoán thêm.",
  "analysis_summary": "Giải thích score {score}/100 dựa vào từng tín hiệu cụ thể.",
  "conflict_hint": "safe | suspicious | scam — đánh giá của bạn về nội dung."
}}"""
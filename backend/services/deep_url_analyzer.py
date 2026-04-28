from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re


class DeepURLAnalyzer:

    @staticmethod
    def analyze(html: str, url: str) -> dict:
        """
        Production Deep Analyzer
        - Defensive parsing
        - Stronger signal detection
        - Consistent scoring (0–100)
        - No crashes on malformed HTML
        """

        if not html or not isinstance(html, str):
            return {
                "overall_score": 0.0,
                "risk_level": "low",
                "is_scam": False,
                "risk_factors": [],
                "page_metadata": {},
                "deep_insights": {}
            }

        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return {
                "overall_score": 0.0,
                "risk_level": "low",
                "is_scam": False,
                "risk_factors": [],
                "page_metadata": {},
                "deep_insights": {}
            }

        parsed = urlparse(url)
        domain = parsed.netloc

        risk_score = 0.0
        signals = []
        details = {}

        # =====================
        # 1. FORM ANALYSIS
        # =====================
        forms = soup.find_all("form")
        login_forms = 0
        payment_forms = 0
        external_forms = 0

        for form in forms:
            inputs = form.find_all("input")

            for inp in inputs:
                t = (inp.get("type") or "").lower()
                name = (inp.get("name") or "").lower()

                if t == "password":
                    login_forms += 1

                if any(x in name for x in ["card", "cvv", "bank", "account"]):
                    payment_forms += 1

            action = form.get("action")
            if action:
                action_url = urljoin(url, action)
                if domain not in action_url:
                    external_forms += 1

        if login_forms:
            signals.append("login_form")
            risk_score += 20

        if payment_forms:
            signals.append("payment_form")
            risk_score += 30

        if external_forms:
            signals.append("external_form")
            risk_score += 25

        details.update({
            "login_forms": login_forms,
            "payment_forms": payment_forms,
            "external_forms": external_forms
        })

        # =====================
        # 2. KEYWORD ANALYSIS
        # =====================
        try:
            text = soup.get_text(" ").lower()
        except Exception:
            text = ""

        keywords = [
            "verify account", "confirm identity", "reset password",
            "urgent", "act now", "limited time",
            "update payment", "security alert"
        ]

        hits = [k for k in keywords if k in text]

        if hits:
            signals.append("suspicious_keywords")
            risk_score += min(20, len(hits) * 3)

        details["keyword_hits"] = hits

        # =====================
        # 2b. GAMBLING ANALYSIS
        # =====================
        gambling_keywords = [
            "cổng game", "rikvip", "casino", "betting", "tài xỉu", 
            "nổ hũ", "đánh bài", "cá cược", "game bài", "lô đề"
        ]
        gambling_hits = [k for k in gambling_keywords if k in text]
        
        if gambling_hits:
            signals.append("gambling_site")
            risk_score += 50
            details["gambling_hits"] = gambling_hits

        # =====================
        # 3. IFRAME ANALYSIS
        # =====================
        iframes = soup.find_all("iframe")
        hidden_iframes = 0

        for iframe in iframes:
            style = (iframe.get("style") or "").lower()
            if "display:none" in style or "visibility:hidden" in style:
                hidden_iframes += 1

        if hidden_iframes:
            signals.append("hidden_iframe")
            risk_score += 15

        details["hidden_iframes"] = hidden_iframes

        # =====================
        # 4. SCRIPT ANALYSIS
        # =====================
        scripts = soup.find_all("script")
        suspicious_scripts = 0

        for s in scripts:
            content = s.string or ""
            if any(x in content for x in ["eval(", "document.write(", "atob("]):
                suspicious_scripts += 1

        if suspicious_scripts:
            signals.append("suspicious_js")
            risk_score += 15

        details["suspicious_scripts"] = suspicious_scripts

        # =====================
        # 5. LINK ANALYSIS
        # =====================
        links = soup.find_all("a")
        external_links = 0

        for link in links:
            href = link.get("href")
            if not href:
                continue

            if href.startswith("http") and domain not in href:
                external_links += 1

        if external_links > 20:
            signals.append("many_external_links")
            risk_score += 10

        details["external_links"] = external_links

        # =====================
        # NORMALIZE SCORE
        # =====================
        risk_score = min(100.0, float(risk_score))

        if risk_score >= 70:
            risk_level = "high"
        elif risk_score >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "overall_score": risk_score,
            "risk_level": risk_level,
            "is_scam": risk_score >= 70,
            "risk_factors": list(set(signals)),
            "page_metadata": {
                "login_forms": login_forms,
                "payment_forms": payment_forms,
                "external_forms": external_forms,
                "external_links": external_links
            },
            "deep_insights": details
        }


# =============================
# PRODUCTION WRAPPER
# =============================

def run_deep_analysis(base_result: dict):
    """
    Production wrapper:
    - Uses HTML already crawled in pipeline
    - No external requests
    - Ensures consistency with main analysis
    """

    html = base_result.get("html") or base_result.get("raw_html")
    url = base_result.get("final_url") or base_result.get("url")

    if not html or not url:
        return {
            "overall_score": base_result.get("overall_score", 0),
            "risk_level": base_result.get("risk_level", "low"),
            "is_scam": base_result.get("is_scam", False),
            "risk_factors": base_result.get("risk_factors", []),
            "page_metadata": base_result.get("page_metadata", {}),
            "deep_insights": {}
        }

    deep = DeepURLAnalyzer.analyze(html, url)

    # Merge with base (deep enhances, not replaces)
    base_score = base_result.get("overall_score", 0)
    try:
        base_score = float(base_score or 0)
    except (TypeError, ValueError):
        base_score = 0.0
    if 0 < base_score <= 1.0:
        base_score *= 100.0

    merged_score = max(base_score, deep["overall_score"])

    return {
        "overall_score": merged_score,
        "risk_level": deep["risk_level"],
        "is_scam": merged_score >= 70,
        "risk_factors": list(set(base_result.get("risk_factors", []) + deep["risk_factors"])),
        "page_metadata": {**base_result.get("page_metadata", {}), **deep.get("page_metadata", {})},
        "deep_insights": deep.get("deep_insights", {})
    }
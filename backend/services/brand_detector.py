"""
Advanced Brand Impersonation Detector (SOC-level).

Features:
- Fuzzy matching (rapidfuzz)
- Official domain verification (false positive fix)
- Subdomain phishing detection
- Homoglyph / punycode detection
- Keyword-based phishing boosting
"""

from typing import Optional
from utils.logger import logger

try:
    from rapidfuzz import fuzz, process
    RAPIDFUZZ_AVAILABLE = True
except ImportError:
    RAPIDFUZZ_AVAILABLE = False
    logger.warning("rapidfuzz_not_installed | brand_detection_disabled")


# =============================================
# Top brands
# =============================================

TOP_BRANDS = [
    "google", "facebook", "microsoft", "apple", "amazon",
    "paypal", "youtube", "instagram", "netflix", "tiktok",
    "shopee", "lazada", "zalopay", "momo",
    "vietcombank", "techcombank", "mbbank", "bidv"
]


# =============================================
# Official domains (CRITICAL FIX)
# =============================================

OFFICIAL_DOMAINS = {
    "google": ["google.com", "accounts.google.com"],
    "facebook": ["facebook.com"],
    "microsoft": ["microsoft.com", "login.microsoftonline.com"],
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com"],
    "youtube": ["youtube.com"],
    "shopee": ["shopee.vn"],
    "momo": ["momo.vn"]
}


# =============================================
# Helpers
# =============================================

def is_official_domain(domain: str, brand: str) -> bool:
    if brand not in OFFICIAL_DOMAINS:
        return False
    return any(domain.endswith(d) for d in OFFICIAL_DOMAINS[brand])


def is_fake_subdomain(domain: str, brand: str) -> bool:
    return brand in domain and not domain.endswith(brand + ".com")


def contains_punycode(domain: str) -> bool:
    return "xn--" in domain


def has_suspicious_keywords(domain: str) -> bool:
    keywords = [
        "login", "secure", "verify", "account",
        "update", "confirm", "bank", "payment"
    ]
    return any(k in domain for k in keywords)


# =============================================
# Main detector
# =============================================

def detect_brand_impersonation(domain: str) -> dict:

    if not RAPIDFUZZ_AVAILABLE:
        return {
            "is_impersonating": False,
            "impersonated_brand": None,
            "similarity_score": 0.0,
            "risk_signal": "brand_detection_unavailable"
        }

    try:
        domain = domain.lower()

        # =========================
        # Normalize
        # =========================
        base = domain.split(".")[0]
        normalized = base.replace("-", "").replace("_", "")

        # =========================
        # Fuzzy match
        # =========================
        best_match = None
        best_score = 0.0

        match, score, _ = process.extractOne(
            normalized,
            TOP_BRANDS,
            scorer=fuzz.partial_ratio
        )

        best_match = match
        best_score = score

        # =========================
        # Decision logic
        # =========================
        is_impersonating = False
        reasons = []

        if best_score >= 75 and best_match:

            # ✅ Nếu là domain chính chủ → bỏ qua
            if is_official_domain(domain, best_match):
                return {
                    "is_impersonating": False,
                    "impersonated_brand": best_match,
                    "similarity_score": round(best_score, 1),
                    "risk_signal": "official_domain"
                }

            # ❌ Fake subdomain
            if is_fake_subdomain(domain, best_match):
                is_impersonating = True
                reasons.append("fake_subdomain")

            # ❌ Punycode
            if contains_punycode(domain):
                is_impersonating = True
                reasons.append("punycode")

            # ❌ Keyword phishing
            if has_suspicious_keywords(domain):
                is_impersonating = True
                reasons.append("phishing_keywords")

            # ❌ Default case
            if not is_impersonating:
                is_impersonating = True
                reasons.append("high_similarity")

        if is_impersonating:
            logger.warning(
                "brand_impersonation_detected | domain=%s | brand=%s | score=%.1f | reasons=%s",
                domain, best_match, best_score, ",".join(reasons)
            )

        return {
            "is_impersonating": is_impersonating,
            "impersonated_brand": best_match if is_impersonating else None,
            "similarity_score": round(best_score, 1),
            "risk_signal": ",".join(reasons) if reasons else "no_impersonation"
        }

    except Exception as e:
        logger.error("brand_detection_error | domain=%s | error=%s", domain, str(e))
        return {
            "is_impersonating": False,
            "impersonated_brand": None,
            "similarity_score": 0.0,
            "risk_signal": "detection_error"
        }
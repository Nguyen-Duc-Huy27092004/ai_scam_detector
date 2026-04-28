"""
Advanced Risk Scoring Engine — Production Ready
Centralized risk calculation combining all signals.
All inputs are None-safe and capped to valid ranges.
"""

from typing import List, Tuple, Dict, Optional
from urllib.parse import urlparse
import math

from utils.logger import logger


# ============================
# CONFIG
# ============================

WEIGHTS = {
    "url_ml":     0.35,   # ML model confidence (primary signal)
    "image_risk": 0.08,
    "text_risk":  0.12,
    "domain_age": 0.08,
    "patterns":   0.15,
    "https":      0.04,
    "trust":      -0.10,  # Trusted domain → reduce risk
    "entropy":    0.05,
    "combo":      0.08,
    "blacklist":  0.05,   # Blacklist bonus weight
}

RISK_THRESHOLDS = {
    # score < 20 -> LOW
    # 20 <= score < 45 -> MEDIUM
    # 45 <= score < 70 -> HIGH
    # score >= 70 -> CRITICAL
    "MEDIUM_MIN": 20,
    "HIGH_MIN": 45,
    "CRITICAL_MIN": 70,
}

TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "microsoft.com",
    "apple.com", "amazon.com", "paypal.com", "twitter.com",
    "linkedin.com", "github.com", "wikipedia.org",
    # Vietnamese trusted
    "gov.vn", "vietcombank.com.vn", "visa.com.vn",
]

PATTERN_WEIGHTS = {
    "ip_address":             35,
    "punycode_domain":        30,
    "high_entropy_domain":    25,
    "suspicious_tld":         20,
    "new_domain":             25,
    "young_domain":           15,
    "too_many_subdomains":    15,
    "invalid_ssl":            20,
    "expired_ssl":            25,
    "ssl_expiring_soon":      10,
    "no_https":               10,
    "http_login_form":        30,  # Login form over plain HTTP
    "dns_not_resolved":       30,
    "no_safe_ip":             25,
    "whois_failed":           10,
    "brand_impersonation":    45,
    "login_form":             15,
    "external_form":          25,
    "suspicious_password_form": 35,
    "long_redirect_chain":    15,
    "many_iframes":           10,
    "many_hidden_inputs":     10,
    "blacklisted_url":        50,  # Hard blacklist hit
    "datacenter_ip":           5,
    "urgency_detected":       15,
    "gambling_site":          70,
    "hudson_rock_credentials_stolen":             60,
    "hudson_rock_high_volume_credentials_stolen": 85,
    "hudson_rock_employee_credentials_stolen":    100,
}


# ============================
# DOMAIN UTILITIES
# ============================

def normalize_domain(domain: str) -> str:
    if not domain:
        return ""
    domain = str(domain).lower().strip()
    if "http" in domain:
        try:
            domain = urlparse(domain).netloc
        except Exception:
            pass
    # Strip port
    domain = domain.split(":")[0]
    # Strip leading www.
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def is_exact_trusted(domain: str, trusted: str) -> bool:
    return domain == trusted or domain.endswith("." + trusted)


def is_fake_brand(domain: str, trusted: str) -> bool:
    brand = trusted.split(".")[0]
    return brand in domain and not is_exact_trusted(domain, trusted)


def calculate_trust_score(domain: str) -> float:
    """Return negative score to reduce risk for trusted domains, positive for fakes."""
    domain = normalize_domain(domain)
    if not domain:
        return 0.0
    for trusted in TRUSTED_DOMAINS:
        if is_exact_trusted(domain, trusted):
            return -40.0   # Legitimate trusted domain → strongly reduce risk
        if is_fake_brand(domain, trusted):
            return 40.0    # Brand impersonation via domain → strongly increase risk
    return 0.0


# ============================
# DOMAIN AGE
# ============================

def calculate_domain_age_score(domain_age_days: Optional[int]) -> float:
    """Returns 0–100 score (higher = riskier)."""
    if domain_age_days is None:
        return 20.0   # Unknown age → mild penalty
    try:
        age = int(domain_age_days)
    except (TypeError, ValueError):
        return 20.0
    if age < 7:
        return 80.0
    if age < 30:
        return 60.0
    if age < 90:
        return 30.0
    if age < 365:
        return 10.0
    return 0.0


# ============================
# ENTROPY
# ============================

def calculate_entropy(domain: str) -> float:
    if not domain:
        return 0.0
    main = domain.split(".")[0]
    if len(main) < 3:
        return 0.0
    try:
        prob = [float(main.count(c)) / len(main) for c in dict.fromkeys(main)]
        return -sum(p * math.log2(p) for p in prob if p > 0)
    except Exception:
        return 0.0


# ============================
# PATTERN SCORE
# ============================

def calculate_pattern_score(patterns: List[str]) -> float:
    """Weighted sum of known risk patterns, capped at 100."""
    score = 0.0
    for pattern in patterns:
        if not pattern or not isinstance(pattern, str):
            continue
        if pattern in PATTERN_WEIGHTS:
            score += PATTERN_WEIGHTS[pattern]
        elif pattern.startswith("keyword_"):
            score += 12   # Content keyword hit
        else:
            score += 5    # Unknown pattern
    return min(score, 100.0)


# ============================
# RISK LEVEL LABELS
# ============================

def determine_risk_level(score: float) -> str:
    if score >= RISK_THRESHOLDS["CRITICAL_MIN"]:
        return "CRITICAL"
    if score >= RISK_THRESHOLDS["HIGH_MIN"]:
        return "HIGH"
    if score >= RISK_THRESHOLDS["MEDIUM_MIN"]:
        return "MEDIUM"
    return "LOW"


# ============================
# TEXT-ONLY HELPERS
# ============================

def calculate_text_risk(
    text_confidence: float,
    suspicious_patterns: Optional[List[str]] = None,
) -> Tuple[str, float, Dict]:
    """
    Risk scoring for plain-text analysis only.
    Do not pass text ML confidence as url_ml_confidence — that applies URL-tuned weights.
    """
    tc = max(0.0, min(float(text_confidence or 0), 1.0))
    return calculate_risk(
        url_ml_confidence=0.0,
        image_risk=0.0,
        text_risk=tc,
        domain_age_days=None,
        is_https=True,
        suspicious_patterns=suspicious_patterns,
        domain="",
        is_blacklisted=False,
    )


# ============================
# MAIN ENGINE
# ============================

def calculate_risk(
    url_ml_confidence: float,
    image_risk: float = 0.0,
    text_risk: float = 0.0,
    domain_age_days: Optional[int] = None,
    is_https: bool = False,
    suspicious_patterns: Optional[List[str]] = None,
    domain: str = "",
    is_blacklisted: bool = False,       # NEW: direct blacklist signal
) -> Tuple[str, float, Dict]:
    """
    Central risk scoring engine.

    Returns:
        (risk_level: str, final_score: float, metadata: dict)
        risk_level ∈ {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
        final_score ∈ [0, 100]
    """
    try:
        suspicious_patterns = [
            p for p in (suspicious_patterns or []) if p and isinstance(p, str)
        ]
        domain = normalize_domain(domain or "")

        # Clamp inputs to [0, 1]
        url_ml_confidence = max(0.0, min(float(url_ml_confidence or 0), 1.0))
        image_risk        = max(0.0, min(float(image_risk or 0), 1.0))
        text_risk         = max(0.0, min(float(text_risk or 0), 1.0))

        score = 0.0
        breakdown: Dict = {}

        #  ML Score 
        ml_scaled = math.pow(url_ml_confidence, 1.2)   # Slight superlinear boost
        ml_score  = ml_scaled * 100 * WEIGHTS["url_ml"]
        breakdown["url_ml"] = round(ml_score, 2)
        score += ml_score

        # Content Signals 
        image_score = image_risk * 100 * WEIGHTS["image_risk"]
        text_score  = text_risk  * 100 * WEIGHTS["text_risk"]
        breakdown["image_risk"] = round(image_score, 2)
        breakdown["text_risk"]  = round(text_score, 2)
        score += image_score + text_score

        #  Domain Age 
        age_raw       = calculate_domain_age_score(domain_age_days)
        age_component = age_raw * WEIGHTS["domain_age"]
        breakdown["domain_age"] = round(age_component, 2)
        score += age_component

        # HTTPS
        https_raw       = 0 if is_https else 30   # Larger penalty for no HTTPS
        https_component = https_raw * WEIGHTS["https"]
        breakdown["https"] = round(https_component, 2)
        score += https_component

        #  Suspicious Patterns 
        pattern_raw = calculate_pattern_score(suspicious_patterns)

        # Scale patterns by ML confidence correlation
        if url_ml_confidence < 0.2:
            pattern_raw *= 0.3
        elif url_ml_confidence < 0.5:
            pattern_raw *= 0.6
        elif url_ml_confidence > 0.75:
            pattern_raw *= 1.2

        pattern_raw       = min(pattern_raw, 70.0)
        pattern_component = pattern_raw * WEIGHTS["patterns"]
        breakdown["patterns"] = round(pattern_component, 2)
        score += pattern_component

        # ─── Entropy ─────────────────────────────────────────────────────────
        entropy       = calculate_entropy(domain)
        entropy_raw   = 25 if entropy > 3.8 else (10 if entropy > 3.2 else 0)
        entropy_comp  = entropy_raw * WEIGHTS["entropy"]
        breakdown["entropy"] = round(entropy_comp, 2)
        score += entropy_comp

        # ─── Blacklist Bonus ─────────────────────────────────────────────────
        # Also auto-detected from patterns if "blacklisted_url" in patterns
        bl_hit = is_blacklisted or ("blacklisted_url" in suspicious_patterns)
        blacklist_bonus = 25.0 if bl_hit else 0.0
        breakdown["blacklist"] = round(blacklist_bonus, 2)
        score += blacklist_bonus

        # ─── Critical Signal Overrides ───────────────────────────────────────
        # Ensure that critical findings bypass the low ML confidence suppression
        critical_bonus = 0.0
        if bl_hit:
            # Force score into HIGH/CRITICAL territory, bypassing penalties
            critical_bonus += 65.0
        if "brand_impersonation" in suspicious_patterns:
            critical_bonus += 45.0
        if "suspicious_password_form" in suspicious_patterns:
            critical_bonus += 20.0
        if "http_login_form" in suspicious_patterns:
            critical_bonus += 20.0
            
        if "gambling_site" in suspicious_patterns:
            critical_bonus += 50.0
            
        if "hudson_rock_employee_credentials_stolen" in suspicious_patterns:
            critical_bonus += 80.0
        elif "hudson_rock_high_volume_credentials_stolen" in suspicious_patterns:
            critical_bonus += 60.0
        elif "hudson_rock_credentials_stolen" in suspicious_patterns:
            critical_bonus += 40.0
        
        breakdown["critical_bonus"] = round(critical_bonus, 2)
        score += critical_bonus

        # ─── Combo Detection ─────────────────────────────────────────────────
        combo_score = 0.0

        if "brand_impersonation" in suspicious_patterns and is_https:
            # HTTPS + brand impersonation = convincing phishing
            combo_score += 25

        if (
            "login_form" in suspicious_patterns and
            domain_age_days is not None and
            int(domain_age_days) < 30 and
            url_ml_confidence > 0.4
        ):
            combo_score += 20

        if "external_form" in suspicious_patterns and "login_form" in suspicious_patterns:
            combo_score += 20

        if "long_redirect_chain" in suspicious_patterns:
            combo_score += 10

        if "http_login_form" in suspicious_patterns:
            combo_score += 15

        breakdown["combo"] = round(combo_score, 2)
        score += combo_score * WEIGHTS["combo"]

        # ─── Trust Score ─────────────────────────────────────────────────────
        trust_raw       = calculate_trust_score(domain)
        trust_component = trust_raw * WEIGHTS["trust"]
        breakdown["trust"] = round(trust_component, 2)
        score += trust_component

        # ─── Final Score (anti-false-positive smoothing) ──────────────────────
        final_score = (score * 0.85) + (ml_score * 0.15)

        # Suppress low URL ML confidence from producing very high scores (skip when no URL ML signal)
        has_hard_evidence = bl_hit or (critical_bonus > 0)
        if 0 < url_ml_confidence < 0.15 and final_score < 40 and not has_hard_evidence:
            final_score = min(final_score, 25.0)

        if final_score > 92 and 0 < url_ml_confidence < 0.4 and not has_hard_evidence:
            final_score = 88.0

        final_score = max(0.0, min(round(final_score, 2), 100.0))
        risk_level  = determine_risk_level(final_score)

        metadata = {
            "risk_level":  risk_level,
            "score":       final_score,
            "breakdown":   breakdown,
            "patterns":    suspicious_patterns,
            "domain":      domain,
            "blacklisted": bl_hit,
        }

        logger.info(
            "risk_calculated | domain=%s | score=%.2f | level=%s | patterns=%d",
            domain or "unknown", final_score, risk_level, len(suspicious_patterns)
        )

        return risk_level, final_score, metadata

    except Exception as e:
        logger.error("risk_engine_failed | %s", str(e))
        return "UNKNOWN", 0.0, {}


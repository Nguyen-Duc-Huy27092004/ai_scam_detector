"""
URL Analysis Pipeline — Production Hardened (Improved Stability + Observability)
"""

import atexit
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List
from urllib.parse import urlparse
import time

from utils.logger import logger

from services.async_crawler import SecureCrawler
from services.domain_intel import get_domain_intel
from services.risk_level import calculate_risk
from services.advisor import generate_advice
from services.redirect_analyzer import analyze_redirects
from services.dataset_checker import DatasetChecker
from services.network_analyzer import NetworkAnalyzer
from services.brand_detector import detect_brand_impersonation
from services.content_extractor import ContentExtractor
from services.file_analyzer import FileAnalyzer
from services.screenshot import ScreenshotService

from ml.url.predict import predict_url
from llm.llm_explainer import generate_explanation


# ========================
# SINGLETONS
# ========================
_dataset_checker = DatasetChecker()

# ========================
# EXECUTOR
# ========================
_EXECUTOR = ThreadPoolExecutor(max_workers=8)
atexit.register(lambda: _EXECUTOR.shutdown(wait=False))


def _safe_future(name: str, future, timeout=8):
    start = time.time()
    try:
        result = future.result(timeout=timeout)
        elapsed = time.time() - start
        logger.info("future_done | %s | %.2fs", name, elapsed)
        return result if result is not None else {}
    except Exception as e:
        elapsed = time.time() - start
        logger.warning("future_fail | %s | %.2fs | %s", name, elapsed, str(e))
        return {}


# ========================
# CONTENT HEURISTICS
# ========================
_SCAM_KEYWORDS: List[tuple] = [
    ("otp", 0.30), ("mã xác nhận", 0.25), ("chuyển tiền", 0.30),
    ("nạp tiền", 0.25), ("trúng thưởng", 0.30),
    ("verify now", 0.20), ("click here", 0.10),
    ("urgent", 0.15), ("đăng nhập", 0.15),
]


def _score_content(text: str, metadata: dict) -> tuple:
    score = 0.0
    factors: List[str] = []

    if text:
        t = text.lower()
        for kw, w in _SCAM_KEYWORDS:
            if kw in t:
                score += w
                factors.append(f"keyword_{kw.replace(' ', '_')}")

    if metadata.get("has_login_form"):
        score += 0.2
        factors.append("login_form")

    if metadata.get("has_otp_field"):
        score += 0.35
        factors.append("otp_request")

    if metadata.get("urgency_phrases"):
        score += 0.15
        factors.append("urgency_detected")

    return min(score, 1.0), factors


def _fallback_explanation(score, risk_level, risk_factors, confidence):
    return {
        "risk_score": round(score, 2),
        "risk_level": risk_level,
        "confidence_note": f"Confidence: {int(confidence * 100)}%",
        "risk_assessment": "Fallback heuristic analysis",
        "detected_signals": risk_factors[:5],
        "recommended_actions": [
            "Không nhập thông tin cá nhân",
            "Xác minh domain trước khi truy cập"
        ],
        "website_summary": "LLM unavailable"
    }


class URLAnalysisPipeline:

    @staticmethod
    def analyze(url: str) -> Dict[str, Any]:
        start_total = time.time()

        try:
            # ========================
            # 1. REDIRECT
            # ========================
            redirect_info = analyze_redirects(url) or {}
            final_url = redirect_info.get("final_url") or url

            if not SecureCrawler.is_safe_url(final_url):
                return {"status": "error", "message": "Unsafe URL"}

            domain = urlparse(final_url).netloc

            # ========================
            # 2. BLACKLIST
            # ========================
            try:
                blacklist = _dataset_checker.check_url(final_url)
            except Exception as e:
                logger.warning("blacklist_fail | %s", str(e))
                blacklist = {"is_blacklisted": False}

            # ========================
            # 3. PARALLEL TASKS
            # ========================
            futures = {
                "crawl": _EXECUTOR.submit(SecureCrawler.crawl_sync, final_url),
                "intel": _EXECUTOR.submit(get_domain_intel, final_url),
                "network": _EXECUTOR.submit(NetworkAnalyzer.analyze, final_url),
                "brand": _EXECUTOR.submit(detect_brand_impersonation, domain),
                "screenshot": _EXECUTOR.submit(
                    ScreenshotService.capture_with_playwright, final_url
                ),
            }

            crawl = _safe_future("crawl", futures["crawl"], 10)
            intel = _safe_future("intel", futures["intel"], 6)
            network = _safe_future("network", futures["network"], 6)
            brand = _safe_future("brand", futures["brand"], 5)
            screenshot_path = _safe_future("screenshot", futures["screenshot"], 12) or None

            html = crawl.get("html", "")
            text = crawl.get("text", "")

            # ========================
            # 4. CONTENT
            # ========================
            metadata = {}
            if html:
                try:
                    metadata = ContentExtractor.extract_metadata(html, base_url=final_url)
                except Exception as e:
                    logger.warning("metadata_fail | %s", str(e))

            content_score, content_factors = _score_content(text, metadata)

            # ========================
            # 5. ML
            # ========================
            ml = predict_url(final_url) or {}
            confidence = float(ml.get("confidence", 0.01))

            # ========================
            # 6. FILE ANALYSIS
            # ========================
            file_risk = 0.0
            if html and len(html) < 2_000_000:
                try:
                    file_result = FileAnalyzer.analyze(html.encode(), "page.html")
                    if file_result.get("suspicious"):
                        file_risk = 0.8
                except Exception as e:
                    logger.debug("file_analysis_skip | %s", str(e))

            # ========================
            # 7. SIGNAL AGGREGATION
            # ========================
            patterns = []
            patterns.extend(network.get("risk_flags", []))
            patterns.extend(content_factors)

            if brand.get("is_impersonating"):
                patterns.append("brand_impersonation")

            if blacklist.get("is_blacklisted"):
                patterns.append("blacklisted")

            patterns = list(set(patterns))[:15]

            # ========================
            # 8. RISK
            # ========================
            try:
                risk_level, score, _ = calculate_risk(
                    url_ml_confidence=confidence,
                    domain_age_days=intel.get("age_days"),
                    is_https=final_url.startswith("https"),
                    suspicious_patterns=patterns,
                    text_risk=max(content_score, file_risk),
                    image_risk=0.0,
                    domain=domain,
                    is_blacklisted=blacklist.get("is_blacklisted", False),
                )
            except Exception as e:
                logger.error("risk_calc_fail | %s", str(e))
                risk_level, score = "low", 0.0

            risk_level = str(risk_level or "low").lower()
            score = float(score or 0.0)

            if blacklist.get("is_blacklisted"):
                score = max(score, 85.0)
                risk_level = "high"

            # ========================
            # 9. LLM (with timeout)
            # ========================
            llm = _fallback_explanation(score, risk_level, patterns, confidence)
            try:
                # Run LLM with 30-second timeout to prevent pipeline blocking
                llm_future = _EXECUTOR.submit(generate_explanation, {
                    "overall_score": score,
                    "risk_level": risk_level,
                    "risk_factors": patterns[:10],
                    "confidence": confidence,
                    "domain": domain,
                    "content_summary": text[:500] if text else ""
                })
                llm = _safe_future("llm", llm_future, timeout=30)
                if not llm:  # If timeout or error, keep fallback
                    llm = _fallback_explanation(score, risk_level, patterns, confidence)
            except Exception as e:
                logger.warning("llm_fail | %s", str(e))
                # llm already has fallback value

            # ========================
            # 10. ADVISOR
            # ========================
            try:
                advice = generate_advice(
                    analysis_type="url",
                    risk_level=risk_level,
                    risk_factors=patterns,
                    confidence=confidence
                )
            except Exception as e:
                logger.error("advice_fail | %s", str(e))
                advice = {}

            total_time = time.time() - start_total
            logger.info("pipeline_done | %.2fs | %s", total_time, final_url[:80])

            # ========================
            # RESULT
            # ========================
            return {
                "status": "completed",
                "url": final_url,
                "final_url": final_url,

                "risk_level": risk_level,
                "overall_score": round(score, 2),
                "confidence": round(confidence, 4),
                "is_scam": score > 70,

                "risk_factors": patterns,

                "page_metadata": {
                    "title": metadata.get("title"),
                    "has_login_form": metadata.get("has_login_form", False),
                    "has_otp_field": metadata.get("has_otp_field", False),
                },

                "network": {
                    "risk_flags": network.get("risk_flags", []),
                    "ssl_valid": network.get("ssl", {}).get("valid"),
                },

                "screenshot_path": screenshot_path,

                "llm_explanation": llm,
                "advice": advice,
            }

        except Exception as e:
            logger.exception("pipeline_fail | %s", str(e))
            return {"status": "error", "message": str(e)}


def analyze_url(url: str) -> dict:
    return URLAnalysisPipeline.analyze(url)
"""
URL Analysis Pipeline — Optimized (No LLM Timeout, Feature-Based)
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


_dataset_checker = DatasetChecker()

# I/O vs LLM: separate pools so slow LLM jobs cannot starve crawl/intel/network/brand.
_IO_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="url-io")
_LLM_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="url-llm")
atexit.register(lambda: _IO_EXECUTOR.shutdown(wait=False))
atexit.register(lambda: _LLM_EXECUTOR.shutdown(wait=False))

IS_SCAM_THRESHOLD = 60.0


def _safe_future(name: str, future, timeout=8):
    start = time.time()
    try:
        result = future.result(timeout=timeout)
        return result if result is not None else {}
    except Exception as e:
        logger.warning("future_fail | %s | %s", name, str(e))
        return {}


def _fallback_explanation(score, risk_level, risk_factors, confidence):
    return {
        "risk_score": round(score, 2),
        "risk_level": risk_level,
        "detected_signals": risk_factors[:5],
        "analysis_summary": "Phân tích tự động dựa trên các dấu hiệu kỹ thuật.",
        "impact": "Chưa xác định. Hãy thận trọng khi tương tác.",
        "confidence_note": "Đánh giá dựa trên dấu hiệu tự động, không qua AI.",
        "recommended_action": "Không nhập thông tin cá nhân",
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
            blacklist = _dataset_checker.check_url(final_url) or {}

            # ========================
            # 3. PARALLEL TASKS
            # ========================
            futures = {
                "crawl": _IO_EXECUTOR.submit(SecureCrawler.crawl_sync, final_url),
                "intel": _IO_EXECUTOR.submit(get_domain_intel, final_url),
                "network": _IO_EXECUTOR.submit(NetworkAnalyzer.analyze, final_url),
                "brand": _IO_EXECUTOR.submit(detect_brand_impersonation, domain),
            }

            crawl = _safe_future("crawl", futures["crawl"], 10)
            intel = _safe_future("intel", futures["intel"], 6)
            network = _safe_future("network", futures["network"], 6)
            brand = _safe_future("brand", futures["brand"], 5)

            html = crawl.get("html", "")

            # ========================
            # 4. CONTENT METADATA
            # ========================
            metadata = {}
            if html:
                metadata = ContentExtractor.extract_metadata(html, base_url=final_url)

            # ========================
            # 5. ML
            # ========================
            ml = predict_url(final_url) or {}
            confidence = float(ml.get("confidence", 0.01))

            # ========================
            # 6. SIGNAL AGGREGATION
            # ========================
            patterns = []
            patterns.extend(network.get("risk_flags", []))
            patterns.extend(intel.get("suspicious_patterns", []))

            if metadata.get("has_login_form"):
                patterns.append("login_form")

            if metadata.get("has_otp_field"):
                patterns.append("otp_request")

            if metadata.get("urgency_phrases"):
                patterns.append("urgency_detected")

            if brand.get("is_impersonating"):
                patterns.append("brand_impersonation")

            if blacklist.get("is_blacklisted"):
                patterns.append("blacklisted_url")

            patterns = list(set(patterns))[:15]

            # ========================
            # 7. RISK
            # ========================
            risk_level, score, _ = calculate_risk(
                url_ml_confidence=confidence,
                domain_age_days=intel.get("age_days"),
                is_https=final_url.startswith("https"),
                suspicious_patterns=patterns,
                text_risk=0.0,
                image_risk=0.0,
                domain=domain,
                is_blacklisted=blacklist.get("is_blacklisted", False),
            )

            score = float(score or 0.0)

            # ========================
            # 8. LLM (FEATURE ONLY)
            # ========================
            llm = _fallback_explanation(score, risk_level, patterns, confidence)

            try:
                llm_features = {
                    "has_login_form": metadata.get("has_login_form"),
                    "has_external_form": metadata.get("has_external_form"),
                    "password_inputs": metadata.get("password_inputs"),
                    "external_links": metadata.get("external_links"),
                    "urgency": metadata.get("urgency_phrases", [])[:3],
                    "keywords": metadata.get("suspicious_keywords", [])[:3],
                }

                llm_future = _LLM_EXECUTOR.submit(generate_explanation, {
                    "overall_score": score,
                    "risk_level": risk_level,
                    "risk_factors": patterns,
                    "confidence": confidence,
                    "domain": domain,
                    "metadata": llm_features   # ✅ QUAN TRỌNG
                })

                llm = _safe_future("llm", llm_future, timeout=15) or llm

            except Exception as e:
                logger.warning("llm_fail | %s", str(e))

            # ========================
            # 9. ADVICE
            # ========================
            advice = generate_advice(
                analysis_type="url",
                risk_level=risk_level,
                risk_factors=patterns,
                confidence=confidence
            )

            logger.info("pipeline_done | %.2fs", time.time() - start_total)

            return {
                "status": "completed",
                "url": final_url,
                "risk_level": risk_level,
                "overall_score": round(score, 2),
                "confidence": round(confidence, 4),
                "risk_factors": patterns,
                "llm_explanation": llm,
                "advice": advice,
                "blacklist": blacklist,
                "brand_check": brand,
                "network": network,
                "page_metadata": metadata,
                "is_scam": score >= IS_SCAM_THRESHOLD,
                "screenshot": None,
            }

        except Exception as e:
            logger.exception("pipeline_fail | %s", str(e))
            return {"status": "error", "message": str(e)}


def analyze_url(url: str) -> dict:
    return URLAnalysisPipeline.analyze(url)
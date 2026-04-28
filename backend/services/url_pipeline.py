"""
URL Analysis Pipeline — Optimized (No LLM Timeout, Feature-Based)
Production hardened:
  - All blocking calls wrapped in asyncio.to_thread / run_in_executor
  - body_text sanitized before LLM (prompt injection defense)
  - IS_SCAM_THRESHOLD loaded from config (env-configurable)
  - atexit replaced by SIGTERM handler in main.py
  - hrefs regex applied to capped HTML to prevent memory spike
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any
from urllib.parse import urlparse
import asyncio
import time

from utils.logger import logger
from utils.config import IS_SCAM_THRESHOLD
from utils.content_sanitizer import sanitize_for_llm, wrap_for_llm

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
from services.domain_info import get_domain_info
from services.hudson_rock import check_hudson_rock

from ml.url.predict import predict_url
from llm.llm_explainer import generate_explanation
from services.llm_fusion import fuse_llm_with_risk
from ocr.ocr_engine import OCREngine as _OCREngine


_dataset_checker = DatasetChecker()

# I/O vs LLM: separate pools so slow LLM jobs cannot starve crawl/intel/network/brand.
_IO_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="url-io")
_LLM_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="url-llm")
# Shutdown is handled by SIGTERM handler in main.py (reliable under Docker/K8s).
# atexit is intentionally NOT used here.


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
    async def analyze(url: str) -> Dict[str, Any]:
        """Full async URL analysis pipeline."""
        import asyncio
        start_total = time.time()

        try:
            # ========================
            # 1. REDIRECT
            # ✔ Wrapped in to_thread — requests lib is blocking
            # ========================
            redirect_info = await asyncio.to_thread(analyze_redirects, url) or {}
            final_url = redirect_info.get("final_url") or url

            if not SecureCrawler.is_safe_url(final_url):
                return {"status": "error", "message": "Unsafe URL"}

            domain = urlparse(final_url).netloc

            # ========================
            # 2. BLACKLIST
            # ✔ Wrapped in to_thread — SQLite I/O is blocking
            # ========================
            blacklist = await asyncio.to_thread(_dataset_checker.check_url, final_url) or {}

            # ========================
            # 3. PARALLEL TASKS (run in IO thread pool via run_in_executor)
            # ========================
            loop = asyncio.get_running_loop()
            f_crawl       = loop.run_in_executor(_IO_EXECUTOR, SecureCrawler.crawl_sync, final_url)
            f_intel       = loop.run_in_executor(_IO_EXECUTOR, get_domain_intel, final_url)
            f_network     = loop.run_in_executor(_IO_EXECUTOR, NetworkAnalyzer.analyze, final_url)
            f_brand       = loop.run_in_executor(_IO_EXECUTOR, detect_brand_impersonation, domain)
            f_domain_info = loop.run_in_executor(_IO_EXECUTOR, get_domain_info, domain)
            f_screenshot  = loop.run_in_executor(_IO_EXECUTOR, ScreenshotService.capture, final_url)
            # Hudson Rock: infostealer credential leak check (non-blocking, 8s timeout)
            f_hudson      = loop.run_in_executor(_IO_EXECUTOR, check_hudson_rock, final_url)

            results = await asyncio.gather(
                asyncio.wait_for(f_crawl,       timeout=10),
                asyncio.wait_for(f_intel,       timeout=6),
                asyncio.wait_for(f_network,     timeout=6),
                asyncio.wait_for(f_brand,       timeout=5),
                asyncio.wait_for(f_domain_info, timeout=5),
                asyncio.wait_for(f_hudson,      timeout=8),
                return_exceptions=True,
            )

            def _safe(r): return r if isinstance(r, dict) else {}
            crawl, intel, network, brand, domain_info, hudson = map(_safe, results)

            try:
                screenshot = await asyncio.wait_for(f_screenshot, timeout=15)
            except Exception as e:
                logger.warning("screenshot_timeout | %s", str(e))
                screenshot = None

            html = crawl.get("html", "")

            # ========================
            # EXTRACT BODY TEXT
            # ========================
            body_text = ""
            if html:
                try:
                    from bs4 import BeautifulSoup as _BS
                    _soup = _BS(html, "html.parser")
                    for _tag in _soup(["script", "style", "noscript", "head"]):
                        _tag.decompose()
                    body_text = _soup.get_text(" ", strip=True)
                    body_text = " ".join(body_text.split())[:1200]
                except Exception as _e:
                    logger.warning("body_text_extract_failed | %s", str(_e))

            # ========================
            # OCR FROM SCREENSHOT
            # ✔ Wrapped in to_thread — Tesseract is CPU-bound/blocking
            # ========================
            if screenshot and isinstance(screenshot, str):
                try:
                    ocr_text, _ = await asyncio.to_thread(_OCREngine.extract_text, screenshot)
                    if ocr_text and len(ocr_text.strip()) > 20:
                        ocr_clean = " ".join(ocr_text.split())[:600]
                        if len(body_text) < 200:
                            body_text = ocr_clean
                            logger.info("ocr_primary | len=%d", len(ocr_clean))
                        else:
                            body_text = body_text[:900] + " [OCR] " + ocr_clean
                            logger.info("ocr_appended | ocr_len=%d", len(ocr_clean))
                    else:
                        logger.info("ocr_empty_or_short | skipped")
                except Exception as _e:
                    logger.warning("ocr_pipeline_failed | %s", str(_e))

            # ========================
            # 4. CONTENT METADATA & FILES
            # ========================
            metadata = {}
            has_dangerous_files = False

            if html:
                metadata = ContentExtractor.extract_metadata(html, base_url=final_url)

                import re
                # Cap HTML to 50KB before regex to prevent memory spike
                hrefs = re.findall(r'href=[\'"]([^\'"]+)[\'"]', html[:50_000], re.IGNORECASE)
                dangerous_exts = FileAnalyzer.DANGEROUS_EXTS.union({"apk", "msi"})
                for h in hrefs:
                    ext = h.split('?')[0].split('.')[-1].lower() if '.' in h else ''
                    if ext in dangerous_exts:
                        has_dangerous_files = True
                        break

            # ========================
            # 5. ML
            # ✔ Wrapped in to_thread — CPU-bound model inference
            # ========================
            ml = await asyncio.to_thread(predict_url, final_url) or {}
            confidence = float(ml.get("confidence", 0.01))

            # ========================
            # 6. SIGNAL AGGREGATION
            # ========================
            patterns = []
            patterns.extend(network.get("risk_flags", []))
            patterns.extend(intel.get("suspicious_patterns", []))

            if metadata.get("has_login_form"):   patterns.append("login_form")
            if metadata.get("has_otp_field"):    patterns.append("otp_request")
            if metadata.get("urgency_phrases"):  patterns.append("urgency_detected")
            if metadata.get("gambling_keywords"): patterns.append("gambling_site")
            if brand.get("is_impersonating"):    patterns.append("brand_impersonation")
            if blacklist.get("is_blacklisted"):  patterns.append("blacklisted_url")
            if has_dangerous_files:              patterns.append("malicious_file_download")

            # Hudson Rock — infostealer credential leak
            hudson_signal = hudson.get("signal")
            if hudson_signal:
                patterns.append(hudson_signal)

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
            # 8. LLM
            # ✔ body_text sanitized before injection (prompt injection defense)
            # ========================
            llm = _fallback_explanation(score, risk_level, patterns, confidence)

            try:
                safe_content = sanitize_for_llm(body_text)
                wrapped_content = wrap_for_llm(safe_content) if safe_content else ""

                llm_features = {
                    "has_login_form":    metadata.get("has_login_form"),
                    "has_external_form": metadata.get("has_external_form"),
                    "password_inputs":   metadata.get("password_inputs"),
                    "external_links":    metadata.get("external_links"),
                    "urgency":           metadata.get("urgency_phrases", [])[:3],
                    "keywords":          metadata.get("suspicious_keywords", [])[:3],
                }

                llm_future = loop.run_in_executor(_LLM_EXECUTOR, generate_explanation, {
                    "overall_score":   score,
                    "risk_level":      risk_level,
                    "risk_factors":    patterns,
                    "confidence":      confidence,
                    "domain":          domain,
                    "metadata":        llm_features,
                    "title":           metadata.get("title") or "No Title",
                    "content_summary": wrapped_content or metadata.get("description") or "",
                })

                llm_raw = await asyncio.wait_for(llm_future, timeout=25) or {}

                llm = fuse_llm_with_risk(
                    risk_level=risk_level,
                    score=score,
                    confidence=confidence,
                    signals=patterns,
                    llm_raw=llm_raw,
                )

            except Exception as e:
                logger.warning("llm_fail | %s", str(e))

            # Extract final fused values if available
            final_risk_level = llm.get("risk_level", risk_level) if isinstance(llm, dict) else risk_level
            final_score      = llm.get("score", score) if isinstance(llm, dict) else score

            # ========================
            # 9. ADVICE
            # ========================
            advice = generate_advice(
                analysis_type="url",
                risk_level=final_risk_level,
                risk_factors=patterns,
                confidence=confidence,
            )

            logger.info("pipeline_done | %.2fs", time.time() - start_total)

            return {
                "status":          "completed",
                "url":             final_url,
                "risk_level":      final_risk_level,
                "overall_score":   round(final_score, 2),
                "confidence":      round(confidence, 4),
                "risk_factors":    patterns,
                "llm_explanation": llm,
                "advice":          advice,
                "blacklist":       blacklist,
                "brand_check":     brand,
                "network":         network,
                "page_metadata":   metadata,
                "is_scam":         final_score >= IS_SCAM_THRESHOLD,
                "screenshot":      screenshot,
                "domain_info":     domain_info,
                "hudson_rock":     hudson,
                # Internal: pass crawl artifacts for deep-analyze reuse (not exposed in API)
                "_crawl_html":     html,
            }

        except Exception as e:
            logger.exception("pipeline_fail | %s", str(e))
            return {"status": "error", "message": str(e)}


async def analyze_url(url: str) -> dict:
    """Async entry point for the URL analysis pipeline.
    
    Hard cap: 70 s total. If the pipeline (crawl + LLM + etc.) does not
    complete in time we return a structured error instead of hanging forever
    and causing the frontend AbortController to fire with a cryptic message.
    """
    try:
        return await asyncio.wait_for(URLAnalysisPipeline.analyze(url), timeout=70)
    except asyncio.TimeoutError:
        logger.warning("pipeline_total_timeout | url=%s", url[:120])
        return {"status": "error", "message": "Phân tích mất quá nhiều thời gian. Vui lòng thử lại."}
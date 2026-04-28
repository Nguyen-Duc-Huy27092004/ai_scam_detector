"""
URL Analysis API — Production ready
Endpoints: /analyze (basic), /deep-analyze (AI-powered)

Changes vs original:
  - analyze_url() is now async — called directly (no asyncio.to_thread wrapper needed)
  - deep-analyze: reuses HTML, OCR, and metadata from base pipeline result
    → eliminates duplicate crawl + duplicate OCR (was 2× cost)
  - content sanitizer applied before LLM in deep-analyze
  - Auth dependency on all endpoints
"""
import asyncio
import base64
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from utils.logger import logger
from utils.validators import is_valid_url
from utils.url_utils import is_safe_url, is_safe_url_detailed, normalize_url
from utils.content_sanitizer import sanitize_for_llm, wrap_for_llm
from services.url_pipeline import analyze_url
from ml.url.db import AnalysisHistory
import json
from services.deep_url_analyzer import DeepURLAnalyzer
from services.llm_fusion import fuse_llm_with_risk
from schemas.url import URLAnalyzeRequest, URLAnalyzeResponse
from utils.config import SCREENSHOTS_DIR
from core.cache import cache
from core.limiter import limiter
from core.auth import require_api_key

router = APIRouter()


# ==============================
# HELPERS
# ==============================

def _build_url_response(url: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Build a flat, frontend-compatible response dict from url_pipeline output."""
    overall_score = float(result.get("overall_score") or 0)
    risk_level    = str(result.get("risk_level") or "unknown").lower()
    risk_factors  = result.get("risk_factors") or []
    llm           = result.get("llm_explanation") or {}
    advice_block  = result.get("advice") or {}

    if isinstance(llm, dict) and llm.get("analysis_summary"):
        risk_summary = llm["analysis_summary"]
    elif risk_factors:
        from services.llm_fusion import _labels as _signal_labels
        risk_summary = f"Phát hiện {len(risk_factors)} tín hiệu rủi ro: {_signal_labels(risk_factors, limit=3)}."
    else:
        risk_summary = "Không phát hiện tín hiệu rủi ro đáng kể."

    advice_text = None
    recommendations = []
    if isinstance(advice_block, dict):
        advice_text     = advice_block.get("advice")
        recommendations = advice_block.get("recommendations") or []
    elif isinstance(llm, dict):
        advice_text = llm.get("recommended_action")

    blacklist = result.get("blacklist") or {}
    brand     = result.get("brand_check") or {}
    network   = result.get("network") or {}
    page_meta = result.get("page_metadata") or {}

    # Suppress screenshot for adult content
    screenshot_data = None
    if not (isinstance(llm, dict) and llm.get("is_adult")):
        screenshot_data = _load_screenshot(result.get("screenshot"))

    return {
        "url":               url,
        "is_scam":           bool(result.get("is_scam")),
        "risk_score":        overall_score,
        "risk_score_percent": overall_score,
        "risk_level":        risk_level,
        "risk_summary":      risk_summary,
        "confidence":        float(result.get("confidence") or 0),
        "reasons":           risk_factors,
        "signals": {
            "blacklisted":          blacklist.get("is_blacklisted", False),
            "blacklist_source":     blacklist.get("source"),
            "brand_impersonation":  brand.get("is_impersonating", False),
            "impersonated_brand":   brand.get("impersonated_brand"),
            "ssl_valid":            network.get("ssl_valid"),
            "port_open":            network.get("port_open"),
            "has_login_form":       page_meta.get("has_login_form", False),
            "has_external_form":    page_meta.get("has_external_form", False),
        },
        "llm_explanation":   llm if isinstance(llm, dict) else None,
        "site_type":         llm.get("site_type", "safe") if isinstance(llm, dict) else "safe",
        "advice":            advice_text,
        "recommendations":   recommendations,
        "screenshot":        screenshot_data,
        "record_id":         result.get("record_id"),
        "domain_info":       result.get("domain_info"),
        "hudson_rock":       result.get("hudson_rock"),   # infostealer credential leak data
    }


def _load_screenshot(screenshot_filename) -> Optional[str]:
    """Read screenshot file and return base64-encoded string. Path-traversal safe."""
    if not screenshot_filename:
        return None
    try:
        safe_path = Path(SCREENSHOTS_DIR) / Path(screenshot_filename).name
        safe_path = safe_path.resolve()
        screenshots_root = Path(SCREENSHOTS_DIR).resolve()
        if not str(safe_path).startswith(str(screenshots_root)):
            logger.warning("screenshot_path_traversal_blocked | filename=%s", screenshot_filename)
            return None
        if not safe_path.is_file():
            return None
        with open(safe_path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception as e:
        logger.warning("screenshot_load_failed | filename=%s | error=%s", screenshot_filename, str(e))
    return None


def _normalize_cache_key(url: str) -> str:
    """
    Produce a canonical string suitable for use as a cache key.
    Normalizes: scheme (lowercase), host (lowercase), strips trailing slash on path.
    Falls back gracefully on any parse error.
    """
    try:
        normalized = normalize_url(url)
        if normalized:
            return normalized.lower().rstrip("/")
    except Exception:
        pass
    return url.lower().rstrip("/")


def _make_cache_key(normalized_url: str) -> str:
    return f"url_analysis:{normalized_url}"


# ==============================
# BASIC URL ANALYSIS
# ==============================

@router.post("/analyze", response_model=URLAnalyzeResponse)
@limiter.limit("10/minute")
async def analyze(
    request: Request,
    payload: URLAnalyzeRequest,
    _auth: None = Depends(require_api_key),
):
    url = payload.url.strip()

    if not is_valid_url(url):
        return URLAnalyzeResponse(
            success=False,
            error="Invalid URL format",
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

    _url_safe, _url_reason = is_safe_url_detailed(url)
    if not _url_safe:
        logger.warning("analyze_ssrf_blocked | url=%s | reason=%s", url[:100], _url_reason)
        _error_msg = {
            "private_ip":           "URL này trỏ về một địa chỉ IP riêng tư/nội bộ và không thể được phân tích.",
            "dns_resolution_failed": "Không thể tra cứu DNS cho domain này. Hãy kiểm tra xem URL có hợp lệ không.",
            "localhost":             "URL trỏ về localhost và không được phép phân tích.",
            "internal_tld":          "Domain sử dụng TLD nội bộ (.local, .lan, ...) không được hỗ trợ.",
            "disallowed_scheme":     "Chỉ hỗ trợ http và https.",
            "metadata_host":         "URL trỏ đến Cloud Metadata Endpoint và bị chặn vì lý do bảo mật.",
        }.get(_url_reason, "URL không hợp lệ hoặc không thể tiếp cận được.")
        return URLAnalyzeResponse(
            success=False,
            error=_error_msg,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

    logger.info("url_analyze_requested | %s", url[:120])

    # -------------------------------------------------------
    # Step 1: Check in-memory / Redis cache (URL gốc)
    # -------------------------------------------------------
    norm_original = _normalize_cache_key(url)
    cache_key_original = _make_cache_key(norm_original)

    cached_result = await cache.get(cache_key_original)
    if cached_result:
        logger.info("url_analyze_cache_hit | source=memory_redis | %s", url[:120])
        return URLAnalyzeResponse(
            success=True,
            data=cached_result,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

    # -------------------------------------------------------
    # Step 2: Check DB (persistent cache — survives restart)
    # Lookup dùng normalized URL gốc (nhất quán với gì được lưu)
    # -------------------------------------------------------
    try:
        db_record = await asyncio.to_thread(
            AnalysisHistory.get_by_input_value, "url", norm_original
        )
        if db_record and db_record.get("evidence_json"):
            db_data = json.loads(db_record["evidence_json"])
            if isinstance(db_data, dict) and "url" in db_data:
                logger.info("url_analyze_db_hit | %s", url[:120])
                # Warm lại in-memory/Redis cache để request tiếp theo không cần vào DB
                await cache.set(cache_key_original, db_data, expire_seconds=7200)
                return URLAnalyzeResponse(
                    success=True,
                    data=db_data,
                    timestamp=datetime.utcnow().isoformat() + "Z"
                )
    except Exception as e:
        logger.warning("db_cache_lookup_failed | %s", str(e))

    # -------------------------------------------------------
    # Step 3: Chạy pipeline phân tích
    # -------------------------------------------------------
    try:
        result = await analyze_url(url)
    except Exception as e:
        logger.error("url_analyze_error | %s", str(e))
        return URLAnalyzeResponse(
            success=False,
            error="Analysis failed internally",
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

    if result.get("status") == "error":
        return URLAnalyzeResponse(
            success=False,
            error=result.get("message", "Analysis failed"),
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

    # -------------------------------------------------------
    # Step 4: Build response
    # -------------------------------------------------------
    response_data = _build_url_response(url, result)

    # -------------------------------------------------------
    # Step 5: Dual-key cache — lưu cả key URL gốc lẫn key final_url
    # Lý do: user có thể gõ URL trước redirect (http://ex.com) hoặc
    # sau redirect (https://ex.com) — cả 2 đều phải hit cache
    # -------------------------------------------------------
    final_url: str = result.get("url") or url
    norm_final = _normalize_cache_key(final_url)
    cache_key_final = _make_cache_key(norm_final)

    await cache.set(cache_key_original, response_data, expire_seconds=7200)
    if norm_final != norm_original:
        # Chỉ set key thứ 2 nếu URL thực sự khác (tránh lưu trùng)
        await cache.set(cache_key_final, response_data, expire_seconds=7200)
        logger.debug("url_analyze_dual_key_cached | original=%s | final=%s", norm_original[:80], norm_final[:80])

    # -------------------------------------------------------
    # Step 6: Lưu DB — dùng normalized URL gốc làm input_value
    # (nhất quán với Step 2 lookup)
    # -------------------------------------------------------
    try:
        await asyncio.to_thread(AnalysisHistory.create, {
            "input_type": "url",
            "input_value": norm_original,   # ← normalized để lookup nhất quán
            "label": "url_scan",
            "risk_level": response_data.get("risk_level", "unknown"),
            "confidence": response_data.get("confidence", 0.0),
            "advice": response_data.get("advice", ""),
            "screenshot_path": result.get("screenshot"),
            "ocr_text": "",
            "evidence_json": json.dumps(response_data),
            "model_version": "pipeline_v2",
        })
    except Exception as e:
        logger.warning("failed_to_save_url_history | %s", str(e))

    return URLAnalyzeResponse(
        success=True,
        data=response_data,
        timestamp=datetime.utcnow().isoformat() + "Z"
    )


# ==============================
# DEEP AI ANALYSIS
# ==============================

class DeepAnalyzeRequest(URLAnalyzeRequest):
    pass


@router.post("/deep-analyze")
@limiter.limit("3/minute")
async def deep_analyze(
    request: Request,
    payload: DeepAnalyzeRequest,
    _auth: None = Depends(require_api_key),
):
    url = payload.url.strip()

    if not is_valid_url(url):
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Invalid URL format",
                     "timestamp": datetime.utcnow().isoformat() + "Z"}
        )

    _url_safe, _url_reason = is_safe_url_detailed(url)
    if not _url_safe:
        logger.warning("deep_analyze_ssrf_blocked | url=%s | reason=%s", url[:100], _url_reason)
        _error_msg = {
            "private_ip":           "URL này trỏ về một địa chỉ IP riêng tư/nội bộ và không thể được phân tích.",
            "dns_resolution_failed": "Không thể tra cứu DNS cho domain này. Hãy kiểm tra xem URL có hợp lệ không.",
            "localhost":             "URL trỏ về localhost và không được phép phân tích.",
            "internal_tld":          "Domain sử dụng TLD nội bộ (.local, .lan, ...) không được hỗ trợ.",
            "disallowed_scheme":     "Chỉ hỗ trợ http và https.",
            "metadata_host":         "URL trỏ đến Cloud Metadata Endpoint và bị chặn vì lý do bảo mật.",
        }.get(_url_reason, "URL không hợp lệ hoặc không thể tiếp cận được.")
        return JSONResponse(
            status_code=403,
            content={"success": False, "error": _error_msg,
                     "timestamp": datetime.utcnow().isoformat() + "Z"}
        )

    logger.info("url_deep_analyze_requested | %s", url[:120])

    cache_key = f"url_deep_analysis:{_normalize_cache_key(url)}"
    cached = await cache.get(cache_key)
    if cached:
        logger.info("url_deep_analyze_cache_hit | %s", url[:120])
        return JSONResponse(
            content={"success": True, "data": cached,
                     "timestamp": datetime.utcnow().isoformat() + "Z"}
        )

    try:
        db_record = await asyncio.to_thread(AnalysisHistory.get_by_input_value, "deep_url", url)
        if db_record and db_record.get("evidence_json"):
            db_data = json.loads(db_record["evidence_json"])
            if isinstance(db_data, dict) and "url" in db_data:
                logger.info("url_deep_analyze_db_hit | %s", url[:120])
                await cache.set(cache_key, db_data, expire_seconds=3600)
                return JSONResponse(
                    content={"success": True, "data": db_data,
                             "timestamp": datetime.utcnow().isoformat() + "Z"}
                )
    except Exception as e:
        logger.warning("db_cache_lookup_failed_deep | %s", str(e))

    # -------------------------------------------------------
    # Step 1: Run the AUTHORITATIVE pipeline (risk engine)
    # analyze_url is now async — call directly, NO second crawl
    # -------------------------------------------------------
    try:
        base_result = await analyze_url(url)
    except Exception as e:
        logger.error("deep_analyze_base_pipeline_failed | %s", str(e))
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": "Analysis failed",
                     "timestamp": datetime.utcnow().isoformat() + "Z"}
        )

    if base_result.get("status") == "error":
        return JSONResponse(
            status_code=502,
            content={"success": False,
                     "error": base_result.get("message", "Analysis failed"),
                     "timestamp": datetime.utcnow().isoformat() + "Z"}
        )

    risk_level = str(base_result.get("risk_level") or "LOW").upper()
    score      = float(base_result.get("overall_score") or 0)
    confidence = float(base_result.get("confidence") or 0)
    signals    = list(base_result.get("risk_factors") or [])

    # -------------------------------------------------------
    # Step 2: Reuse HTML from base pipeline (NO second crawl)
    # _crawl_html is a private key added by url_pipeline for this purpose
    # -------------------------------------------------------
    html = base_result.get("_crawl_html", "") or ""
    website_title = "No Title"
    text_content  = ""

    if html:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
            if soup.title and soup.title.string:
                website_title = soup.title.string.strip()
            for _tag in soup(["script", "style", "noscript", "head"]):
                _tag.decompose()
            text_content = " ".join(soup.get_text(" ", strip=True).split())[:1200]
        except Exception:
            text_content = ""

        # Deep HTML analysis — extra signals only
        try:
            deep = await asyncio.to_thread(DeepURLAnalyzer.analyze, html, url)
            extra_signals = [s for s in (deep.get("risk_factors") or []) if s not in signals]
            signals = list(set(signals + extra_signals))[:20]
        except Exception as e:
            logger.warning("deep_html_analyze_failed | %s", str(e))

    # -------------------------------------------------------
    # OCR: reuse screenshot path from base result (NO second OCR)
    # The base pipeline already ran OCR and merged result into body_text.
    # For deep-analyze we take the base text_content which is equivalent.
    # Only run OCR here if base pipeline had no HTML (thin crawl fallback).
    # -------------------------------------------------------
    if not text_content:
        screenshot_path = base_result.get("screenshot")
        if screenshot_path and isinstance(screenshot_path, str):
            try:
                from ocr.ocr_engine import OCREngine as _OCR
                ocr_text, _ = await asyncio.to_thread(_OCR.extract_text, screenshot_path)
                if ocr_text and len(ocr_text.strip()) > 20:
                    text_content = " ".join(ocr_text.split())[:600]
                    logger.info("deep_ocr_fallback | len=%d", len(text_content))
            except Exception as e:
                logger.warning("deep_ocr_failed | %s", str(e))

    # -------------------------------------------------------
    # Step 3: Sanitize content (prompt injection defense)
    # -------------------------------------------------------
    safe_content = sanitize_for_llm(text_content)
    wrapped_content = wrap_for_llm(safe_content) if safe_content else ""

    # -------------------------------------------------------
    # Step 4: LLM explanation
    # -------------------------------------------------------
    llm_raw: Optional[Dict] = None
    try:
        from urllib.parse import urlparse as _urlparse
        from llm.llm_explainer import generate_explanation

        _domain = _urlparse(url).netloc
        llm_raw = await asyncio.to_thread(generate_explanation, {
            "overall_score":   round(score, 2),
            "risk_level":      risk_level,
            "risk_factors":    signals,
            "confidence":      confidence,
            "domain":          _domain,
            "title":           website_title,
            "content_summary": wrapped_content,
        })
    except Exception as e:
        logger.warning("deep_analyze_llm_failed | %s", str(e))

    # -------------------------------------------------------
    # Step 5: FUSION — single authoritative output
    # -------------------------------------------------------
    fused = fuse_llm_with_risk(
        risk_level=risk_level,
        score=score,
        confidence=confidence,
        signals=signals,
        llm_raw=llm_raw,
    )

    response_data = {
        "url":                url,
        "risk_score":         fused.get("score", score),
        "risk_score_percent": round(fused.get("score", score), 0),
        "risk_level":         str(fused.get("risk_level", risk_level)).lower(),
        "signals":            signals,
        "site_type":          fused["site_type"],
        "llm_explanation":    fused,
        "website_title":      website_title,
        "consistent":         True,
    }

    await cache.set(cache_key, response_data, expire_seconds=3600)

    try:
        await asyncio.to_thread(AnalysisHistory.create, {
            "input_type": "deep_url",
            "input_value": url,
            "label": "deep_url_scan",
            "risk_level": risk_level.lower(),
            "confidence": confidence,
            "advice": fused.get("recommended_action", ""),
            "screenshot_path": base_result.get("screenshot"),
            "ocr_text": "",
            "evidence_json": json.dumps(response_data),
            "model_version": "deep_pipeline_v2",
        })
    except Exception as e:
        logger.warning("failed_to_save_deep_url_history | %s", str(e))

    return JSONResponse(
        content={
            "success": True,
            "data": response_data,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    )

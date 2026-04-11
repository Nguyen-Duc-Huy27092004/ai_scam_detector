"""
URL Analysis API — Production ready
Endpoints: /analyze (basic), /deep-analyze (AI-powered)
"""
import asyncio
import base64
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from utils.logger import logger
from utils.validators import is_valid_url
from utils.url_utils import is_safe_url, normalize_url
from services.url_pipeline import analyze_url
from services.async_crawler import SecureCrawler
from services.deep_url_analyzer import DeepURLAnalyzer
from schemas.url import URLAnalyzeRequest, URLAnalyzeResponse
from utils.config import SCREENSHOTS_DIR
from core.cache import cache
from core.limiter import limiter

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

    # Human-readable risk summary
    if isinstance(llm, dict) and llm.get("analysis_summary"):
        risk_summary = llm["analysis_summary"]
    elif risk_factors:
        risk_summary = f"Phát hiện {len(risk_factors)} tín hiệu rủi ro."
    else:
        risk_summary = "Không phát hiện tín hiệu rủi ro đáng kể."

    # Advice + recommendations
    advice_text = None
    recommendations = []
    if isinstance(advice_block, dict):
        advice_text     = advice_block.get("advice")
        recommendations = advice_block.get("recommendations") or []
    elif isinstance(llm, dict):
        advice_text = llm.get("recommended_action")

    # Blacklist / brand signals
    blacklist  = result.get("blacklist") or {}
    brand      = result.get("brand_check") or {}
    network    = result.get("network") or {}
    page_meta  = result.get("page_metadata") or {}

    return {
        "url":               url,
        "is_scam":           bool(result.get("is_scam", overall_score >= 70)),
        "risk_score":        overall_score,
        "risk_score_percent": overall_score,
        "risk_level":        risk_level,
        "risk_summary":      risk_summary,
        "confidence":        float(result.get("confidence") or 0),
        # Signals
        "reasons":           risk_factors,
        "signals": {
            "blacklisted":       blacklist.get("is_blacklisted", False),
            "blacklist_source":  blacklist.get("source"),
            "brand_impersonation": brand.get("is_impersonating", False),
            "impersonated_brand":  brand.get("impersonated_brand"),
            "ssl_valid":         network.get("ssl_valid"),
            "port_open":         network.get("port_open"),
            "has_login_form":    page_meta.get("has_login_form", False),
            "has_external_form": page_meta.get("has_external_form", False),
        },
        # AI explanation
        "llm_explanation":   llm if isinstance(llm, dict) else None,
        # Advice
        "advice":            advice_text,
        "recommendations":   recommendations,
        # Screenshot (populated by deep-analyze)
        "screenshot":        _load_screenshot(result.get("screenshot")),
        "record_id":         result.get("record_id"),
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
    """Normalize URL for cache key to avoid misses on trivial variants."""
    try:
        return normalize_url(url)
    except Exception:
        return url.lower().rstrip("/")


# ==============================
# BASIC URL ANALYSIS
# ==============================

@router.post("/analyze", response_model=URLAnalyzeResponse)
@limiter.limit("10/minute")
async def analyze(request: Request, payload: URLAnalyzeRequest):
    url = payload.url.strip()

    if not is_valid_url(url):
        return URLAnalyzeResponse(
            success=False,
            error="Invalid URL format",
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

    logger.info("url_analyze_requested | %s", url[:120])

    # Cache check
    cache_key    = f"url_analysis:{_normalize_cache_key(url)}"
    cached_result = await cache.get(cache_key)
    if cached_result:
        logger.info("url_analyze_cache_hit | %s", url[:120])
        return URLAnalyzeResponse(
            success=True,
            data=cached_result,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

    try:
        result = await asyncio.to_thread(analyze_url, url)
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

    response_data = _build_url_response(url, result)

    # Cache for 2 hours
    await cache.set(cache_key, response_data, expire_seconds=7200)

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
async def deep_analyze(request: Request, payload: DeepAnalyzeRequest):
    url = payload.url.strip()

    if not is_valid_url(url):
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "Invalid URL format",
                     "timestamp": datetime.utcnow().isoformat() + "Z"}
        )

    if not is_safe_url(url):
        logger.warning("deep_analyze_ssrf_blocked | url=%s", url[:100])
        return JSONResponse(
            status_code=403,
            content={"success": False,
                     "error": "URL resolves to a private or reserved address",
                     "timestamp": datetime.utcnow().isoformat() + "Z"}
        )

    logger.info("url_deep_analyze_requested | %s", url[:120])

    cache_key = f"url_deep_analysis:{_normalize_cache_key(url)}"
    cached = await cache.get(cache_key)
    if cached:
        logger.info("url_deep_analyze_cache_hit | %s", url[:120])
        return {"success": True, "data": cached, "timestamp": datetime.utcnow().isoformat() + "Z"}

    # Fetch HTML via SecureCrawler (SSRF + size safe)
    logger.info("deep_analyze_crawl_start | url=%s", url[:120])
    try:
        # Increased timeout to 35s to allow for slow websites
        crawl_result = await asyncio.wait_for(
            SecureCrawler.crawl(url),
            timeout=35
        )
    except Exception as e:
        logger.error("deep_analyze_crawl_exception | url=%s | error=%s", url[:120], str(e))
        return JSONResponse(
            status_code=502,
            content={"success": False, "error": f"Failed to fetch website: {str(e)}",
                     "timestamp": datetime.utcnow().isoformat() + "Z"}
        )
    
    logger.info("deep_analyze_crawl_result | success=%s | has_html=%s", 
                crawl_result.get("success") if isinstance(crawl_result, dict) else False,
                bool(crawl_result.get("html")) if isinstance(crawl_result, dict) else False)
    
    if not isinstance(crawl_result, dict) or not crawl_result.get("success"):
        logger.error("deep_analyze_fetch_failed | url=%s | result=%s", url[:120], str(crawl_result)[:200])
        return JSONResponse(
            status_code=502,
            content={"success": False, "error": "Failed to fetch website content",
                     "timestamp": datetime.utcnow().isoformat() + "Z"}
        )
    
    html = crawl_result.get("html", "")

    # Run deep analysis (sync → threadpool)
    try:
        logger.info("deep_analyze_starting | url=%s | html_size=%d", url[:120], len(html))
        deep_result = await asyncio.to_thread(DeepURLAnalyzer.analyze, html, url)
        logger.info("deep_analyze_completed | url=%s | risk_score=%s", url[:120], deep_result.get("risk_score", "?"))
    except Exception as e:
        logger.error("deep_analysis_failed | url=%s | error=%s", url[:120], str(e), exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"Deep analysis failed: {str(e)}",
                     "timestamp": datetime.utcnow().isoformat() + "Z"}
        )

    # Parse HTML for title / snippet
    website_title  = "No Title"
    text_content   = ""
    risk_level_str = "unknown"
    risk_score_pct = 0

    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        if soup.title and soup.title.string:
            website_title = soup.title.string.strip()
        text_content = soup.get_text(" ", strip=True)[:500]

        risk_score_raw = deep_result.get("risk_score", 0) or 0
        risk_score_pct = int(risk_score_raw * 100) if risk_score_raw <= 1 else int(risk_score_raw)

        if risk_score_pct > 60:
            risk_level_str = "dangerous"
        elif risk_score_pct > 30:
            risk_level_str = "suspicious"
        else:
            risk_level_str = "safe"

    except Exception as e:
        logger.warning("deep_analyze_html_parse_failed | %s", str(e))

    # LLM explanation with fallback
    llm_explanation: Optional[Dict] = None
    try:
        from llm.llm_explainer import generate_explanation
        llm_explanation = await asyncio.to_thread(generate_explanation, {
            "overall_score":   risk_score_pct,
            "risk_level":      risk_level_str,
            "risk_factors":    deep_result.get("signals", []),
            "confidence":      1.0,
            "scam_type":       "phishing",
            "title":           website_title,
            "content_summary": text_content,
        })
    except Exception as e:
        logger.warning("deep_analyze_llm_failed | %s", str(e))
        # Local fallback — never crash
        llm_explanation = {
            "risk_score":         risk_score_pct,
            "risk_level":         risk_level_str,
            "detected_signals":   deep_result.get("signals", [])[:5],
            "website_summary":    f"Website: {website_title}",
            "analysis_summary":   "AI explanation unavailable — LLM offline.",
            "recommended_action": "Kiểm tra thủ công trước khi tin tưởng website này.",
        }

    response_data = {
        "url":              url,
        "risk_score":       deep_result.get("risk_score", 0),
        "risk_score_percent": risk_score_pct,
        "risk_level":       risk_level_str,
        "signals":          deep_result.get("signals", []),
        "llm_explanation":  llm_explanation,
        "website_title":    website_title,
    }

    # Cache for 1 hour
    await cache.set(cache_key, response_data, expire_seconds=3600)

    return {
        "success":   True,
        "data":      response_data,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

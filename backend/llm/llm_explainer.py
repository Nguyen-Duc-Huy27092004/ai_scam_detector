"""
LLM Explanation Engine — Production Hardened

Improvements:
- Retry + timeout tuning
- Circuit breaker with backoff
- requests.Session() reuse
- Safer JSON parsing
- Better prompt context
"""

import json
import re
import time
import threading
from typing import Optional

import requests
import os

from utils.logger import logger
from utils.config import LLM_PROVIDER, LLM_MODEL, LLM_BASE_URL, LLM_API_KEY


# ==========================
# CONFIG
# ==========================

LLM_TIMEOUT     = int(os.getenv("LLM_TIMEOUT", "120"))
LLM_MAX_TOKENS  = int(os.getenv("LLM_MAX_TOKENS", "800"))  # Reduced for faster generation

MAX_RETRIES = 2

# Timeout tuple: (connect_timeout, read_timeout)
# connect_timeout: how long to wait for connection establishment
# read_timeout: how long to wait for response data
LLM_CONNECT_TIMEOUT = 10  # Faster connection timeout
LLM_READ_TIMEOUT = LLM_TIMEOUT    # Use environment variable for read timeout
LLM_REQUEST_TIMEOUT = (LLM_CONNECT_TIMEOUT, LLM_READ_TIMEOUT)


# ==========================
# SESSION (performance)
# ==========================

def _create_session():
    """Create a configured requests session with connection pooling."""
    session = requests.Session()
    # Disable keep-alive to avoid connection reuse issues
    session.headers.update({"Connection": "close"})
    # Configure connection pooling
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=10,
        pool_maxsize=10,
        max_retries=0,  # let our retry logic handle it
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

_session = _create_session()


# ==========================
# CIRCUIT BREAKER
# ==========================

_CB_LOCK = threading.Lock()
_cb_failures = 0
_cb_open_until = 0.0

_CB_FAILURE_THRESHOLD = 3


def _circuit_is_open() -> bool:
    with _CB_LOCK:
        return time.time() < _cb_open_until


def _record_success():
    global _cb_failures, _cb_open_until
    with _CB_LOCK:
        _cb_failures = 0
        _cb_open_until = 0.0


def _record_failure():
    global _cb_failures, _cb_open_until
    with _CB_LOCK:
        _cb_failures += 1

        if _cb_failures >= _CB_FAILURE_THRESHOLD:
            # exponential backoff
            backoff = min(60, 5 * _cb_failures)
            _cb_open_until = time.time() + backoff

            logger.warning(
                "llm_circuit_open | failures=%d | open_for=%ds",
                _cb_failures,
                backoff,
            )


# ==========================
# PROMPT
# ==========================

def build_explanation_prompt(meta: dict) -> str:
    # Lấy thông tin đối tượng phân tích
    target = meta.get("domain") or meta.get("title") or "Không rõ"
    content_summary = meta.get("content_summary", "")[:800] if meta.get("content_summary") else "Không có nội dung."
    
    return f"""Bạn là chuyên gia an ninh mạng. Phân tích nhanh.

=== WEBSITE ===
URL: {target}
Nội dung: {content_summary}
Risk score: {meta.get("overall_score", 0)}/100
ML confidence: {meta.get("confidence", 0):.1%}
Dấu hiệu: {", ".join(meta.get("risk_factors", [])[:5])}

Trả về CHÍNH XÁC JSON này (không text bên ngoài):
{{
  "risk_score": {meta.get("overall_score", 0)},
  "risk_level": "safe",
  "detected_signals": [],
  "website_summary": "Mô tả ngắn 2-3 dòng",
  "analysis_summary": "Kết luận 2-3 dòng",
  "recommended_action": "Khuyến nghị 1 dòng"
}}"""


# ==========================
# LLM CALL
# ==========================

def call_llm(prompt: str) -> Optional[str]:
    if _circuit_is_open():
        logger.info("llm_circuit_open_skip")
        return None

    for attempt in range(MAX_RETRIES):

        try:
            logger.info(
                "llm_request | len=%d | attempt=%d | provider=%s",
                len(prompt),
                attempt,
                LLM_PROVIDER,
            )

            if LLM_PROVIDER == "ollama":
                try:
                    resp = _session.post(
                        f"{LLM_BASE_URL.rstrip('/')}/api/generate",
                        json={
                            "model": LLM_MODEL,
                            "prompt": prompt,
                            "stream": False,
                            "options": {
                                "temperature": 0.1,  # Lower for consistency
                                "num_predict": 500,  # Limit tokens for speedup
                                "top_k": 40,
                                "top_p": 0.9,
                            },
                        },
                        timeout=LLM_REQUEST_TIMEOUT,
                    )

                    if resp.status_code == 200:
                        _record_success()
                        logger.debug("llm_response_received | size=%d", len(resp.text))
                        return resp.json().get("response", "")
                except requests.ConnectTimeout:
                    logger.warning("llm_connect_timeout_attempt_%d", attempt)
                    continue
                except requests.ReadTimeout:
                    logger.warning("llm_read_timeout_attempt_%d", attempt)
                    continue

            elif LLM_PROVIDER in ("openai", "gemini"):
                try:
                    resp = _session.post(
                        f"{LLM_BASE_URL.rstrip('/')}/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {LLM_API_KEY}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": LLM_MODEL,
                            "messages": [{"role": "user", "content": prompt}],
                            "temperature": 0.1,
                            "max_tokens": 500,  # Faster response
                        },
                        timeout=LLM_REQUEST_TIMEOUT,
                    )

                    if resp.status_code == 200:
                        _record_success()
                        logger.debug("llm_response_received | size=%d", len(resp.text))
                        return resp.json()["choices"][0]["message"]["content"]
                except requests.ConnectTimeout:
                    logger.warning("llm_connect_timeout_attempt_%d", attempt)
                    continue
                except requests.ReadTimeout:
                    logger.warning("llm_read_timeout_attempt_%d", attempt)
                    continue

            if 'resp' in locals():
                logger.warning(
                    "llm_bad_status | attempt=%d | status=%s | body_len=%d",
                    attempt,
                    resp.status_code,
                    len(resp.text) if resp.text else 0,
                )
            else:
                logger.warning(
                    "llm_no_response | attempt=%d",
                    attempt,
                )

        except requests.Timeout as e:
            logger.warning("llm_timeout_attempt_%d | type=%s", attempt, type(e).__name__)

        except Exception as e:
            logger.warning("llm_error_attempt_%d | %s", attempt, str(e)[:200])

    _record_failure()
    return None


# ==========================
# JSON PARSER (SAFE)
# ==========================

def _extract_json(text: str) -> Optional[dict]:
    if not text:
        return None

    text = text.strip()
    
    logger.debug("llm_extract_json | input_len=%d | first_50=%s", len(text), text[:50])

    # remove markdown code blocks
    if "```" in text:
        parts = text.split("```")
        if len(parts) >= 3:
            # extract content between first and second ```
            text = parts[1]
        elif len(parts) == 2:
            # only one ``` found, try the second part
            text = parts[1]
        text = text.replace("json", "").replace("JSON", "").strip()
        logger.debug("llm_markdown_stripped | new_len=%d", len(text))

    # try direct parse first
    try:
        data = json.loads(text)
        logger.info("llm_json_direct_parse_success")
        return data
    except json.JSONDecodeError as e:
        logger.debug("llm_json_direct_parse_failed | error=%s", str(e)[:100])

    # more aggressive search for JSON object
    # handle cases where there's text before/after JSON
    start_idx = text.find('{')
    end_idx = text.rfind('}')
    
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        json_candidate = text[start_idx:end_idx + 1]
        logger.debug("llm_json_extracted_substring | len=%d", len(json_candidate))
        try:
            data = json.loads(json_candidate)
            logger.info("llm_json_substring_parse_success")
            return data
        except json.JSONDecodeError as e:
            logger.debug("llm_json_substring_parse_failed | error=%s", str(e)[:100])

    # fallback: try regex with non-greedy matching
    matches = re.findall(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
    logger.debug("llm_regex_matches_found | count=%d", len(matches))

    for i, m in enumerate(matches):
        try:
            data = json.loads(m)
            logger.info("llm_json_regex_parse_success | match_idx=%d", i)
            return data
        except json.JSONDecodeError as e:
            logger.debug("llm_regex_match_%d_failed | len=%d", i, len(m))
            continue

    logger.warning("llm_json_extraction_all_failed | input=%s", text[:200])
    return None


# ==========================
# NORMALIZE
# ==========================

def _normalize(data: dict, fallback: dict) -> dict:
    return {
        "risk_score": data.get("risk_score", fallback["score"]),
        "risk_level": data.get("risk_level", fallback["risk_level"]),
        "detected_signals": data.get("detected_signals", fallback["factors"][:5]),
        "website_summary": data.get("website_summary") or "Không rõ nội dung.",
        "analysis_summary": data.get("analysis_summary") or "Không có phân tích.",
        "recommended_action": data.get("recommended_action") or "Hãy cẩn trọng.",
    }


# ==========================
# PUBLIC API
# ==========================

def generate_explanation(meta: dict) -> dict:
    score = round(meta.get("overall_score", 0))
    risk_level = meta.get("risk_level", "suspicious")
    factors = meta.get("risk_factors", [])

    prompt = build_explanation_prompt(meta)

    start = time.monotonic()
    raw = call_llm(prompt)
    elapsed = time.monotonic() - start

    logger.info("llm_done | elapsed=%.2fs | success=%s", elapsed, raw is not None)

    if raw:
        # Always log raw response for debugging when parsing fails
        logger.debug("llm_raw_response | len=%d | content=%s", len(raw), raw[:500])

        parsed = _extract_json(raw)
        if parsed:
            logger.info("llm_json_parsed | success | keys=%s", list(parsed.keys()))
            return _normalize(parsed, {
                "score": score,
                "risk_level": risk_level,
                "factors": factors,
            })

        logger.warning("llm_json_parse_failed | raw_len=%d | raw_start=%s", len(raw), raw[:100])

    logger.warning("llm_fallback_used | elapsed=%.2fs", elapsed)

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "detected_signals": factors[:5],
        "website_summary": "Không thể phân tích đầy đủ.",
        "analysis_summary": "LLM không phản hồi hoặc lỗi.",
        "recommended_action": "Không nên tin tưởng, hãy kiểm tra thủ công.",
    }
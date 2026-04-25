"""
LLM Explanation Engine — Production Hardened

Improvements:
- Groq API support (OpenAI-compatible endpoint)
- Retry + timeout tuning for cloud APIs
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
from llm.promt_templates import build_url_explanation_prompt, build_text_explanation_prompt


# ==========================
# CONFIG
# ==========================

# For cloud APIs like Groq, 30s read timeout is more than enough.
# Ollama local can be slow, but we no longer use it.
LLM_TIMEOUT     = int(os.getenv("LLM_TIMEOUT", "30"))
LLM_MAX_TOKENS  = int(os.getenv("LLM_MAX_TOKENS", "512"))

MAX_RETRIES = 2

# Timeout tuple: (connect_timeout, read_timeout)
LLM_CONNECT_TIMEOUT = 10
LLM_READ_TIMEOUT = LLM_TIMEOUT
LLM_REQUEST_TIMEOUT = (LLM_CONNECT_TIMEOUT, LLM_READ_TIMEOUT)


# ==========================
# SESSION (performance)
# ==========================

def _create_session():
    """Create a configured requests session with connection pooling."""
    session = requests.Session()
    # Let connection pooling work naturally
    # Configure connection pooling
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=20,
        pool_maxsize=20,
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
# Prompts are now imported from llm.promt_templates


# ==========================
# LLM CALL
# ==========================

def _build_endpoint() -> str:
    """
    Build the correct chat completions endpoint.

    LLM_BASE_URL may already contain '/v1' (e.g. 'https://api.groq.com/openai/v1')
    or may be a bare host (e.g. 'http://localhost:11434').
    We normalise so the final URL always ends in '/chat/completions'.
    """
    base = LLM_BASE_URL.rstrip("/")
    # Already ends with /v1  →  just append /chat/completions
    if base.endswith("/v1"):
        return f"{base}/chat/completions"
    # Already ends with /chat/completions (idempotent)
    if base.endswith("/chat/completions"):
        return base
    # Bare OpenAI-compatible host  →  append /v1/chat/completions
    return f"{base}/v1/chat/completions"


def call_llm(prompt: str) -> Optional[str]:
    if _circuit_is_open():
        logger.info("llm_circuit_open_skip")
        return None

    endpoint = _build_endpoint()

    for attempt in range(MAX_RETRIES):
        try:
            logger.info(
                "llm_request | len=%d | attempt=%d | provider=%s | endpoint=%s",
                len(prompt),
                attempt,
                LLM_PROVIDER,
                endpoint,
            )

            resp = _session.post(
                endpoint,
                headers={
                    "Authorization": f"Bearer {LLM_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": LLM_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "max_tokens": LLM_MAX_TOKENS,
                },
                timeout=LLM_REQUEST_TIMEOUT,
            )

            if resp.status_code == 200:
                _record_success()
                logger.debug("llm_response_received | size=%d", len(resp.text))
                return resp.json()["choices"][0]["message"]["content"]


            logger.warning(
                "llm_bad_status | attempt=%d | status=%d | body=%s",
                attempt,
                resp.status_code,
                resp.text[:300],
            )


            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "5"))
                logger.info("llm_rate_limited | waiting=%ds", retry_after)
                time.sleep(retry_after)
                continue

            if 400 <= resp.status_code < 500:
                break

        except requests.ConnectTimeout:
            logger.warning("llm_connect_timeout | attempt=%d", attempt)
        except requests.ReadTimeout:
            logger.warning("llm_read_timeout | attempt=%d | timeout=%ds", attempt, LLM_READ_TIMEOUT)
        except requests.Timeout as e:
            logger.warning("llm_timeout | attempt=%d | type=%s", attempt, type(e).__name__)
        except Exception as e:
            logger.warning("llm_error | attempt=%d | %s", attempt, str(e)[:200])

    _record_failure()
    return None


# ==========================
# JSON PARSER (SAFE)
# ==========================

def _extract_json(text: str) -> tuple[Optional[dict], str]:
    if not text:
        return None, "Empty text"

    text = text.strip()
    
    # remove markdown code blocks
    if "```" in text:
        parts = text.split("```")
        if len(parts) >= 3:
            text = parts[1]
        elif len(parts) == 2:
            text = parts[1]
        text = text.replace("json", "").replace("JSON", "").strip()

    # try direct parse first
    err_msg = ""
    try:
        # Prevent common LLM error: trailing commas
        text_clean = re.sub(r',\s*([\]}])', r'\1', text)
        data = json.loads(text_clean)
        return data, "success"
    except json.JSONDecodeError as e:
        err_msg = str(e)

    # more aggressive search for JSON object
    start_idx = text.find('{')
    end_idx = text.rfind('}')
    
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        json_candidate = text[start_idx:end_idx + 1]
        try:
            candidate_clean = re.sub(r',\s*([\]}])', r'\1', json_candidate)
            data = json.loads(candidate_clean)
            return data, "success"
        except json.JSONDecodeError as e:
            err_msg = str(e)

    # fallback: try regex
    matches = re.findall(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
    for m in matches:
        try:
            m_clean = re.sub(r',\s*([\]}])', r'\1', m)
            data = json.loads(m_clean)
            return data, "success"
        except json.JSONDecodeError:
            continue

    return None, f"Parse err: {err_msg} | raw: {text[:40]}"


# ==========================
# NORMALIZE
# ==========================

def _normalize(data: dict, fallback: dict) -> dict:
    """Pass LLM output fields through to fusion layer (minimal processing)."""
    # Validate site_type
    _valid_types = {"safe", "suspicious", "scam", "adult", "unknown"}
    site_type = str(data.get("site_type") or "unknown").lower().strip()
    if site_type not in _valid_types:
        site_type = "unknown"

    return {
        "site_type":        site_type,
        "content_summary":  data.get("content_summary") or _NO_DATA,
        "behavior_summary": data.get("behavior_summary") or _NO_BEHAVIOR,
        "analysis_summary": data.get("analysis_summary") or _NO_DATA,
        "conflict_hint":    str(data.get("conflict_hint") or "").lower().strip(),
        # These fields are intentionally omitted — fusion layer injects them:
        # risk_level, score, recommended_action, warnings
    }


_NO_DATA     = "Không đủ dữ liệu."
_NO_BEHAVIOR = "Không phát hiện hành vi đáng chú ý."


# ==========================
# PUBLIC API
# ==========================

def generate_explanation(meta: dict) -> dict:
    score = round(meta.get("overall_score", 0))
    risk_level = meta.get("risk_level", "suspicious")
    factors = meta.get("risk_factors", [])

    if meta.get("scam_type") == "text_scam":
        prompt = build_text_explanation_prompt(meta)
    else:
        prompt = build_url_explanation_prompt(meta)

    start = time.monotonic()
    raw = call_llm(prompt)
    elapsed = time.monotonic() - start

    logger.info("llm_done | elapsed=%.2fs | success=%s", elapsed, raw is not None)

    # ==========================
    # VALIDATE + PARSE
    # ==========================
    if raw:
        logger.debug("llm_raw_response | len=%d", len(raw))

        # ---- Guard 1: truncate để tránh payload quá lớn
        if len(raw) > 2000:
            raw = raw[:2000]

        # ---- Guard 2: detect prompt leakage
        LEAK_PATTERNS = [
            "Bạn là chuyên gia",
            "Tóm tắt nội dung",
            "Form đăng nhập",
            "Risk Analysis",
            "Confidence:",
        ]
        if any(p in raw for p in LEAK_PATTERNS):
            logger.warning("llm_prompt_leak_detected")
            raw = None

        parsed, err_reason = _extract_json(raw) if raw else (None, "prompt_leak")

        # ---- Guard 3: accept new schema (content_summary or analysis_summary)
        REQUIRED_KEYS = ["site_type", "analysis_summary"]
        # Also accept old schema gracefully
        ALT_KEYS = ["content_summary"]

        if (
            parsed
            and isinstance(parsed, dict)
            and (
                all(k in parsed for k in REQUIRED_KEYS)
                or any(k in parsed for k in ALT_KEYS)
            )
        ):
            logger.info("llm_json_parsed | success | keys=%s", list(parsed.keys()))
            return _normalize(parsed, {
                "score": score,
                "risk_level": risk_level,
                "factors": factors,
            })

        logger.warning(
            "llm_json_parse_failed | reason=%s | raw_len=%s",
            err_reason,
            len(raw) if raw else 0
        )

    # ==========================
    # HARD FALLBACK (user-friendly)
    # ==========================
    logger.warning("llm_fallback_used | elapsed=%.2fs", elapsed)

    return {
        "site_type":        "safe" if score < 30 else ("suspicious" if score < 60 else "scam"),
        "content_summary":  _NO_DATA,
        "behavior_summary": _NO_BEHAVIOR,
        "analysis_summary": _NO_DATA,
        "conflict_hint":    "",
        # risk_level, recommended_action, warnings injected by fusion layer
    }
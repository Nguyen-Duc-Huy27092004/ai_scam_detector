"""
Chat API — Cybersecurity Chatbot with LLM Tool Calling
Production fixes:
- SSRF guard on all tool-call URLs
- JSON parse error handling
- LLM provider fallback (Ollama / OpenAI / Gemini)
- Sanitized logs (no PII/response body)
- Timeout on all HTTP calls
- Input length validation
"""
import json
import asyncio
from typing import List, Dict, Any, Optional

from pydantic import BaseModel, Field, validator

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from core.limiter import limiter

from utils.logger import logger
from utils.config import LLM_BASE_URL, LLM_API_KEY, LLM_MODEL, LLM_PROVIDER
from utils.validators import is_valid_url
from utils.url_utils import is_safe_url
from services.url_pipeline import analyze_url
from services.text_pipeline import analyze_text
import requests

router = APIRouter()

# ========================
# MAX LIMITS
# ========================
MAX_MESSAGE_LENGTH = 4000
MAX_MESSAGES       = 30


# ========================
# REQUEST SCHEMAS
# ========================

class ChatMessage(BaseModel):
    role:    str = Field(..., description="user or assistant")
    content: str = Field(..., description="Message content")

    @validator("content")
    def content_not_empty(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Message content cannot be empty")
        return v[:MAX_MESSAGE_LENGTH]  # Truncate silently

    @validator("role")
    def role_valid(cls, v):
        if v not in ("user", "assistant", "system", "tool"):
            raise ValueError("Invalid role")
        return v


class ChatRequest(BaseModel):
    messages: List[ChatMessage] = Field(..., max_items=MAX_MESSAGES)
    images:   Optional[List[str]] = Field(None, description="Base64 encoded images (optional)")
    stream:   bool = Field(False, description="Stream response via SSE")


# ========================
# TOOL DEFINITIONS
# ========================

TOOLS = [
    {
        "type": "function",
        "function": {
            "name":        "analyze_url",
            "description": "Analyzes a URL for phishing and scam indicators. Returns a detailed risk report.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The full URL to analyze (must start with http/https)"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name":        "analyze_text",
            "description": "Analyzes a text message or email for scam patterns.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text content to analyze"}
                },
                "required": ["text"]
            }
        }
    }
]

SYSTEM_PROMPT = (
    "You are a cybersecurity expert chatbot for AI Scam Detector. "
    "Help users detect scams from URLs, text messages, and images. "
    "Use the provided tools to analyze URLs or text when asked. "
    "Always respond in the same language as the user. "
    "Keep answers concise and actionable."
)


# ========================
# LLM CALL (sync, runs in thread)
# ========================

def _call_llm_with_tools(messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Call LLM API with tool support. Returns assistant message dict."""

    # ─── Ollama (no native tool calling) ───────────────────────────────────
    if LLM_PROVIDER not in ("openai", "gemini"):
        try:
            resp = requests.post(
                f"{LLM_BASE_URL}/api/chat",
                json={"model": LLM_MODEL, "messages": messages, "stream": False},
                timeout=20,
            )
            if resp.status_code == 200:
                content = resp.json().get("message", {}).get("content", "")
                return {"role": "assistant", "content": content or "Tôi không thể xử lý yêu cầu này."}
        except Exception as e:
            logger.warning("ollama_chat_fail | %s", str(e))
        return {"role": "assistant", "content": "Dịch vụ AI tạm thời không khả dụng. Vui lòng thử lại sau."}

    # ─── OpenAI / Gemini ────────────────────────────────────────────────────
    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type":  "application/json",
    }
    payload = {
        "model":       LLM_MODEL,
        "messages":    messages,
        "tools":       TOOLS,
        "tool_choice": "auto",
    }
    try:
        resp = requests.post(
            f"{LLM_BASE_URL}/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=20,
        )
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]
        # FIX: log status only — NOT resp.text which may contain user PII
        logger.error("llm_chat_http_error | provider=%s | status=%d", LLM_PROVIDER, resp.status_code)
    except requests.exceptions.Timeout:
        logger.warning("llm_chat_timeout | provider=%s", LLM_PROVIDER)
    except Exception as e:
        logger.warning("llm_chat_fail | %s", str(e))

    return {"role": "assistant", "content": "Dịch vụ AI tạm thời không khả dụng. Vui lòng thử lại sau."}


# ========================
# SSE STREAMING (sync generator)
# ========================

def _stream_llm(messages: List[Dict[str, Any]]):
    """Generator for streaming LLM responses via SSE."""
    if LLM_PROVIDER not in ("openai", "gemini"):
        # Ollama streaming via /api/chat
        try:
            resp = requests.post(
                f"{LLM_BASE_URL}/api/chat",
                json={"model": LLM_MODEL, "messages": messages, "stream": True},
                stream=True,
                timeout=30,
            )
            for line in resp.iter_lines():
                if not line:
                    continue
                try:
                    data = json.loads(line.decode("utf-8"))
                    content = data.get("message", {}).get("content", "")
                    if content:
                        yield {"event": "message", "data": json.dumps({"content": content})}
                    if data.get("done"):
                        break
                except Exception:
                    pass
        except Exception as e:
            logger.warning("ollama_stream_fail | %s", str(e))
            yield {"event": "error", "data": json.dumps({"error": "Stream interrupted"})}
        yield {"event": "done", "data": "[DONE]"}
        return

    # OpenAI streaming
    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type":  "application/json",
    }
    payload = {"model": LLM_MODEL, "messages": messages, "stream": True}
    try:
        with requests.post(
            f"{LLM_BASE_URL}/v1/chat/completions",
            headers=headers,
            json=payload,
            stream=True,
            timeout=30,
        ) as resp:
            if resp.status_code != 200:
                yield {"event": "error", "data": json.dumps({"error": f"LLM HTTP {resp.status_code}"})}
                return
            for line in resp.iter_lines():
                if not line:
                    continue
                decoded = line.decode("utf-8")
                if not decoded.startswith("data: "):
                    continue
                data_str = decoded[6:].strip()
                if data_str == "[DONE]":
                    break
                try:
                    chunk = json.loads(data_str)
                    delta_content = (
                        chunk.get("choices", [{}])[0]
                             .get("delta", {})
                             .get("content", "")
                    )
                    if delta_content:
                        yield {"event": "message", "data": json.dumps({"content": delta_content})}
                except (json.JSONDecodeError, IndexError, KeyError):
                    pass
        yield {"event": "done", "data": "[DONE]"}

    except Exception as e:
        logger.error("llm_stream_error | %s", str(e))
        yield {"event": "error", "data": json.dumps({"error": "Stream interrupted"})}


# ========================
# TOOL EXECUTION (async)
# ========================

async def _execute_tool(function_name: str, function_args: dict) -> str:
    """Execute a tool call from the LLM. Returns JSON string result."""

    if function_name == "analyze_url":
        url = str(function_args.get("url", "")).strip()

        # FIX: SSRF guard — LLM can be prompt-injected to supply internal URLs
        if not is_valid_url(url) or not is_safe_url(url):
            logger.warning("chat_tool_ssrf_blocked | url=%.100s", url)
            return json.dumps({"error": "URL không hợp lệ hoặc bị chặn vì lý do bảo mật"})

        try:
            res = await asyncio.to_thread(analyze_url, url)
            return json.dumps({
                "risk_level": res.get("risk_level"),
                "score":      res.get("overall_score"),
                "is_scam":    res.get("is_scam"),
                "signals":    res.get("risk_factors", [])[:5],
            })
        except Exception as e:
            logger.warning("tool_analyze_url_fail | %s", str(e))
            return json.dumps({"error": f"URLs analysis failed: {str(e)}"})

    elif function_name == "analyze_text":
        text = str(function_args.get("text", "")).strip()
        if not text:
            return json.dumps({"error": "Text input is empty"})
        if len(text) > MAX_MESSAGE_LENGTH:
            text = text[:MAX_MESSAGE_LENGTH]
        try:
            res = await asyncio.to_thread(analyze_text, text)
            return json.dumps({
                "risk_level": res.get("risk_level"),
                "score":      res.get("overall_score"),
                "keywords":   res.get("keywords", [])[:8],
            })
        except Exception as e:
            logger.warning("tool_analyze_text_fail | %s", str(e))
            return json.dumps({"error": f"Text analysis failed: {str(e)}"})

    return json.dumps({"error": f"Unknown tool: {function_name}"})


# ========================
# MAIN ENDPOINT
# ========================

@router.post("/completions")
@limiter.limit("15/minute")
async def chat_completions(request: Request, payload: ChatRequest):
    """
    Chatbot endpoint with LLM tool calling (analyze_url, analyze_text).
    Supports streaming via SSE.
    """
    try:
        messages = [
            {"role": msg.role, "content": msg.content}
            for msg in payload.messages
        ]

        # Inject system prompt if not present
        if not messages or messages[0].get("role") != "system":
            messages.insert(0, {"role": "system", "content": SYSTEM_PROMPT})

        # ─── First LLM call ───────────────────────────────────────────────
        response_message = await asyncio.to_thread(_call_llm_with_tools, messages)

        tool_calls = response_message.get("tool_calls")

        if not tool_calls:
            # No tool use — return or stream directly
            if payload.stream:
                return EventSourceResponse(_stream_llm(messages))
            return JSONResponse(content={"success": True, "message": response_message})

        # ─── Execute tool calls ───────────────────────────────────────────
        messages.append(response_message)

        for tool_call in tool_calls:
            tc_id          = tool_call.get("id", "")
            function_info  = tool_call.get("function", {})
            function_name  = function_info.get("name", "")

            # FIX: JSON parse error handling — LLM can return malformed args
            try:
                raw_args      = function_info.get("arguments", "{}")
                function_args = json.loads(raw_args) if raw_args else {}
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning("tool_call_args_parse_fail | tool=%s | %s", function_name, str(e))
                function_args = {}

            logger.info("llm_tool_call | tool=%s", function_name)

            tool_result = await _execute_tool(function_name, function_args)

            messages.append({
                "tool_call_id": tc_id,
                "role":         "tool",
                "name":         function_name,
                "content":      tool_result,
            })

        # ─── Second LLM call with tool results ───────────────────────────
        if payload.stream:
            return EventSourceResponse(_stream_llm(messages))

        final_response = await asyncio.to_thread(_call_llm_with_tools, messages)
        return JSONResponse(content={"success": True, "message": final_response})

    except Exception as e:
        logger.error("chat_endpoint_error | %s", str(e))
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": "Internal server error"}
        )

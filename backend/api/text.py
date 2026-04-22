import asyncio
from typing import List, Dict, Any
from pydantic import BaseModel, Field

from fastapi import APIRouter, Request

from core.limiter import limiter
from core.responses import json_error, json_success
from utils.logger import logger
from utils.validators import validate_text_input
from services.text_pipeline import analyze_text

router = APIRouter()

BATCH_CONCURRENCY = 5


class TextAnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1)


class BatchTextAnalyzeRequest(BaseModel):
    texts: List[str] = Field(..., min_length=1, max_length=50)


@router.post("/analyze")
@limiter.limit("20/minute")
async def analyze_text_endpoint(request: Request, payload: TextAnalyzeRequest):
    """Analyze text for scam indicators."""
    try:
        text = payload.text.strip()

        is_valid, error_msg = validate_text_input(text)
        if not is_valid:
            return json_error(error_msg, 400)

        logger.info("text_analysis_requested | length=%d", len(text))

        result = await asyncio.to_thread(analyze_text, text)

        if result.get("status") == "error":
            logger.error("text_analysis_error | error=%s", result.get("error"))
            return json_error("Analysis failed", 500, {"error": result.get("error")})

        response_data = {
            "text_preview": text[:100] + ("..." if len(text) > 100 else ""),
            "text_length": len(text),
            "analysis": {
                "risk_level": result.get("risk_level"),
                "overall_score": result.get("overall_score"),
                "label": result.get("label"),
                "confidence": result.get("classification", {}).get("confidence"),
            },
            "details": {
                "classification": result.get("classification"),
                "keywords_found": result.get("keywords", []),
            },
            "advice": result.get("advice"),
            "recommendations": result.get("recommendations", []),
            "risk_factors": result.get("risk_factors", []),
            "record_id": result.get("record_id"),
        }

        return json_success(response_data, 200)

    except Exception as e:
        logger.exception("text_endpoint_error | error=%s", str(e))
        return json_error("Internal server error", 500)


@router.post("/batch-analyze")
@limiter.limit("5/minute")
async def batch_analyze_texts(request: Request, payload: BatchTextAnalyzeRequest):
    """Analyze multiple text samples."""
    try:
        texts = payload.texts

        invalid_texts = []
        for i, text in enumerate(texts):
            is_valid, _ = validate_text_input(text)
            if not is_valid:
                invalid_texts.append(i)

        if invalid_texts:
            return json_error("Some texts are invalid", 400, {"invalid_indices": invalid_texts[:5]})

        logger.info("batch_text_analysis_requested | count=%d", len(texts))

        sem = asyncio.Semaphore(BATCH_CONCURRENCY)

        async def analyze_one(idx: int, t: str) -> Dict[str, Any]:
            async with sem:
                try:
                    result = await asyncio.to_thread(analyze_text, t)
                    return {
                        "index": idx,
                        "text_length": len(t),
                        "risk_level": result.get("risk_level"),
                        "overall_score": result.get("overall_score"),
                        "confidence": result.get("classification", {}).get("confidence"),
                        "keywords": result.get("keywords", []),
                        "record_id": result.get("record_id"),
                        "status": result.get("status"),
                    }
                except Exception as e:
                    logger.error("batch_text_failed | index=%d | error=%s", idx, str(e))
                    return {
                        "index": idx,
                        "error": "Analysis failed",
                        "status": "error",
                    }

        tasks = [analyze_one(i, t) for i, t in enumerate(texts)]
        results = await asyncio.gather(*tasks)

        return json_success({
            "total": len(texts),
            "completed": sum(1 for r in results if r.get("status") != "error"),
            "results": results,
        }, 200)

    except Exception as e:
        logger.exception("batch_text_endpoint_error | error=%s", str(e))
        return json_error("Internal server error", 500)

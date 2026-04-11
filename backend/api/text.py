import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from fastapi import APIRouter, Request  # FIX: added Request for rate limiter
from fastapi.responses import JSONResponse

from core.limiter import limiter  # FIX: import rate limiter
from utils.logger import logger
from utils.validators import validate_text_input
from services.text_pipeline import analyze_text

router = APIRouter()

class TextAnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1)

class BatchTextAnalyzeRequest(BaseModel):
    texts: List[str] = Field(..., min_items=1, max_items=50)

def _success_response(data: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            'success': True,
            'data': data,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    )

def _error_response(message: str, status_code: int = 400, details: Optional[Dict] = None) -> JSONResponse:
    content = {
        'success': False,
        'error': message,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    if details:
        content['details'] = details
    return JSONResponse(status_code=status_code, content=content)


@router.post("/analyze")
@limiter.limit("20/minute")  # FIX: add rate limit - missing from original, prevent NLP abuse
async def analyze_text_endpoint(request: Request, payload: TextAnalyzeRequest):  # FIX: renamed param to 'payload' to free 'request' for limiter
    """
    Analyze text for scam indicators.
    """
    try:
        text = payload.text.strip()  # FIX: use 'payload' instead of 'request'
        
        is_valid, error_msg = validate_text_input(text)
        if not is_valid:
            return _error_response(error_msg, 400)
            
        logger.info("text_analysis_requested | length=%d", len(text))
        
        # Run blocking analysis in threadpool
        result = await asyncio.to_thread(analyze_text, text)
        
        if result.get('status') == 'error':
            logger.error("text_analysis_error | error=%s", result.get('error'))
            return _error_response("Analysis failed", 500, {'error': result.get('error')})
            
        response_data = {
            'text_preview': text[:100] + ('...' if len(text) > 100 else ''),
            'text_length': len(text),
            'analysis': {
                'risk_level': result.get('risk_level'),
                'overall_score': result.get('overall_score'),
                'label': result.get('label'),
                'confidence': result.get('classification', {}).get('confidence'),
            },
            'details': {
                'classification': result.get('classification'),
                'keywords_found': result.get('keywords', []),
            },
            'advice': result.get('advice'),
            'recommendations': result.get('recommendations', []),
            'risk_factors': result.get('risk_factors', []),
            'record_id': result.get('record_id')
        }
        
        return _success_response(response_data, 200)
        
    except Exception as e:
        logger.exception("text_endpoint_error | error=%s", str(e))
        return _error_response("Internal server error", 500)


@router.post("/batch-analyze")
async def batch_analyze_texts(request: BatchTextAnalyzeRequest):
    """
    Analyze multiple text samples.
    """
    try:
        texts = request.texts
        
        invalid_texts = []
        for i, text in enumerate(texts):
            is_valid, _ = validate_text_input(text)
            if not is_valid:
                invalid_texts.append(i)
                
        if invalid_texts:
            return _error_response("Some texts are invalid", 400, {'invalid_indices': invalid_texts[:5]})
            
        logger.info("batch_text_analysis_requested | count=%d", len(texts))
        
        results = []
        for i, text in enumerate(texts):
            try:
                result = await asyncio.to_thread(analyze_text, text)
                results.append({
                    'index': i,
                    'text_length': len(text),
                    'risk_level': result.get('risk_level'),
                    'overall_score': result.get('overall_score'),
                    'confidence': result.get('classification', {}).get('confidence'),
                    'keywords': result.get('keywords', []),
                    'record_id': result.get('record_id'),
                    'status': result.get('status')
                })
            except Exception as e:
                logger.error("batch_text_failed | index=%d | error=%s", i, str(e))
                results.append({
                    'index': i,
                    'error': str(e),
                    'status': 'error'
                })
                
        return _success_response({
            'total': len(texts),
            'completed': sum(1 for r in results if r.get('status') != 'error'),
            'results': results
        }, 200)
        
    except Exception as e:
        logger.exception("batch_text_endpoint_error | error=%s", str(e))
        return _error_response("Internal server error", 500)


# FIX: /keywords endpoint DISABLED — exposing detection keywords lets attackers craft
# scam messages that avoid triggering them (detector bypass attack).
# If needed for internal monitoring, protect behind an API key/admin auth.
#
# @router.get("/keywords")
# async def get_suspicious_keywords():
#     from ml.text.text_classifier import TextScamClassifier
#     keywords_by_weight = {}
#     for keyword, weight in TextScamClassifier.SCAM_KEYWORDS.items():
#         if weight not in keywords_by_weight:
#             keywords_by_weight[weight] = []
#         keywords_by_weight[weight].append(keyword)
#     return _success_response({'keywords_by_weight': keywords_by_weight,
#                               'total_keywords': len(TextScamClassifier.SCAM_KEYWORDS)}, 200)

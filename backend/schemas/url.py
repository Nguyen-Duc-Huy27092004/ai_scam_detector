from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


class URLAnalyzeRequest(BaseModel):
    """Request body for URL / deep analysis endpoints."""

    url: str = Field(..., min_length=1, description="Full URL to analyze")


class URLAnalyzeResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: str

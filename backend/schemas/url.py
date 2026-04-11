from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any

class URLAnalyzeRequest(BaseModel):
    url: str

class URLAnalyzeResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: str

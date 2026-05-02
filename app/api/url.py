from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.analyzers.url_analyzer import analyze_url


# APIRouter keeps URL analysis separate from the existing phishing endpoint.
router = APIRouter(tags=["url"])


# This model describes the JSON body the client must send.
class UrlAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, description="URL to analyze")


# This model describes the exact JSON shape returned by the endpoint.
class UrlAnalyzeResponse(BaseModel):
    trust_score: int
    risk: Literal["safe", "suspicious", "dangerous"]
    reasons: list[str]
    recommendation: str


# This endpoint analyzes phishing signals in a single URL.
@router.post("/url", response_model=UrlAnalyzeResponse)
def analyze_url_endpoint(request: UrlAnalyzeRequest):
    return analyze_url(request.url)

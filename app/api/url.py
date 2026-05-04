from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.analyzers.url_analyzer import analyze_url
from app.db.dependencies import get_db
from app.db.repository import save_scan_history


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
def analyze_url_endpoint(request: UrlAnalyzeRequest, db: Session = Depends(get_db)):
    result = analyze_url(request.url)

    save_scan_history(
        db=db,
        scan_type="url",
        input_value=request.url,
        trust_score=result["trust_score"],
        risk=result["risk"],
        reasons=result["reasons"],
        recommendation=result["recommendation"],
    )

    return result

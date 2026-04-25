from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.analyzers.phishing_analyzer import analyze_phishing_text
from app.scoring.trust_score import calculate_trust_score, get_recommendation, get_risk_level


# APIRouter lets us group related endpoints together.
# main.py decides where this router is mounted in the full API.
router = APIRouter(tags=["phishing"])


# This model describes the JSON body the client must send.
# Pydantic validates that "text" exists and is a string.
class PhishingAnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Message text to analyze")


# This model describes the shape of the JSON response.
# Literal limits "risk" to one of these three exact values.
class PhishingAnalyzeResponse(BaseModel):
    trust_score: int
    risk: Literal["safe", "suspicious", "dangerous"]
    reasons: list[str]
    recommendation: str


# This endpoint receives a message, analyzes it, scores it, and returns advice.
@router.post("/phishing", response_model=PhishingAnalyzeResponse)
def analyze_phishing(request: PhishingAnalyzeRequest):
    reasons = analyze_phishing_text(request.text)
    trust_score = calculate_trust_score(reasons)
    risk = get_risk_level(trust_score)
    recommendation = get_recommendation(risk)

    return PhishingAnalyzeResponse(
        trust_score=trust_score,
        risk=risk,
        reasons=reasons,
        recommendation=recommendation,
    )

from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.analyzers.url_analyzer import RECOMMENDATIONS, analyze_url
from app.db.dependencies import get_db
from app.db.repository import save_scan_history
from app.services.google_safe_browsing import GOOGLE_SAFE_BROWSING_REASON, check_google_safe_browsing
from app.services.virustotal import (
    VIRUSTOTAL_MALICIOUS_REASON,
    VIRUSTOTAL_SUSPICIOUS_REASON,
    check_virustotal_url,
)


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
    google_safe_browsing_result = check_google_safe_browsing(request.url)
    virustotal_result = check_virustotal_url(request.url)

    # Safe Browsing is an external signal: matches make the result dangerous,
    # while missing keys, no matches, or API failures leave internal rules intact.
    if google_safe_browsing_result.get("matches"):
        if GOOGLE_SAFE_BROWSING_REASON not in result["reasons"]:
            result["reasons"].append(GOOGLE_SAFE_BROWSING_REASON)

        result["trust_score"] = min(result["trust_score"], 10)
        result["risk"] = "dangerous"
        result["recommendation"] = RECOMMENDATIONS["dangerous"]

    # VirusTotal does not make clean URLs safe; it only strengthens suspicious or dangerous verdicts.
    if virustotal_result.get("checked"):
        malicious_count = virustotal_result.get("malicious", 0)
        suspicious_count = virustotal_result.get("suspicious", 0)

        if malicious_count >= 3:
            if VIRUSTOTAL_MALICIOUS_REASON not in result["reasons"]:
                result["reasons"].append(VIRUSTOTAL_MALICIOUS_REASON)

            result["trust_score"] = min(result["trust_score"], 10)
            result["risk"] = "dangerous"
            result["recommendation"] = RECOMMENDATIONS["dangerous"]
        elif malicious_count >= 1 or suspicious_count >= 2:
            if VIRUSTOTAL_SUSPICIOUS_REASON not in result["reasons"]:
                result["reasons"].append(VIRUSTOTAL_SUSPICIOUS_REASON)

            result["trust_score"] = min(result["trust_score"], 55)
            if result["risk"] == "safe":
                result["risk"] = "suspicious"
                result["recommendation"] = RECOMMENDATIONS["suspicious"]

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

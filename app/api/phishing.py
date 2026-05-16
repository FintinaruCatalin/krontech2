from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.analyzers.phishing_analyzer import analyze_phishing_text
from app.db.dependencies import get_db
from app.db.repository import save_scan_history
from app.scoring.trust_score import calculate_trust_score, get_recommendation, get_risk_level
from app.services.ml.predictor import predict_sms_with_local_model


# APIRouter lets us group related endpoints together.
# main.py decides where this router is mounted in the full API.
router = APIRouter(tags=["phishing"])

LOCAL_ML_PHISHING_REASON = "Modelul ML local a identificat caracteristici de phishing în mesaj."


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
def analyze_phishing(request: PhishingAnalyzeRequest, db: Session = Depends(get_db)):
    reasons = analyze_phishing_text(request.text)
    trust_score = calculate_trust_score(reasons)
    risk = get_risk_level(trust_score)
    print(f"[SMS Analyzer] Rule-based reasons before ML: {reasons}")
    print(f"[SMS Analyzer] Rule-based decision: trust_score={trust_score}, risk={risk}")

    local_ml_result = predict_sms_with_local_model(request.text)
    print(
        "[SMS Analyzer] Local ML result: "
        f"available={local_ml_result['available']}, "
        f"label={local_ml_result['label']}, "
        f"confidence={local_ml_result['confidence']}"
    )

    if local_ml_result["available"] and local_ml_result["label"] == "phishing":
        if LOCAL_ML_PHISHING_REASON not in reasons:
            reasons.append(LOCAL_ML_PHISHING_REASON)
            print("[SMS Analyzer] Local ML phishing reason appended.")
        else:
            print("[SMS Analyzer] Local ML phishing reason already present.")

        # Scoring impact: the model is an extra signal. It lowers trust, but it
        # does not replace the existing rule-based checks or make safe verdicts.
        had_rule_based_indicators = len(reasons) > 1
        confidence = local_ml_result["confidence"]

        if confidence >= 0.85:
            trust_score = max(0, trust_score - 30)

            if had_rule_based_indicators:
                risk = "dangerous"
        else:
            trust_score = max(0, trust_score - 15)

        if risk == "safe":
            risk = "suspicious"
    else:
        print("[SMS Analyzer] Local ML did not append a phishing reason.")

    recommendation = get_recommendation(risk)
    print(f"[SMS Analyzer] Final decision: trust_score={trust_score}, risk={risk}, reasons={reasons}")

    save_scan_history(
        db=db,
        scan_type="sms",
        input_value=request.text,
        trust_score=trust_score,
        risk=risk,
        reasons=reasons,
        recommendation=recommendation,
    )

    return PhishingAnalyzeResponse(
        trust_score=trust_score,
        risk=risk,
        reasons=reasons,
        recommendation=recommendation,
    )

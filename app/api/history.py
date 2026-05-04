import json
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.db.models import ScanHistory


router = APIRouter(tags=["history"])


class ScanHistoryResponse(BaseModel):
    id: int
    scan_type: Literal["sms", "url"]
    input_value: str
    trust_score: int
    risk: str
    reasons: list[str]
    recommendation: str
    created_at: datetime

    class Config:
        from_attributes = True


def normalize_reasons(reasons: object) -> list[str]:
    if isinstance(reasons, list):
        return [str(reason) for reason in reasons]

    if isinstance(reasons, str):
        try:
            parsed_reasons = json.loads(reasons)
        except json.JSONDecodeError:
            return [reasons]

        if isinstance(parsed_reasons, list):
            return [str(reason) for reason in parsed_reasons]

        return [reasons]

    return []


@router.get("/history", response_model=list[ScanHistoryResponse])
def get_scan_history(scan_type: Literal["sms", "url"] | None = None, db: Session = Depends(get_db)):
    query = db.query(ScanHistory)

    if scan_type:
        query = query.filter(ScanHistory.scan_type == scan_type)

    try:
        records = query.order_by(ScanHistory.created_at.desc()).limit(50).all()
    except SQLAlchemyError:
        return []

    return [
        ScanHistoryResponse(
            id=record.id,
            scan_type=record.scan_type,
            input_value=record.input_value,
            trust_score=record.trust_score,
            risk=record.risk,
            reasons=normalize_reasons(record.reasons),
            recommendation=record.recommendation,
            created_at=record.created_at,
        )
        for record in records
    ]

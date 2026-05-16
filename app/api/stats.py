from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.db.models import ScanHistory


router = APIRouter(tags=["stats"])


class StatsResponse(BaseModel):
    total_analyses: int
    alerts_generated: int
    risk_rate: float


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    try:
        total_analyses = db.query(func.count(ScanHistory.id)).scalar() or 0
        alerts_generated = (
            db.query(func.count(ScanHistory.id))
            .filter(ScanHistory.risk.in_(["suspicious", "dangerous"]))
            .scalar()
            or 0
        )
    except SQLAlchemyError:
        return StatsResponse(total_analyses=0, alerts_generated=0, risk_rate=0)

    risk_rate = 0 if total_analyses == 0 else (alerts_generated / total_analyses) * 100

    return StatsResponse(
        total_analyses=total_analyses,
        alerts_generated=alerts_generated,
        risk_rate=risk_rate,
    )

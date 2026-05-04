from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.models import ScanHistory


def save_scan_history(
    db: Session,
    scan_type: str,
    input_value: str,
    trust_score: int,
    risk: str,
    reasons: list[str],
    recommendation: str,
) -> None:
    # History is useful, but scan APIs should still respond if the database is down.
    scan_history = ScanHistory(
        scan_type=scan_type,
        input_value=input_value,
        trust_score=trust_score,
        risk=risk,
        reasons=reasons,
        recommendation=recommendation,
    )

    try:
        db.add(scan_history)
        db.commit()
    except SQLAlchemyError:
        db.rollback()

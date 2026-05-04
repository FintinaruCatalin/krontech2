from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, JSON, String, Text

from app.db.database import Base


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String, index=True)
    input_value = Column(Text)
    trust_score = Column(Integer)
    risk = Column(String)
    reasons = Column(JSON)
    recommendation = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

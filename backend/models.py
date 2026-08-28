from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from sqlalchemy.sql import func
from backend.database import Base


class URLScan(Base):
    """
    SQLAlchemy model representing the url_scans table.
    Stores all URL analysis records, scores, classifications, and extracted features.
    """
    __tablename__ = "url_scans"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    risk_score = Column(Integer, nullable=False)
    classification = Column(String(50), nullable=False, index=True)
    detection_reasons = Column(JSON, nullable=False)
    extracted_features = Column(JSON, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    def to_dict(self):
        """Converts model instance to dictionary format."""
        return {
            "id": self.id,
            "url": self.url,
            "domain": self.domain,
            "risk_score": self.risk_score,
            "classification": self.classification,
            "detection_reasons": self.detection_reasons,
            "extracted_features": self.extracted_features,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

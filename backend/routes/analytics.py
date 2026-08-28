import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from backend.database import get_db
from backend.models import URLScan
from backend.schemas import AnalyticsResponse, ScanResponse

logger = logging.getLogger("hackvortex.routes.analytics")
router = APIRouter(prefix="/api", tags=["Analytics"])


@router.get("/analytics", response_model=AnalyticsResponse)
def get_analytics(db: Session = Depends(get_db)):
    """
    Computes and returns aggregate scan statistics directly from the MySQL database.
    """
    try:
        # Total scans
        total_scans = db.query(func.count(URLScan.id)).scalar() or 0

        # Classification counts
        safe_scans = (
            db.query(func.count(URLScan.id))
            .filter(URLScan.classification == "SAFE")
            .scalar()
            or 0
        )

        suspicious_scans = (
            db.query(func.count(URLScan.id))
            .filter(URLScan.classification == "SUSPICIOUS")
            .scalar()
            or 0
        )

        malicious_scans = (
            db.query(func.count(URLScan.id))
            .filter(URLScan.classification == "MALICIOUS")
            .scalar()
            or 0
        )

        # Average risk score
        avg_score_raw = db.query(func.avg(URLScan.risk_score)).scalar()
        average_risk_score = round(float(avg_score_raw)) if avg_score_raw is not None else 0

        # Unique domains
        unique_domains = db.query(func.count(distinct(URLScan.domain))).scalar() or 0

        # Percentages
        if total_scans > 0:
            safe_pct = round((safe_scans / total_scans) * 100, 1)
            suspicious_pct = round((suspicious_scans / total_scans) * 100, 1)
            malicious_pct = round((malicious_scans / total_scans) * 100, 1)
        else:
            safe_pct = 0.0
            suspicious_pct = 0.0
            malicious_pct = 0.0

        # Recent 5 scans
        recent_scans = (
            db.query(URLScan)
            .order_by(URLScan.created_at.desc())
            .limit(5)
            .all()
        )

        return AnalyticsResponse(
            total_scans=total_scans,
            safe_scans=safe_scans,
            suspicious_scans=suspicious_scans,
            malicious_scans=malicious_scans,
            average_risk_score=average_risk_score,
            unique_domains=unique_domains,
            safe_percentage=safe_pct,
            suspicious_percentage=suspicious_pct,
            malicious_percentage=malicious_pct,
            recent_scans=recent_scans,
        )

    except Exception as e:
        logger.error(f"Error computing scan analytics: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch analytics: {str(e)}"
        )

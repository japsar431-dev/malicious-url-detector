import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models import URLScan
from backend.schemas import ScanRequest, ScanResponse
from backend.engine.threat_detector import analyze_threat

logger = logging.getLogger("hackvortex.routes.scan")
router = APIRouter(prefix="/api", tags=["Scanner"])


@router.post("/scan", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def scan_url(payload: ScanRequest, db: Session = Depends(get_db)):
    """
    Analyzes a URL for malicious indicators, scores threat level (0-100),
    persists the scan record in the MySQL database, and returns analysis results.
    """
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL cannot be empty."
        )

    try:
        # Run heuristic analysis & feature extraction
        analysis = analyze_threat(raw_url)

        # Create SQLAlchemy ORM record
        scan_record = URLScan(
            url=analysis["url"],
            domain=analysis["domain"],
            risk_score=analysis["risk_score"],
            classification=analysis["classification"],
            detection_reasons=analysis["detection_reasons"],
            extracted_features=analysis["extracted_features"],
        )

        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)

        return ScanResponse(
            id=scan_record.id,
            url=scan_record.url,
            domain=scan_record.domain,
            risk_score=scan_record.risk_score,
            classification=scan_record.classification,
            detection_reasons=scan_record.detection_reasons,
            extracted_features=scan_record.extracted_features,
            created_at=scan_record.created_at,
        )

    except Exception as e:
        db.rollback()
        logger.error(f"Error scanning URL '{raw_url}': {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze URL: {str(e)}"
        )

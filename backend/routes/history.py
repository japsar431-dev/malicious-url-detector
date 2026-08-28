import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models import URLScan
from backend.schemas import ScanResponse

logger = logging.getLogger("hackvortex.routes.history")
router = APIRouter(prefix="/api", tags=["History"])


@router.get("/history", response_model=List[ScanResponse])
def get_scan_history(
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Records offset"),
    db: Session = Depends(get_db)
):
    """
    Retrieves previous scan results from the MySQL database,
    ordered by most recent scan first.
    """
    try:
        scans = (
            db.query(URLScan)
            .order_by(URLScan.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return scans

    except Exception as e:
        logger.error(f"Error retrieving scan history: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch scan history: {str(e)}"
        )

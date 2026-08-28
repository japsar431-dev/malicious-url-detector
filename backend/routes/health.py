from fastapi import APIRouter
from backend.database import check_db_connection
from backend.schemas import DBHealthResponse

router = APIRouter(prefix="/api/health", tags=["Health"])


@router.get("/db", response_model=DBHealthResponse)
def check_database_health():
    """
    Checks if the MySQL database is reachable and table schema exists.
    """
    health = check_db_connection()
    status_str = "healthy" if health["connected"] and health["table_exists"] else "degraded" if health["connected"] else "disconnected"

    return DBHealthResponse(
        status=status_str,
        connected=health["connected"],
        database=health["database"],
        host=health["host"],
        port=health["port"],
        user=health["user"],
        table_exists=health["table_exists"],
        message=health["message"]
    )

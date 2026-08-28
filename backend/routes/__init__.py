"""
HackVortex API Routes
"""
from backend.routes.scan import router as scan_router
from backend.routes.history import router as history_router
from backend.routes.analytics import router as analytics_router
from backend.routes.health import router as health_router

__all__ = ["scan_router", "history_router", "analytics_router", "health_router"]

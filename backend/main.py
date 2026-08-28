import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from backend.config import BASE_DIR, CORS_ORIGINS, DEBUG
from backend.database import init_db
from backend.routes.scan import router as scan_router
from backend.routes.history import router as history_router
from backend.routes.analytics import router as analytics_router
from backend.routes.health import router as health_router

# Setup logging
logging.basicConfig(
    level=logging.INFO if DEBUG else logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("hackvortex.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    Initializes database tables on server startup.
    """
    logger.info("Initializing HackVortex backend...")
    init_db()
    yield
    logger.info("Shutting down HackVortex backend...")


# Initialize FastAPI app
app = FastAPI(
    title="HackVortex Malicious URL Detector API",
    description="Heuristic Threat Analysis Engine and URL Security API powered by FastAPI and MySQL.",
    version="1.0.0",
    lifespan=lifespan,
)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if "*" not in CORS_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(scan_router)
app.include_router(history_router)
app.include_router(analytics_router)
app.include_router(health_router)


# Serve Static Frontend Files from root directory
@app.get("/", include_in_schema=False)
async def serve_index():
    index_path = BASE_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"message": "HackVortex API is active. Navigate to /docs for API documentation."}


@app.get("/history.html", include_in_schema=False)
async def serve_history():
    return FileResponse(BASE_DIR / "history.html")


@app.get("/analytics.html", include_in_schema=False)
async def serve_analytics():
    return FileResponse(BASE_DIR / "analytics.html")


@app.get("/login.html", include_in_schema=False)
async def serve_login():
    return FileResponse(BASE_DIR / "login.html")


@app.get("/landing.html", include_in_schema=False)
async def serve_landing():
    return FileResponse(BASE_DIR / "landing.html")


# Mount static assets (CSS, JS, images)
app.mount("/static", StaticFiles(directory=str(BASE_DIR)), name="static")

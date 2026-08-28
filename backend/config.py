import os
from pathlib import Path
from dotenv import load_dotenv
from sqlalchemy.engine import URL
# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env file from project rootpython -c "from backend.configuration
load_dotenv(dotenv_path=BASE_DIR / ".env")

# Database configuration
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "malicious_url_detector")

# Constructed MySQL SQLAlchemy connection string
DATABASE_URL = URL.create(
    drivername="mysql+pymysql",
    username=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=DB_PORT,
    database=DB_NAME,
    query={"charset": "utf8mb4"},
)

# Root MySQL connection string (without database name) for automatic database creation
ROOT_DATABASE_URL = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/?charset=utf8mb4"
)

# Server configuration
SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8000"))
DEBUG = os.getenv("DEBUG", "True").lower() in ("true", "1", "t")

# CORS configuration
CORS_ORIGINS_RAW = os.getenv("CORS_ORIGINS", "*")
CORS_ORIGINS = [origin.strip() for origin in CORS_ORIGINS_RAW.split(",") if origin.strip()]

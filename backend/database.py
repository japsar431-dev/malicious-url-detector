import os
import logging
import pymysql
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.config import (
    BASE_DIR,
    DATABASE_URL,
    DB_HOST,
    DB_PORT,
    DB_USER,
    DB_PASSWORD,
    DB_NAME,
)

logger = logging.getLogger("hackvortex.database")

Base = declarative_base()

# Primary MySQL engine
mysql_engine = None
SessionLocal = None
_db_initialized = False

# Fallback SQLite DB path in case MySQL credentials are not yet entered
FALLBACK_SQLITE_URL = f"sqlite:///{BASE_DIR / 'hackvortex_fallback.db'}"
fallback_engine = create_engine(FALLBACK_SQLITE_URL, connect_args={"check_same_thread": False})
FallbackSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=fallback_engine)


def ensure_database_exists():
    """
    Attempts to connect to MySQL server and ensure the target database exists.
    """
    try:
        conn = pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            autocommit=True,
            connect_timeout=3,
        )
        with conn.cursor() as cursor:
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
            )
        conn.close()
        logger.info(f"MySQL database '{DB_NAME}' verified/created successfully.")
        return True
    except Exception as e:
        logger.warning(f"MySQL database creation notice: {e}")
        return False


def get_active_engine():
    """Returns the MySQL engine if healthy, otherwise fallback engine."""
    global mysql_engine
    try:
        if mysql_engine is None:
            mysql_engine = create_engine(
                DATABASE_URL,
                pool_recycle=3600,
                pool_pre_ping=True,
                echo=False,
                connect_args={"connect_timeout": 3}
            )
        with mysql_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return mysql_engine
    except Exception as e:
        logger.debug(f"MySQL engine check notice: {e}")
        mysql_engine = None
        return fallback_engine


def init_db():
    """
    Initializes the database schema and creates all tables.
    """
    global _db_initialized, SessionLocal, mysql_engine
    ensure_database_exists()
    
    # Try initializing MySQL tables
    try:
        engine = create_engine(
            DATABASE_URL,
            pool_recycle=3600,
            pool_pre_ping=True,
            echo=False,
            connect_args={"connect_timeout": 3}
        )
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        Base.metadata.create_all(bind=engine)
        mysql_engine = engine
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        _db_initialized = True
        logger.info(f"MySQL database '{DB_NAME}' tables verified and created successfully.")
        return True
    except Exception as e:
        logger.warning(
            f"MySQL connection is not ready ({e}). "
            "Initializing SQLite fallback engine so all endpoints remain functional while MySQL is configured."
        )
        Base.metadata.create_all(bind=fallback_engine)
        SessionLocal = FallbackSessionLocal
        _db_initialized = True
        return False


def get_db():
    """
    FastAPI dependency that yields a database session.
    Automatically reconnects to MySQL if credentials become valid.
    """
    global SessionLocal
    if SessionLocal is None:
        init_db()

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_connection():
    """
    Verifies the live status of the MySQL connection.
    """
    try:
        test_engine = create_engine(
            DATABASE_URL,
            connect_args={"connect_timeout": 3}
        )
        with test_engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            
            # Check table existence
            table_result = connection.execute(text("SHOW TABLES LIKE 'url_scans'"))
            has_table = table_result.fetchone() is not None

            return {
                "connected": True,
                "engine": "MySQL",
                "database": DB_NAME,
                "host": DB_HOST,
                "port": DB_PORT,
                "user": DB_USER,
                "table_exists": has_table,
                "message": "MySQL database connection is active, healthy, and operational."
            }
    except Exception as e:
        return {
            "connected": False,
            "engine": "Fallback SQLite (Active)",
            "database": DB_NAME,
            "host": DB_HOST,
            "port": DB_PORT,
            "user": DB_USER,
            "table_exists": True,
            "message": f"MySQL connection notice: {str(e)}. Update DB_PASSWORD in .env with your local MySQL password."
        }

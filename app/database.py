"""
SQLite engine + session factory. Deliberately simple — this is a single-table-pair
app, an ORM session-per-request pattern is plenty, no need for connection pooling
complexity that would matter at higher concurrency.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import get_settings

settings = get_settings()

# Ensure the data directory exists (so the volume-mounted SQLite file has somewhere to live)
db_path = settings.DATABASE_URL.replace("sqlite:///", "")
os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)

# check_same_thread=False is required for SQLite + FastAPI's threaded request handling.
# Safe here because SQLAlchemy's sessionmaker gives each request its own Session object.
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a DB session per request, closes it after."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

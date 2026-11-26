"""PostgreSQL database connection and SQLAlchemy 2.0 session management for Q-Shields."""

from __future__ import annotations

import os
from collections.abc import Generator

from sqlalchemy import MetaData, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# Explicit constraint naming convention for predictable Alembic migrations
POSTGRES_NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base declarative class for all Q-Shields SQLAlchemy ORM models."""

    metadata = MetaData(naming_convention=POSTGRES_NAMING_CONVENTION)


def get_database_url() -> str:
    """Resolve the PostgreSQL SQLAlchemy URL from DATABASE_URL or POSTGRES_* env vars."""
    url = os.getenv("DATABASE_URL")
    if not url:
        pg_user = os.getenv("POSTGRES_USER", "qshields")
        pg_password = os.getenv("POSTGRES_PASSWORD", "qshields")
        pg_host = os.getenv("POSTGRES_HOST", "postgres")
        pg_port = os.getenv("POSTGRES_PORT", "5432")
        pg_db = os.getenv("POSTGRES_DB", "qshields")
        return f"postgresql+psycopg2://{pg_user}:{pg_password}@{pg_host}:{pg_port}/{pg_db}"

    # Normalize postgres:// or plain postgresql:// URLs to psycopg2-binary driver
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg2://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg2://", 1)
    return url


DATABASE_URL: str = get_database_url()

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
    max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
    echo=os.getenv("SQL_ECHO", "false").lower() == "true",
)

SessionLocal = sessionmaker(
    bind=engine,
    class_=Session,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a scoped SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables registered on Base.metadata (useful for dev/bootstrap)."""
    # Ensure all ORM models are imported before creating tables
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)

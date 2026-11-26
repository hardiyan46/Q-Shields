"""Minimal FastAPI entrypoint for Q-Shields Phase 1."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .database import get_db, init_db


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Initialize PostgreSQL tables on startup via SQLAlchemy Base.metadata.create_all."""
    init_db()
    yield


app = FastAPI(
    title="Q-Shields API",
    description="Internal Vulnerability Assessment, Compliance & AI-Assisted Remediation Platform",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health", tags=["Health"])
def health_check(db: Session = Depends(get_db)) -> dict[str, str]:
    """Verify API availability and live PostgreSQL database connectivity."""
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"PostgreSQL connection failed: {exc.__class__.__name__}",
        ) from exc

    return {
        "status": "ok",
        "database": "connected",
        "environment": os.getenv("APP_ENV", "development"),
    }

"""FastAPI application entrypoint for Q-Shields Phase 1."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .database import SessionLocal, get_db, init_db
from .routers import assets, auth, findings, remediations, users
from .services.seed_admin import seed_initial_admin


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Initialize PostgreSQL tables and seed initial local ADMIN user on startup."""
    init_db()
    with SessionLocal() as db:
        seed_initial_admin(db)
    yield


app = FastAPI(
    title="Q-Shields API",
    description="Internal Vulnerability Assessment, Compliance & AI-Assisted Remediation Platform",
    version="0.1.0",
    lifespan=lifespan,
)

# Configure CORS so Next.js frontend (http://localhost:3000) can call the API during development
raw_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
allowed_origins = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(assets.router)
app.include_router(findings.router)
app.include_router(remediations.router)


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

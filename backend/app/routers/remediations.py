"""API routes for AI-assisted remediation generation (LangGraph + Ollama) and job queries."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.security import get_current_user, require_roles
from ..database import get_db
from ..models import JobStatus, OSFamily, RemediationJob, User, UserRole
from ..schemas import RemediationJobOut
from ..services.remediation_graph import (
    FindingNotFoundError,
    OllamaServiceError,
    run_remediation_generation,
)

router = APIRouter(prefix="/api", tags=["Remediations"])


@router.post(
    "/findings/{finding_id}/generate-remediation",
    response_model=RemediationJobOut,
    status_code=status.HTTP_201_CREATED,
)
def generate_remediation_for_finding(
    finding_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_roles([UserRole.OPERATOR, UserRole.ADMIN])),
    db: Session = Depends(get_db),
) -> RemediationJobOut:
    """Run LangGraph + local Ollama workflow to generate a PENDING_APPROVAL remediation job."""
    try:
        job = run_remediation_generation(
            db,
            finding_id=finding_id,
            requested_by=current_user,
            client_ip=request.client.host if request.client else None,
        )
    except FindingNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except OllamaServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    return RemediationJobOut.model_validate(job)


@router.get("/remediations", response_model=list[RemediationJobOut])
def list_remediations(
    job_status: JobStatus | None = Query(default=None, alias="status"),
    target_os: OSFamily | None = Query(default=None, description="Filter by linux, windows, or macos"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[RemediationJobOut]:
    """List remediation jobs with optional status and target_os filters."""
    stmt = select(RemediationJob)
    if job_status is not None:
        stmt = stmt.where(RemediationJob.status == job_status)
    if target_os is not None:
        stmt = stmt.where(RemediationJob.target_os == target_os)

    stmt = stmt.order_by(RemediationJob.created_at.desc()).offset(skip).limit(limit)
    jobs = db.scalars(stmt).all()
    return [RemediationJobOut.model_validate(j) for j in jobs]


@router.get("/remediations/{job_id}", response_model=RemediationJobOut)
def get_remediation_detail(
    job_id: uuid.UUID,
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RemediationJobOut:
    """Get complete details for a single remediation job including scripts and pre-backup status."""
    job = db.scalar(select(RemediationJob).where(RemediationJob.id == job_id))
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation job {job_id} not found",
        )
    return RemediationJobOut.model_validate(job)

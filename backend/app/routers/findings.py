"""API routes for querying CVE and SCA_CIS findings across endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from ..core.security import get_current_user
from ..database import get_db
from ..models import (
    Endpoint,
    Finding,
    FindingSource,
    FindingStatus,
    OSFamily,
    SeverityLevel,
    User,
)
from ..schemas import EndpointBriefOut, FindingDetailOut, FindingOut

router = APIRouter(prefix="/api", tags=["Findings"])


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    endpoint_id: uuid.UUID | None = Query(default=None),
    os_family: OSFamily | None = Query(default=None, description="Filter by linux, windows, or macos"),
    source_type: FindingSource | None = Query(default=None),
    severity: SeverityLevel | None = Query(default=None),
    finding_status: FindingStatus | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None, description="Search by external ID, title, or description"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[FindingOut]:
    """List CVE and SCA_CIS findings with multi-criteria filtering and pagination."""
    stmt = select(Finding)

    if os_family is not None:
        stmt = stmt.join(Endpoint, Finding.endpoint_id == Endpoint.id).where(
            Endpoint.os_family == os_family
        )
    if endpoint_id is not None:
        stmt = stmt.where(Finding.endpoint_id == endpoint_id)
    if source_type is not None:
        stmt = stmt.where(Finding.source_type == source_type)
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity)
    if finding_status is not None:
        stmt = stmt.where(Finding.status == finding_status)
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Finding.external_id.ilike(pattern),
                Finding.title.ilike(pattern),
                Finding.description.ilike(pattern),
            )
        )

    stmt = stmt.order_by(Finding.detected_at.desc()).offset(skip).limit(limit)
    findings = db.scalars(stmt).all()
    return [FindingOut.model_validate(f) for f in findings]


@router.get("/findings/{finding_id}", response_model=FindingDetailOut)
def get_finding_detail(
    finding_id: uuid.UUID,
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FindingDetailOut:
    """Get complete details for a single finding along with its target endpoint."""
    finding = db.scalar(
        select(Finding)
        .options(selectinload(Finding.endpoint))
        .where(Finding.id == finding_id)
    )
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found",
        )

    base = FindingOut.model_validate(finding)
    return FindingDetailOut(
        **base.model_dump(),
        endpoint=EndpointBriefOut.model_validate(finding.endpoint),
    )

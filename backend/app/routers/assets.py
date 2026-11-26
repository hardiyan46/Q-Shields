"""API routes for Wazuh sync, endpoint inventory, and dashboard summary."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from ..core.security import get_current_user
from ..database import get_db
from ..models import (
    Endpoint,
    EndpointStatus,
    Finding,
    FindingStatus,
    OSFamily,
    SeverityLevel,
    User,
)
from ..schemas import (
    DashboardSummaryOut,
    EndpointDetailOut,
    EndpointOut,
    FindingOut,
    SeveritySummary,
    SyncResultOut,
)
from ..services.audit import record_audit_log
from ..services.wazuh_sync import WazuhLiveSyncNotImplementedError, sync_wazuh_data

router = APIRouter(prefix="/api", tags=["Assets & Sync"])


@router.post("/sync/wazuh", response_model=SyncResultOut)
def trigger_wazuh_sync(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SyncResultOut:
    """Trigger idempotent Wazuh synchronization (mock or live) into PostgreSQL."""
    try:
        result = sync_wazuh_data(db)
    except WazuhLiveSyncNotImplementedError as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=str(exc),
        ) from exc

    record_audit_log(
        db,
        action="SYNC_WAZUH",
        resource_type="wazuh_sync",
        actor_user=current_user,
        ip_address=request.client.host if request.client else None,
        details={
            "mode": result.mode,
            "endpoints_synced": result.endpoints_synced,
            "findings_synced": result.findings_synced,
        },
        commit=True,
    )
    return result


@router.get("/endpoints", response_model=list[EndpointOut])
def list_endpoints(
    os_family: OSFamily | None = Query(default=None, description="Filter by linux, windows, or macos"),
    endpoint_status: EndpointStatus | None = Query(
        default=None,
        alias="status",
        description="Filter by endpoint connection status",
    ),
    search: str | None = Query(default=None, description="Search by hostname, agent ID, or IP"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[EndpointOut]:
    """List managed endpoints with filters, pagination, and OPEN finding counts."""
    open_count_subq = (
        select(
            Finding.endpoint_id,
            func.count(Finding.id).label("open_count"),
        )
        .where(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.endpoint_id)
        .subquery()
    )

    stmt = select(
        Endpoint,
        func.coalesce(open_count_subq.c.open_count, 0).label("open_findings_count"),
    ).outerjoin(open_count_subq, Endpoint.id == open_count_subq.c.endpoint_id)

    if os_family is not None:
        stmt = stmt.where(Endpoint.os_family == os_family)
    if endpoint_status is not None:
        stmt = stmt.where(Endpoint.status == endpoint_status)
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Endpoint.hostname.ilike(pattern),
                Endpoint.wazuh_agent_id.ilike(pattern),
                Endpoint.ip_address.ilike(pattern),
            )
        )

    stmt = stmt.order_by(Endpoint.hostname.asc()).offset(skip).limit(limit)
    rows = db.execute(stmt).all()

    results: list[EndpointOut] = []
    for ep, open_count in rows:
        ep_out = EndpointOut.model_validate(ep)
        ep_out.open_findings_count = int(open_count)
        results.append(ep_out)
    return results


@router.get("/endpoints/{endpoint_id}", response_model=EndpointDetailOut)
def get_endpoint_detail(
    endpoint_id: uuid.UUID,
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> EndpointDetailOut:
    """Get a single endpoint with its severity summary and findings list."""
    endpoint = db.scalar(
        select(Endpoint)
        .options(selectinload(Endpoint.findings))
        .where(Endpoint.id == endpoint_id)
    )
    if endpoint is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Endpoint {endpoint_id} not found",
        )

    severity_counts = {
        SeverityLevel.CRITICAL.value: 0,
        SeverityLevel.HIGH.value: 0,
        SeverityLevel.MEDIUM.value: 0,
        SeverityLevel.LOW.value: 0,
    }
    for finding in endpoint.findings:
        if finding.status == FindingStatus.OPEN:
            severity_counts[finding.severity.value] += 1

    total_open = sum(severity_counts.values())
    summary = SeveritySummary(
        CRITICAL=severity_counts[SeverityLevel.CRITICAL.value],
        HIGH=severity_counts[SeverityLevel.HIGH.value],
        MEDIUM=severity_counts[SeverityLevel.MEDIUM.value],
        LOW=severity_counts[SeverityLevel.LOW.value],
        total_open=total_open,
    )

    sorted_findings = sorted(
        endpoint.findings,
        key=lambda f: f.detected_at,
        reverse=True,
    )

    base = EndpointOut.model_validate(endpoint)
    return EndpointDetailOut(
        **base.model_dump(exclude={"open_findings_count"}),
        open_findings_count=total_open,
        findings_summary=summary,
        findings=[FindingOut.model_validate(f) for f in sorted_findings],
    )


@router.get("/dashboard/summary", response_model=DashboardSummaryOut)
def get_dashboard_summary(
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DashboardSummaryOut:
    """Return aggregated multi-OS endpoint, open finding severity, and compliance metrics."""
    endpoints_by_os: dict[str, int] = {os_item.value: 0 for os_item in OSFamily}
    os_rows = db.execute(
        select(Endpoint.os_family, func.count(Endpoint.id)).group_by(Endpoint.os_family)
    ).all()
    for os_fam, count in os_rows:
        endpoints_by_os[os_fam.value] = int(count)

    total_endpoints = sum(endpoints_by_os.values())

    open_findings_by_severity: dict[str, int] = {sev.value: 0 for sev in SeverityLevel}
    sev_rows = db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.severity)
    ).all()
    for sev, count in sev_rows:
        open_findings_by_severity[sev.value] = int(count)

    open_findings_total = sum(open_findings_by_severity.values())

    avg_score = db.scalar(
        select(func.avg(Endpoint.compliance_score)).where(Endpoint.compliance_score.is_not(None))
    )
    average_compliance_score = round(float(avg_score), 2) if avg_score is not None else None

    return DashboardSummaryOut(
        total_endpoints=total_endpoints,
        endpoints_by_os=endpoints_by_os,
        open_findings_total=open_findings_total,
        open_findings_by_severity=open_findings_by_severity,
        average_compliance_score=average_compliance_score,
    )

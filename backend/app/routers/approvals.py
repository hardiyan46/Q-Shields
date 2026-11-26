"""API routes for Human-in-the-Loop Approval Queue, Execution, and Rollback."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..core.security import get_current_user, require_roles
from ..database import get_db
from ..models import (
    ExecutionLog,
    Finding,
    FindingStatus,
    JobStatus,
    RemediationJob,
    User,
    UserRole,
)
from ..schemas import (
    ApproveJobRequest,
    ExecutionLogOut,
    RejectJobRequest,
    RemediationJobDetailOut,
)
from ..services.audit import record_audit_log
from ..services.executor import (
    ExecutionGuardError,
    WazuhLiveExecutionNotImplementedError,
    execute_remediation_job,
    rollback_remediation_job,
)

router = APIRouter(prefix="/api", tags=["Approvals & Execution"])


def _load_job_detail(db: Session, job_id: uuid.UUID) -> RemediationJob:
    job = db.scalar(
        select(RemediationJob)
        .options(
            selectinload(RemediationJob.endpoint),
            selectinload(RemediationJob.finding),
            selectinload(RemediationJob.execution_logs),
        )
        .where(RemediationJob.id == job_id)
    )
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation job {job_id} not found",
        )
    return job


@router.get("/approvals/queue", response_model=list[RemediationJobDetailOut])
def list_approval_queue(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    _reviewer: User = Depends(require_roles([UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
) -> list[RemediationJobDetailOut]:
    """List PENDING_APPROVAL remediation jobs newest-first with endpoint & finding details."""
    stmt = (
        select(RemediationJob)
        .options(
            selectinload(RemediationJob.endpoint),
            selectinload(RemediationJob.finding),
            selectinload(RemediationJob.execution_logs),
        )
        .where(RemediationJob.status == JobStatus.PENDING_APPROVAL)
        .order_by(RemediationJob.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    jobs = db.scalars(stmt).all()
    return [RemediationJobDetailOut.model_validate(job) for job in jobs]


@router.post("/remediations/{job_id}/approve", response_model=RemediationJobDetailOut)
def approve_remediation_job(
    job_id: uuid.UUID,
    request: Request,
    payload: ApproveJobRequest = Body(default_factory=ApproveJobRequest),
    reviewer: User = Depends(require_roles([UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
) -> RemediationJobDetailOut:
    """Approve a PENDING_APPROVAL job (requires verified pre-backup & AUTO_SAFE) and optionally execute."""
    job = _load_job_detail(db, job_id)

    if job.status != JobStatus.PENDING_APPROVAL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Job cannot be approved because current status is '{job.status.value}' (must be PENDING_APPROVAL).",
        )
    if job.has_pre_backup is not True or not (job.backup_path or "").strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Approval locked: pre-change backup is not verified (has_pre_backup=False).",
        )
    if job.requires_manual_mdm is True:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Approval locked: finding requires manual or MDM intervention (requires_manual_mdm=True).",
        )

    now = datetime.now(timezone.utc)
    job.status = JobStatus.APPROVED
    job.approved_by_id = reviewer.id
    job.approved_at = now

    client_ip = request.client.host if request.client else None
    record_audit_log(
        db,
        action="APPROVE_REMEDIATION_JOB",
        resource_type="remediation_job",
        resource_id=str(job.id),
        actor_user=reviewer,
        ip_address=client_ip,
        details={"execute_immediately": payload.execute_immediately},
    )
    db.commit()

    if payload.execute_immediately:
        try:
            execute_remediation_job(db, job, triggered_by=reviewer, client_ip=client_ip)
        except ExecutionGuardError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except WazuhLiveExecutionNotImplementedError as exc:
            raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc

    refreshed = _load_job_detail(db, job.id)
    return RemediationJobDetailOut.model_validate(refreshed)


@router.post("/remediations/{job_id}/reject", response_model=RemediationJobDetailOut)
def reject_remediation_job(
    job_id: uuid.UUID,
    payload: RejectJobRequest,
    request: Request,
    reviewer: User = Depends(require_roles([UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
) -> RemediationJobDetailOut:
    """Reject a PENDING_APPROVAL job with a mandatory reason and reopen its finding."""
    job = _load_job_detail(db, job_id)

    if job.status != JobStatus.PENDING_APPROVAL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Job cannot be rejected because current status is '{job.status.value}' (must be PENDING_APPROVAL).",
        )

    reason = payload.rejection_reason.strip()
    if len(reason) < 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="rejection_reason must be at least 5 non-whitespace characters.",
        )

    now = datetime.now(timezone.utc)
    job.status = JobStatus.REJECTED
    job.rejection_reason = reason
    job.approved_by_id = reviewer.id
    job.approved_at = now

    finding = db.scalar(select(Finding).where(Finding.id == job.finding_id))
    if finding is not None:
        finding.status = FindingStatus.OPEN

    record_audit_log(
        db,
        action="REJECT_REMEDIATION_JOB",
        resource_type="remediation_job",
        resource_id=str(job.id),
        actor_user=reviewer,
        ip_address=request.client.host if request.client else None,
        details={"rejection_reason": reason},
    )
    db.commit()

    refreshed = _load_job_detail(db, job.id)
    return RemediationJobDetailOut.model_validate(refreshed)


@router.post("/remediations/{job_id}/execute", response_model=RemediationJobDetailOut)
def execute_approved_job(
    job_id: uuid.UUID,
    request: Request,
    reviewer: User = Depends(require_roles([UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
) -> RemediationJobDetailOut:
    """Execute a pre-approved remediation job (status must be APPROVED)."""
    job = _load_job_detail(db, job_id)
    client_ip = request.client.host if request.client else None

    try:
        execute_remediation_job(db, job, triggered_by=reviewer, client_ip=client_ip)
    except ExecutionGuardError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except WazuhLiveExecutionNotImplementedError as exc:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc

    refreshed = _load_job_detail(db, job.id)
    return RemediationJobDetailOut.model_validate(refreshed)


@router.post("/remediations/{job_id}/rollback", response_model=RemediationJobDetailOut)
def rollback_executed_job(
    job_id: uuid.UUID,
    request: Request,
    reviewer: User = Depends(require_roles([UserRole.APPROVER, UserRole.ADMIN])),
    db: Session = Depends(get_db),
) -> RemediationJobDetailOut:
    """Rollback a SUCCESS or FAILED job using its pre-change backup_path."""
    job = _load_job_detail(db, job_id)
    client_ip = request.client.host if request.client else None

    try:
        rollback_remediation_job(db, job, triggered_by=reviewer, client_ip=client_ip)
    except ExecutionGuardError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except WazuhLiveExecutionNotImplementedError as exc:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc

    refreshed = _load_job_detail(db, job.id)
    return RemediationJobDetailOut.model_validate(refreshed)


@router.get("/remediations/{job_id}/logs", response_model=list[ExecutionLogOut])
def get_remediation_execution_logs(
    job_id: uuid.UUID,
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[ExecutionLogOut]:
    """Return chronological execution and rollback logs for a remediation job."""
    job = db.scalar(select(RemediationJob).where(RemediationJob.id == job_id))
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation job {job_id} not found",
        )

    logs = db.scalars(
        select(ExecutionLog)
        .where(ExecutionLog.job_id == job_id)
        .order_by(ExecutionLog.executed_at.asc())
    ).all()
    return [ExecutionLogOut.model_validate(entry) for entry in logs]

"""Controlled execution and rollback service for approved remediation jobs."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Endpoint,
    ExecutionActionType,
    ExecutionLog,
    Finding,
    FindingStatus,
    JobStatus,
    OSFamily,
    RemediationJob,
    User,
)
from .audit import record_audit_log


class ExecutionGuardError(ValueError):
    """Raised when a remediation or rollback violates mandatory safety guardrails."""


class WazuhLiveExecutionNotImplementedError(NotImplementedError):
    """Raised when WAZUH_USE_MOCK=false live Active Response is requested before Sprint 4."""


def _is_mock_enabled() -> bool:
    return os.getenv("WAZUH_USE_MOCK", "true").strip().lower() in {"1", "true", "yes", "on"}


def _build_mock_remediate_stdout(job: RemediationJob, endpoint: Endpoint | None) -> str:
    host = endpoint.hostname if endpoint else str(job.endpoint_id)
    targets = ", ".join(job.backup_targets) if job.backup_targets else "(snapshot)"
    if job.target_os == OSFamily.LINUX:
        return (
            f"[mock-wazuh][linux:{host}] Creating backup directory {job.backup_path}\n"
            f"[mock-wazuh][linux:{host}] Backed up targets ({targets}) with cp -a and sha256sum manifest\n"
            f"[mock-wazuh][linux:{host}] Applied bash remediation script (set -euo pipefail)\n"
            f"[mock-wazuh][linux:{host}] Post-change validation passed (exit=0)"
        )
    if job.target_os == OSFamily.WINDOWS:
        return (
            f"[mock-wazuh][windows:{host}] Running under NT AUTHORITY\\SYSTEM\n"
            f"[mock-wazuh][windows:{host}] Created backup directory {job.backup_path}\n"
            f"[mock-wazuh][windows:{host}] Exported targets ({targets}) + Get-FileHash SHA256\n"
            f"[mock-wazuh][windows:{host}] Applied PowerShell remediation and verified target state (exit=0)"
        )
    return (
        f"[mock-wazuh][macos:{host}] Created backup directory {job.backup_path}\n"
        f"[mock-wazuh][macos:{host}] Backed up BSD/plist targets ({targets}) with shasum -a 256\n"
        f"[mock-wazuh][macos:{host}] Applied BSD-safe shell remediation without violating SIP/TCC/MDM\n"
        f"[mock-wazuh][macos:{host}] Post-change validation passed (exit=0)"
    )


def _build_mock_rollback_stdout(job: RemediationJob, endpoint: Endpoint | None) -> str:
    host = endpoint.hostname if endpoint else str(job.endpoint_id)
    targets = ", ".join(job.backup_targets) if job.backup_targets else "(snapshot)"
    return (
        f"[mock-wazuh][{job.target_os.value}:{host}] Executing rollback_script from {job.backup_path}\n"
        f"[mock-wazuh][{job.target_os.value}:{host}] Verified checksums and restored targets: {targets}\n"
        f"[mock-wazuh][{job.target_os.value}:{host}] System restored to pre-change state (ROLLED_BACK)"
    )


def _dispatch_wazuh_active_response(
    *,
    endpoint: Endpoint,
    action_type: ExecutionActionType,
    script_body: str,
    job: RemediationJob,
) -> tuple[int, str, str]:
    """Placeholder for Sprint 4 live Wazuh Manager API (PUT /active-response)."""
    api_url = os.getenv("WAZUH_API_URL", "https://wazuh-manager:55000")
    raise WazuhLiveExecutionNotImplementedError(
        f"Live Wazuh Active Response ({action_type.value}) via {api_url}/active-response "
        f"for agent {endpoint.wazuh_agent_id} (job {job.id}) is scheduled for Sprint 4. "
        "Set WAZUH_USE_MOCK=true in .env to run simulated execution."
    )


def execute_remediation_job(
    db: Session,
    job: RemediationJob,
    triggered_by: User,
    client_ip: str | None = None,
) -> ExecutionLog:
    """Validate strict safety guardrails and execute an APPROVED remediation job."""
    # Guardrail 1: Hanya job berstatus APPROVED yang boleh dieksekusi
    if job.status != JobStatus.APPROVED:
        raise ExecutionGuardError(
            f"Execution denied: job status is '{job.status.value}', must be 'APPROVED'."
        )

    # Guardrail 2: Wajib memiliki pre-change backup dan backup_path valid
    if job.has_pre_backup is not True or not (job.backup_path or "").strip():
        raise ExecutionGuardError(
            "Execution denied: job does not have a verified pre-change backup (has_pre_backup=True)."
        )

    # Guardrail 3: Dilarang eksekusi otomatis jika diblokir SIP/TCC/MDM macOS
    if job.requires_manual_mdm is True:
        raise ExecutionGuardError(
            "Execution denied: job requires manual or MDM intervention (requires_manual_mdm=True)."
        )

    endpoint = db.scalar(select(Endpoint).where(Endpoint.id == job.endpoint_id))
    finding = db.scalar(select(Finding).where(Finding.id == job.finding_id))

    job.status = JobStatus.EXECUTING
    db.flush()

    now = datetime.now(timezone.utc)
    if _is_mock_enabled():
        exit_code = 0
        stdout = _build_mock_remediate_stdout(job, endpoint)
        stderr = ""
    else:
        if endpoint is None:
            raise ExecutionGuardError(f"Target endpoint {job.endpoint_id} not found.")
        exit_code, stdout, stderr = _dispatch_wazuh_active_response(
            endpoint=endpoint,
            action_type=ExecutionActionType.REMEDIATE,
            script_body=job.remediation_script,
            job=job,
        )

    log_entry = ExecutionLog(
        job_id=job.id,
        action_type=ExecutionActionType.REMEDIATE,
        triggered_by_id=triggered_by.id,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        executed_at=now,
    )
    db.add(log_entry)

    if exit_code == 0:
        job.status = JobStatus.SUCCESS
        if finding is not None:
            finding.status = FindingStatus.RESOLVED
            finding.resolved_at = now
    else:
        job.status = JobStatus.FAILED

    record_audit_log(
        db,
        action="EXECUTE_REMEDIATION_JOB",
        resource_type="remediation_job",
        resource_id=str(job.id),
        status="SUCCESS" if exit_code == 0 else "FAILURE",
        actor_user=triggered_by,
        ip_address=client_ip,
        details={
            "target_os": job.target_os.value,
            "backup_path": job.backup_path,
            "exit_code": exit_code,
            "job_status": job.status.value,
        },
    )
    db.commit()
    db.refresh(job)
    db.refresh(log_entry)
    return log_entry


def rollback_remediation_job(
    db: Session,
    job: RemediationJob,
    triggered_by: User,
    client_ip: str | None = None,
) -> ExecutionLog:
    """Restore an endpoint from job.backup_path using the generated rollback_script."""
    if job.status not in {JobStatus.SUCCESS, JobStatus.FAILED}:
        raise ExecutionGuardError(
            f"Rollback denied: job status is '{job.status.value}', must be 'SUCCESS' or 'FAILED'."
        )

    if job.has_pre_backup is not True or not (job.backup_path or "").strip():
        raise ExecutionGuardError(
            "Rollback denied: job lacks a verified pre-change backup path."
        )

    endpoint = db.scalar(select(Endpoint).where(Endpoint.id == job.endpoint_id))
    finding = db.scalar(select(Finding).where(Finding.id == job.finding_id))
    now = datetime.now(timezone.utc)

    if _is_mock_enabled():
        exit_code = 0
        stdout = _build_mock_rollback_stdout(job, endpoint)
        stderr = ""
    else:
        if endpoint is None:
            raise ExecutionGuardError(f"Target endpoint {job.endpoint_id} not found.")
        exit_code, stdout, stderr = _dispatch_wazuh_active_response(
            endpoint=endpoint,
            action_type=ExecutionActionType.ROLLBACK,
            script_body=job.rollback_script,
            job=job,
        )

    log_entry = ExecutionLog(
        job_id=job.id,
        action_type=ExecutionActionType.ROLLBACK,
        triggered_by_id=triggered_by.id,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        executed_at=now,
    )
    db.add(log_entry)

    if exit_code == 0:
        job.status = JobStatus.ROLLED_BACK
        if finding is not None:
            finding.status = FindingStatus.OPEN
            finding.resolved_at = None

    record_audit_log(
        db,
        action="ROLLBACK_REMEDIATION_JOB",
        resource_type="remediation_job",
        resource_id=str(job.id),
        status="SUCCESS" if exit_code == 0 else "FAILURE",
        actor_user=triggered_by,
        ip_address=client_ip,
        details={
            "target_os": job.target_os.value,
            "backup_path": job.backup_path,
            "exit_code": exit_code,
            "job_status": job.status.value,
        },
    )
    db.commit()
    db.refresh(job)
    db.refresh(log_entry)
    return log_entry

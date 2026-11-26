"""Pydantic v2 response schemas for Q-Shields assets, findings, sync, and dashboard."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .models import (
    EndpointStatus,
    FindingSource,
    FindingStatus,
    IsolationStatus,
    OSFamily,
    SeverityLevel,
)


class SeveritySummary(BaseModel):
    """Breakdown of OPEN findings by severity level."""

    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    total_open: int = 0


class EndpointBriefOut(BaseModel):
    """Lightweight endpoint metadata embedded inside finding detail responses."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    wazuh_agent_id: str
    hostname: str
    ip_address: str | None = None
    os_family: OSFamily
    os_name: str
    os_version: str
    status: EndpointStatus


class FindingOut(BaseModel):
    """Serialized CVE or SCA_CIS finding record."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    endpoint_id: uuid.UUID
    source_type: FindingSource
    external_id: str
    title: str
    description: str
    severity: SeverityLevel
    status: FindingStatus
    remediation_hint: str | None = None
    raw_payload: dict[str, Any] | None = None
    detected_at: datetime
    resolved_at: datetime | None = None


class FindingDetailOut(FindingOut):
    """Detailed finding view including target endpoint information."""

    endpoint: EndpointBriefOut


class EndpointOut(BaseModel):
    """Endpoint inventory record with count of currently OPEN findings."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    wazuh_agent_id: str
    hostname: str
    ip_address: str | None = None
    os_family: OSFamily
    os_name: str
    os_version: str
    architecture: str | None = None
    agent_version: str | None = None
    status: EndpointStatus
    compliance_score: float | None = None
    isolation_status: IsolationStatus
    last_seen_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    open_findings_count: int = 0


class EndpointDetailOut(EndpointOut):
    """Detailed endpoint view including severity breakdown and its findings list."""

    findings_summary: SeveritySummary = Field(default_factory=SeveritySummary)
    findings: list[FindingOut] = Field(default_factory=list)


class SyncResultOut(BaseModel):
    """Summary returned after a Wazuh mock or live synchronization run."""

    mode: str
    endpoints_synced: int
    endpoints_created: int
    endpoints_updated: int
    findings_synced: int
    findings_created: int
    findings_updated: int
    synced_at: datetime


class DashboardSummaryOut(BaseModel):
    """Aggregated security posture metrics for the Q-Shields dashboard cards."""

    total_endpoints: int
    endpoints_by_os: dict[str, int]
    open_findings_total: int
    open_findings_by_severity: dict[str, int]
    average_compliance_score: float | None = None

"""Pydantic v2 schemas for Q-Shields auth, users, LDAP settings, assets, findings, and sync."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .models import (
    AuthProvider,
    EndpointStatus,
    FindingSource,
    FindingStatus,
    IsolationStatus,
    JobStatus,
    OSFamily,
    ScriptLanguage,
    SeverityLevel,
    UserRole,
)


# ==============================================================================
# AUTHENTICATION, USER MANAGEMENT & LDAP SETTINGS SCHEMAS
# ==============================================================================

AuthMode = Literal["AUTO", "LOCAL", "LDAP"]


class LoginRequest(BaseModel):
    """Hybrid login payload supporting AUTO, LOCAL, or LDAP mode."""

    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)
    auth_mode: AuthMode = "AUTO"


class UserOut(BaseModel):
    """Public user profile returned by API (never exposes password_hash)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: str | None = None
    full_name: str
    auth_provider: AuthProvider
    ldap_dn: str | None = None
    role: UserRole
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class TokenResponse(BaseModel):
    """JWT access token + authenticated user profile."""

    access_token: str
    token_type: str = "bearer"
    user: UserOut


class UserCreateLocal(BaseModel):
    """Payload for ADMIN creating a new LOCAL user account."""

    username: str = Field(min_length=2, max_length=100)
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=150)
    email: str | None = Field(default=None, max_length=255)
    role: UserRole = UserRole.OPERATOR
    is_active: bool = True


class UserUpdate(BaseModel):
    """Payload for ADMIN updating a user's RBAC role, active status, or profile."""

    role: UserRole | None = None
    is_active: bool | None = None
    full_name: str | None = Field(default=None, min_length=1, max_length=150)
    email: str | None = Field(default=None, max_length=255)


class LdapConfigOut(BaseModel):
    """LDAP configuration response with bind password masked."""

    id: uuid.UUID | None = None
    server_url: str
    bind_dn: str
    bind_password_masked: str | None = None
    has_bind_password: bool = False
    base_dn: str
    user_search_filter: str
    group_operator_dn: str | None = None
    group_approver_dn: str | None = None
    group_admin_dn: str | None = None
    is_enabled: bool
    source: Literal["database", "environment"] = "database"
    updated_at: datetime | None = None


class LdapConfigUpdate(BaseModel):
    """Payload for ADMIN updating Domain Controller / LDAP settings."""

    server_url: str = Field(min_length=1, max_length=255)
    bind_dn: str = Field(min_length=1)
    bind_password: str | None = Field(
        default=None,
        description="Leave null/empty to keep the existing stored bind password.",
    )
    base_dn: str = Field(min_length=1)
    user_search_filter: str = Field(default="(sAMAccountName={username})", min_length=1, max_length=255)
    group_operator_dn: str | None = None
    group_approver_dn: str | None = None
    group_admin_dn: str | None = None
    is_enabled: bool = False


# ==============================================================================
# ASSETS, FINDINGS, SYNC & DASHBOARD SCHEMAS
# ==============================================================================


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


# ==============================================================================
# AI REMEDIATION STRUCTURED OUTPUT & JOB SCHEMAS
# ==============================================================================


class RemediationDraftSchema(BaseModel):
    """Structured output contract returned by Ollama LLM via LangGraph."""

    remediation_script: str = Field(
        description="Complete OS-native script with pre-change backup, remediation, validation, and auto-revert."
    )
    rollback_script: str = Field(
        description="Standalone rollback script referencing the exact job backup_path to restore prior state."
    )
    ai_explanation: str = Field(
        description="Clear explanation of what the script changes, validates, and backs up (or why manual/MDM is required)."
    )
    risk_level: Literal["LOW", "MEDIUM", "HIGH"] = Field(
        description="Operational risk level of applying this remediation."
    )
    requires_reboot: bool = Field(
        description="Whether a system reboot is required after remediation."
    )
    requires_manual_mdm: bool = Field(
        description="True if macOS SIP, TCC, or MDM policy blocks safe automated CLI remediation."
    )
    backup_targets: list[str] = Field(
        default_factory=list,
        description="List of config files, registry keys, plists, or package snapshots backed up before changes.",
    )


class RemediationJobOut(BaseModel):
    """Serialized remediation job returned to Swagger UI and Next.js frontend."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    endpoint_id: uuid.UUID
    finding_id: uuid.UUID
    target_os: OSFamily
    script_language: ScriptLanguage
    remediation_script: str
    rollback_script: str
    ai_explanation: str
    risk_level: str
    requires_reboot: bool
    requires_manual_mdm: bool
    backup_path: str
    backup_targets: list[str]
    has_pre_backup: bool
    status: JobStatus
    linter_status: str
    linter_report: dict[str, Any] | None = None
    is_canary: bool
    requested_by_id: uuid.UUID
    approved_by_id: uuid.UUID | None = None
    rejection_reason: str | None = None
    created_at: datetime
    approved_at: datetime | None = None

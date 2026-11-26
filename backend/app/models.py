"""SQLAlchemy 2.0+ PostgreSQL ORM models for Q-Shields Phase 1 (multi-OS: linux, windows, macos)."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _enum_values(enum_cls: type[enum.Enum]) -> list[str]:
    """Persist enum string values (not member names) in PostgreSQL native ENUMs."""
    return [str(member.value) for member in enum_cls]


# ==============================================================================
# 1. STANDARD MULTI-OS, AUTH, RBAC & WORKFLOW ENUMS
# ==============================================================================


class OSFamily(str, enum.Enum):
    """Supported endpoint OS families across Wazuh, LangGraph, and backups."""

    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"


class ScriptLanguage(str, enum.Enum):
    """Target script dialect per OS family (zsh_bsd = macOS BSD-safe shell)."""

    BASH = "bash"
    POWERSHELL = "powershell"
    ZSH_BSD = "zsh_bsd"


class AuthProvider(str, enum.Enum):
    LOCAL = "LOCAL"
    LDAP = "LDAP"


class UserRole(str, enum.Enum):
    OPERATOR = "OPERATOR"
    APPROVER = "APPROVER"
    ADMIN = "ADMIN"


class EndpointStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    DISCONNECTED = "DISCONNECTED"
    PENDING = "PENDING"


class IsolationStatus(str, enum.Enum):
    """Phase 3 reserve: EDR host isolation state."""

    NORMAL = "NORMAL"
    ISOLATING = "ISOLATING"
    ISOLATED = "ISOLATED"


class FindingSource(str, enum.Enum):
    CVE = "CVE"
    SCA_CIS = "SCA_CIS"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    MANUAL_REQUIRED = "MANUAL_REQUIRED"


class JobStatus(str, enum.Enum):
    DRAFT = "DRAFT"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


class ExecutionActionType(str, enum.Enum):
    REMEDIATE = "REMEDIATE"
    ROLLBACK = "ROLLBACK"


# ==============================================================================
# 2. AUTHENTICATION, RBAC & LDAP CONFIGURATION MODELS
# ==============================================================================


class User(Base):
    """Local or Domain Controller (LDAP) user account with RBAC role."""

    __tablename__ = "users"
    __table_args__ = (
        # Ensure LDAP users never store password_hash and LOCAL users always have one
        CheckConstraint(
            "(auth_provider = 'LOCAL' AND password_hash IS NOT NULL) OR "
            "(auth_provider = 'LDAP' AND password_hash IS NULL)",
            name="local_password_hash_consistency",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    username: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        index=True,
        nullable=False,
    )
    email: Mapped[str | None] = mapped_column(
        String(255),
        unique=True,
        nullable=True,
    )
    full_name: Mapped[str] = mapped_column(String(150), nullable=False)
    auth_provider: Mapped[AuthProvider] = mapped_column(
        SAEnum(AuthProvider, name="auth_provider_enum", values_callable=_enum_values),
        nullable=False,
        default=AuthProvider.LOCAL,
        server_default=AuthProvider.LOCAL.value,
    )
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    ldap_dn: Mapped[str | None] = mapped_column(Text, nullable=True)
    role: Mapped[UserRole] = mapped_column(
        SAEnum(UserRole, name="user_role_enum", values_callable=_enum_values),
        nullable=False,
        default=UserRole.OPERATOR,
        server_default=UserRole.OPERATOR.value,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    requested_jobs: Mapped[list[RemediationJob]] = relationship(
        back_populates="requested_by",
        foreign_keys="RemediationJob.requested_by_id",
    )
    approved_jobs: Mapped[list[RemediationJob]] = relationship(
        back_populates="approved_by",
        foreign_keys="RemediationJob.approved_by_id",
    )
    triggered_executions: Mapped[list[ExecutionLog]] = relationship(
        back_populates="triggered_by",
        foreign_keys="ExecutionLog.triggered_by_id",
    )
    audit_logs: Mapped[list[AuditLog]] = relationship(
        back_populates="actor_user",
        foreign_keys="AuditLog.actor_user_id",
    )


class LdapConfig(Base):
    """Domain Controller / LDAP server & group-to-role mapping configuration."""

    __tablename__ = "ldap_configs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    server_url: Mapped[str] = mapped_column(String(255), nullable=False)
    bind_dn: Mapped[str] = mapped_column(Text, nullable=False)
    bind_password_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    base_dn: Mapped[str] = mapped_column(Text, nullable=False)
    user_search_filter: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="(sAMAccountName={username})",
        server_default="(sAMAccountName={username})",
    )
    group_operator_dn: Mapped[str | None] = mapped_column(Text, nullable=True)
    group_approver_dn: Mapped[str | None] = mapped_column(Text, nullable=True)
    group_admin_dn: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


# ==============================================================================
# 3. ENDPOINTS & FINDINGS (WAZUH INVENTORY)
# ==============================================================================


class Endpoint(Base):
    """Managed endpoint synced from Wazuh Manager (linux, windows, or macos)."""

    __tablename__ = "endpoints"
    __table_args__ = (
        Index("ix_endpoints_os_status", "os_family", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    wazuh_agent_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    os_family: Mapped[OSFamily] = mapped_column(
        SAEnum(OSFamily, name="os_family_enum", values_callable=_enum_values),
        nullable=False,
        index=True,
    )
    os_name: Mapped[str] = mapped_column(String(150), nullable=False)
    os_version: Mapped[str] = mapped_column(String(100), nullable=False)
    architecture: Mapped[str | None] = mapped_column(String(32), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    status: Mapped[EndpointStatus] = mapped_column(
        SAEnum(EndpointStatus, name="endpoint_status_enum", values_callable=_enum_values),
        nullable=False,
        default=EndpointStatus.PENDING,
        server_default=EndpointStatus.PENDING.value,
        index=True,
    )
    compliance_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Phase 3 reserve: EDR host network isolation state (Isolate / Unisolate Host)
    isolation_status: Mapped[IsolationStatus] = mapped_column(
        SAEnum(IsolationStatus, name="isolation_status_enum", values_callable=_enum_values),
        nullable=False,
        default=IsolationStatus.NORMAL,
        server_default=IsolationStatus.NORMAL.value,
    )

    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships
    findings: Mapped[list[Finding]] = relationship(
        back_populates="endpoint",
        cascade="all, delete-orphan",
    )
    remediation_jobs: Mapped[list[RemediationJob]] = relationship(
        back_populates="endpoint",
        cascade="all, delete-orphan",
    )


class Finding(Base):
    """Vulnerability (CVE) or CIS Benchmark / SCA compliance finding per endpoint."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "endpoint_id",
            "source_type",
            "external_id",
            name="uq_finding_endpoint_source_external",
        ),
        Index("ix_findings_endpoint_status", "endpoint_id", "status"),
        Index("ix_findings_severity_status", "severity", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("endpoints.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_type: Mapped[FindingSource] = mapped_column(
        SAEnum(FindingSource, name="finding_source_enum", values_callable=_enum_values),
        nullable=False,
        index=True,
    )
    external_id: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[SeverityLevel] = mapped_column(
        SAEnum(SeverityLevel, name="severity_level_enum", values_callable=_enum_values),
        nullable=False,
        index=True,
    )
    status: Mapped[FindingStatus] = mapped_column(
        SAEnum(FindingStatus, name="finding_status_enum", values_callable=_enum_values),
        nullable=False,
        default=FindingStatus.OPEN,
        server_default=FindingStatus.OPEN.value,
        index=True,
    )
    remediation_hint: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    endpoint: Mapped[Endpoint] = relationship(back_populates="findings")
    remediation_jobs: Mapped[list[RemediationJob]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
    )


# ==============================================================================
# 4. REMEDIATION JOBS, PRE-CHANGE BACKUP & EXECUTION LOGS
# ==============================================================================


class RemediationJob(Base):
    """AI-generated remediation & rollback job subject to pre-backup and approval."""

    __tablename__ = "remediation_jobs"
    __table_args__ = (
        Index("ix_remediation_jobs_status_pre_backup", "status", "has_pre_backup"),
        Index("ix_remediation_jobs_target_os_status", "target_os", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("endpoints.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_os: Mapped[OSFamily] = mapped_column(
        SAEnum(OSFamily, name="os_family_enum", values_callable=_enum_values),
        nullable=False,
        index=True,
    )
    script_language: Mapped[ScriptLanguage] = mapped_column(
        SAEnum(ScriptLanguage, name="script_language_enum", values_callable=_enum_values),
        nullable=False,
    )
    remediation_script: Mapped[str] = mapped_column(Text, nullable=False)
    rollback_script: Mapped[str] = mapped_column(Text, nullable=False)
    ai_explanation: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    requires_reboot: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    # Khusus pembatasan Apple SIP / TCC / MDM pada endpoint macOS
    requires_manual_mdm: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )

    # Pre-change backup wajib unik per job sesuai konvensi OS target
    backup_path: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    backup_targets: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    has_pre_backup: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
        index=True,
    )

    status: Mapped[JobStatus] = mapped_column(
        SAEnum(JobStatus, name="job_status_enum", values_callable=_enum_values),
        nullable=False,
        default=JobStatus.PENDING_APPROVAL,
        server_default=JobStatus.PENDING_APPROVAL.value,
        index=True,
    )

    # Phase 2 reserve: Static code analyzer (ShellCheck / PSScriptAnalyzer) sebelum approval
    linter_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="NOT_RUN",
        server_default="NOT_RUN",
    )
    # Phase 2 reserve: Laporan terstruktur hasil static analyzer (warnings/errors JSON)
    linter_report: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # Phase 2 reserve: Menandai job uji coba canary (1 PC) sebelum push massal
    is_canary: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )

    requested_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    approved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    endpoint: Mapped[Endpoint] = relationship(back_populates="remediation_jobs")
    finding: Mapped[Finding] = relationship(back_populates="remediation_jobs")
    requested_by: Mapped[User] = relationship(
        back_populates="requested_jobs",
        foreign_keys=[requested_by_id],
    )
    approved_by: Mapped[User | None] = relationship(
        back_populates="approved_jobs",
        foreign_keys=[approved_by_id],
    )
    execution_logs: Mapped[list[ExecutionLog]] = relationship(
        back_populates="job",
        cascade="all, delete-orphan",
        order_by="ExecutionLog.executed_at",
    )


class ExecutionLog(Base):
    """Execution output log for REMEDIATE and ROLLBACK runs per remediation job."""

    __tablename__ = "execution_logs"
    __table_args__ = (
        Index("ix_execution_logs_job_executed_at", "job_id", "executed_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action_type: Mapped[ExecutionActionType] = mapped_column(
        SAEnum(
            ExecutionActionType,
            name="execution_action_type_enum",
            values_callable=_enum_values,
        ),
        nullable=False,
    )
    triggered_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stdout: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    # Relationships
    job: Mapped[RemediationJob] = relationship(back_populates="execution_logs")
    triggered_by: Mapped[User] = relationship(
        back_populates="triggered_executions",
        foreign_keys=[triggered_by_id],
    )


# ==============================================================================
# 5. STRUCTURED RELATIONAL AUDIT LOG
# ==============================================================================


class AuditLog(Base):
    """Structured relational audit log stored in PostgreSQL (append-only)."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_actor_created", "actor_user_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    actor_username: Mapped[str] = mapped_column(String(100), nullable=False)
    actor_role: Mapped[str | None] = mapped_column(String(20), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="SUCCESS",
        server_default="SUCCESS",
    )
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    # Relationships
    actor_user: Mapped[User | None] = relationship(
        back_populates="audit_logs",
        foreign_keys=[actor_user_id],
    )

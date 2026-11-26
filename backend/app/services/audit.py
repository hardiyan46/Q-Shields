"""Relational PostgreSQL audit logging helper."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ..models import AuditLog, User


def record_audit_log(
    db: Session,
    *,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    status: str = "SUCCESS",
    actor_user: User | None = None,
    actor_username: str | None = None,
    actor_role: str | None = None,
    ip_address: str | None = None,
    details: dict[str, Any] | None = None,
    commit: bool = False,
) -> AuditLog:
    """Append an immutable audit log row to PostgreSQL."""
    resolved_username = actor_username or (actor_user.username if actor_user else "anonymous")
    resolved_role = actor_role or (actor_user.role.value if actor_user else None)

    entry = AuditLog(
        actor_user_id=actor_user.id if actor_user else None,
        actor_username=resolved_username,
        actor_role=resolved_role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        status=status,
        ip_address=ip_address,
        details=details or {},
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    return entry

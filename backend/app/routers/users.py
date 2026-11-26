"""ADMIN-only routes for User Management and Domain Controller / LDAP configuration."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.security import encrypt_secret, hash_password, require_admin
from ..database import get_db
from ..models import AuthProvider, LdapConfig, User, UserRole
from ..schemas import LdapConfigOut, LdapConfigUpdate, UserCreateLocal, UserOut, UserUpdate
from ..services.audit import record_audit_log
from ..services.ldap_auth import get_effective_ldap_config

router = APIRouter(prefix="/api", tags=["Users & LDAP Settings"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _mask_ldap_config(db: Session) -> LdapConfigOut:
    db_cfg = db.scalar(select(LdapConfig).limit(1))
    effective = get_effective_ldap_config(db)
    has_pw = bool(effective.bind_password)
    return LdapConfigOut(
        id=db_cfg.id if db_cfg else None,
        server_url=effective.server_url,
        bind_dn=effective.bind_dn,
        bind_password_masked="********" if has_pw else None,
        has_bind_password=has_pw,
        base_dn=effective.base_dn,
        user_search_filter=effective.user_search_filter,
        group_operator_dn=effective.group_operator_dn,
        group_approver_dn=effective.group_approver_dn,
        group_admin_dn=effective.group_admin_dn,
        is_enabled=effective.is_enabled,
        source="database" if db_cfg else "environment",
        updated_at=db_cfg.updated_at if db_cfg else None,
    )


@router.get("/users", response_model=list[UserOut])
def list_users(
    auth_provider: AuthProvider | None = Query(default=None),
    role: UserRole | None = Query(default=None),
    is_active: bool | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=200),
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> list[UserOut]:
    """List all LOCAL and LDAP users (ADMIN only)."""
    stmt = select(User)
    if auth_provider is not None:
        stmt = stmt.where(User.auth_provider == auth_provider)
    if role is not None:
        stmt = stmt.where(User.role == role)
    if is_active is not None:
        stmt = stmt.where(User.is_active == is_active)

    stmt = stmt.order_by(User.created_at.asc()).offset(skip).limit(limit)
    users = db.scalars(stmt).all()
    return [UserOut.model_validate(u) for u in users]


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_local_user(
    payload: UserCreateLocal,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> UserOut:
    """Create a new LOCAL user account with bcrypt-hashed password (ADMIN only)."""
    username = payload.username.strip()
    email = payload.email.strip() if payload.email else None

    if db.scalar(select(User).where(User.username == username)) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{username}' already exists",
        )
    if email and db.scalar(select(User).where(User.email == email)) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Email '{email}' is already in use",
        )

    new_user = User(
        username=username,
        email=email,
        full_name=payload.full_name.strip(),
        auth_provider=AuthProvider.LOCAL,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=payload.is_active,
    )
    db.add(new_user)
    db.flush()

    record_audit_log(
        db,
        action="CREATE_LOCAL_USER",
        resource_type="user",
        resource_id=str(new_user.id),
        actor_user=admin_user,
        ip_address=_client_ip(request),
        details={"username": new_user.username, "role": new_user.role.value},
    )
    db.commit()
    db.refresh(new_user)
    return UserOut.model_validate(new_user)


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> UserOut:
    """Update user RBAC role, active status, or profile metadata (ADMIN only)."""
    target_user = db.scalar(select(User).where(User.id == user_id))
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    # Prevent the active ADMIN from accidentally locking themselves out
    if target_user.id == admin_user.id:
        if payload.is_active is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot disable their own account",
            )
        if payload.role is not None and payload.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot downgrade their own ADMIN role",
            )

    if payload.email is not None:
        cleaned_email = payload.email.strip() or None
        if cleaned_email and cleaned_email != target_user.email:
            email_owner = db.scalar(
                select(User).where(User.email == cleaned_email, User.id != target_user.id)
            )
            if email_owner is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Email '{cleaned_email}' is already in use",
                )
        target_user.email = cleaned_email

    if payload.full_name is not None:
        target_user.full_name = payload.full_name.strip()
    if payload.role is not None:
        target_user.role = payload.role
    if payload.is_active is not None:
        target_user.is_active = payload.is_active

    record_audit_log(
        db,
        action="UPDATE_USER",
        resource_type="user",
        resource_id=str(target_user.id),
        actor_user=admin_user,
        ip_address=_client_ip(request),
        details={
            "target_username": target_user.username,
            "role": target_user.role.value,
            "is_active": target_user.is_active,
        },
    )
    db.commit()
    db.refresh(target_user)
    return UserOut.model_validate(target_user)


@router.get("/settings/ldap", response_model=LdapConfigOut)
def get_ldap_settings(
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> LdapConfigOut:
    """Retrieve effective Domain Controller / LDAP configuration with bind password masked."""
    return _mask_ldap_config(db)


@router.put("/settings/ldap", response_model=LdapConfigOut)
def update_ldap_settings(
    payload: LdapConfigUpdate,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> LdapConfigOut:
    """Create or update Domain Controller / LDAP configuration in PostgreSQL (ADMIN only)."""
    db_cfg = db.scalar(select(LdapConfig).limit(1))

    if db_cfg is None:
        if not payload.bind_password:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="bind_password is required when creating initial LDAP configuration",
            )
        db_cfg = LdapConfig(
            server_url=payload.server_url.strip(),
            bind_dn=payload.bind_dn.strip(),
            bind_password_encrypted=encrypt_secret(payload.bind_password),
            base_dn=payload.base_dn.strip(),
            user_search_filter=payload.user_search_filter.strip(),
            group_operator_dn=payload.group_operator_dn.strip() if payload.group_operator_dn else None,
            group_approver_dn=payload.group_approver_dn.strip() if payload.group_approver_dn else None,
            group_admin_dn=payload.group_admin_dn.strip() if payload.group_admin_dn else None,
            is_enabled=payload.is_enabled,
        )
        db.add(db_cfg)
    else:
        db_cfg.server_url = payload.server_url.strip()
        db_cfg.bind_dn = payload.bind_dn.strip()
        if payload.bind_password:
            db_cfg.bind_password_encrypted = encrypt_secret(payload.bind_password)
        db_cfg.base_dn = payload.base_dn.strip()
        db_cfg.user_search_filter = payload.user_search_filter.strip()
        db_cfg.group_operator_dn = (
            payload.group_operator_dn.strip() if payload.group_operator_dn else None
        )
        db_cfg.group_approver_dn = (
            payload.group_approver_dn.strip() if payload.group_approver_dn else None
        )
        db_cfg.group_admin_dn = (
            payload.group_admin_dn.strip() if payload.group_admin_dn else None
        )
        db_cfg.is_enabled = payload.is_enabled

    record_audit_log(
        db,
        action="UPDATE_LDAP_CONFIG",
        resource_type="ldap_config",
        resource_id=str(db_cfg.id) if db_cfg.id else "singleton",
        actor_user=admin_user,
        ip_address=_client_ip(request),
        details={
            "server_url": db_cfg.server_url,
            "base_dn": db_cfg.base_dn,
            "is_enabled": db_cfg.is_enabled,
        },
    )
    db.commit()
    return _mask_ldap_config(db)

"""Authentication API routes supporting hybrid LOCAL and Domain Controller / LDAP login."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.security import create_access_token, get_current_user, verify_password
from ..database import get_db
from ..models import AuthProvider, User
from ..schemas import LoginRequest, TokenResponse, UserOut
from ..services.audit import record_audit_log
from ..services.ldap_auth import (
    LdapAccountConflictError,
    LdapConnectionError,
    LdapDisabledError,
    LdapInvalidCredentialsError,
    authenticate_ldap_user,
    get_effective_ldap_config,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _authenticate_local(db: Session, username: str, password: str) -> User | None:
    """Verify a LOCAL user's password hash. Returns None if no LOCAL account exists."""
    user = db.scalar(
        select(User).where(
            User.username == username,
            User.auth_provider == AuthProvider.LOCAL,
        )
    )
    if user is None:
        return None
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )
    if not user.password_hash or not verify_password(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate via AUTO, LOCAL (PostgreSQL hash), or LDAP (ldap3) and return JWT."""
    username = payload.username.strip()
    ip_addr = _client_ip(request)
    user: User | None = None

    if payload.auth_mode == "LOCAL":
        try:
            user = _authenticate_local(db, username, payload.password)
        except HTTPException as exc:
            record_audit_log(
                db,
                action="LOGIN_LOCAL",
                resource_type="user",
                resource_id=username,
                status="FAILURE",
                actor_username=username,
                ip_address=ip_addr,
                details={"reason": exc.detail, "auth_mode": "LOCAL"},
                commit=True,
            )
            raise
        if user is None:
            record_audit_log(
                db,
                action="LOGIN_LOCAL",
                resource_type="user",
                resource_id=username,
                status="FAILURE",
                actor_username=username,
                ip_address=ip_addr,
                details={"reason": "Local user not found", "auth_mode": "LOCAL"},
                commit=True,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )

    elif payload.auth_mode == "LDAP":
        try:
            user = authenticate_ldap_user(db, username, payload.password)
        except LdapDisabledError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        except LdapConnectionError as exc:
            record_audit_log(
                db,
                action="LOGIN_LDAP",
                resource_type="user",
                resource_id=username,
                status="FAILURE",
                actor_username=username,
                ip_address=ip_addr,
                details={"reason": "LDAP connection failure", "auth_mode": "LDAP"},
                commit=True,
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc
        except LdapAccountConflictError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        except LdapInvalidCredentialsError as exc:
            record_audit_log(
                db,
                action="LOGIN_LDAP",
                resource_type="user",
                resource_id=username,
                status="FAILURE",
                actor_username=username,
                ip_address=ip_addr,
                details={"reason": str(exc), "auth_mode": "LDAP"},
                commit=True,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
            ) from exc

    else:  # AUTO
        try:
            user = _authenticate_local(db, username, payload.password)
        except HTTPException as exc:
            record_audit_log(
                db,
                action="LOGIN_LOCAL",
                resource_type="user",
                resource_id=username,
                status="FAILURE",
                actor_username=username,
                ip_address=ip_addr,
                details={"reason": exc.detail, "auth_mode": "AUTO"},
                commit=True,
            )
            raise

        if user is None:
            ldap_cfg = get_effective_ldap_config(db)
            if not ldap_cfg.is_enabled:
                record_audit_log(
                    db,
                    action="LOGIN_AUTO",
                    resource_type="user",
                    resource_id=username,
                    status="FAILURE",
                    actor_username=username,
                    ip_address=ip_addr,
                    details={"reason": "User not found locally and LDAP disabled"},
                    commit=True,
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username or password",
                )
            try:
                user = authenticate_ldap_user(db, username, payload.password)
            except LdapConnectionError as exc:
                record_audit_log(
                    db,
                    action="LOGIN_LDAP",
                    resource_type="user",
                    resource_id=username,
                    status="FAILURE",
                    actor_username=username,
                    ip_address=ip_addr,
                    details={"reason": "LDAP connection failure", "auth_mode": "AUTO"},
                    commit=True,
                )
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=str(exc),
                ) from exc
            except (LdapInvalidCredentialsError, LdapDisabledError, LdapAccountConflictError) as exc:
                record_audit_log(
                    db,
                    action="LOGIN_LDAP",
                    resource_type="user",
                    resource_id=username,
                    status="FAILURE",
                    actor_username=username,
                    ip_address=ip_addr,
                    details={"reason": str(exc), "auth_mode": "AUTO"},
                    commit=True,
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username or password",
                ) from exc

    action_name = "LOGIN_LDAP" if user.auth_provider == AuthProvider.LDAP else "LOGIN_LOCAL"
    record_audit_log(
        db,
        action=action_name,
        resource_type="user",
        resource_id=str(user.id),
        status="SUCCESS",
        actor_user=user,
        ip_address=ip_addr,
        details={"auth_provider": user.auth_provider.value, "role": user.role.value},
        commit=True,
    )

    access_token = create_access_token(user)
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserOut.model_validate(user),
    )


@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)) -> UserOut:
    """Return the authenticated user's profile and RBAC role."""
    return UserOut.model_validate(current_user)

"""Authentication, password hashing, secret encryption, JWT, and RBAC dependencies."""

from __future__ import annotations

import base64
import hashlib
import os
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, UserRole

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


def _get_secret_key() -> str:
    return os.getenv("SECRET_KEY", "dev-insecure-qshields-secret-change-me")


def _get_jwt_algorithm() -> str:
    return os.getenv("JWT_ALGORITHM", "HS256")


def _get_token_expire_minutes() -> int:
    try:
        return int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))
    except ValueError:
        return 480


def _get_fernet() -> Fernet:
    """Derive a deterministic Fernet key from SECRET_KEY for encrypting LDAP bind credentials."""
    digest = hashlib.sha256(_get_secret_key().encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def hash_password(plain_password: str) -> str:
    """Hash a local user password using bcrypt."""
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    if not hashed_password:
        return False
    return pwd_context.verify(plain_password, hashed_password)


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a sensitive service credential (e.g. LDAP bind password) at rest."""
    if not plaintext:
        return ""
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a sensitive service credential stored with encrypt_secret."""
    if not ciphertext:
        return ""
    try:
        return _get_fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Unable to decrypt stored secret with current SECRET_KEY") from exc


def create_access_token(user: User, expires_delta: timedelta | None = None) -> str:
    """Create a signed JWT access token carrying user identity and RBAC role."""
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=_get_token_expire_minutes()))
    payload: dict[str, Any] = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role.value,
        "auth_provider": user.auth_provider.value,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(payload, _get_secret_key(), algorithm=_get_jwt_algorithm())


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT access token."""
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            _get_secret_key(),
            algorithms=[_get_jwt_algorithm()],
        )
        return payload
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI dependency returning the authenticated active User from Bearer JWT."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject claim",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = uuid.UUID(str(sub))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed user identifier in token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )
    return user


def require_roles(allowed_roles: Sequence[UserRole | str]) -> Callable[..., User]:
    """Build a FastAPI dependency that enforces membership in allowed RBAC roles."""
    normalized_roles = {
        role if isinstance(role, UserRole) else UserRole(str(role))
        for role in allowed_roles
    }

    def _role_dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in normalized_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )
        return current_user

    return _role_dependency


require_admin = require_roles([UserRole.ADMIN])

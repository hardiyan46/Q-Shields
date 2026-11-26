"""Domain Controller / LDAP authentication adapter using ldap3."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ldap3 import NONE, SUBTREE, Connection, Server
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.utils.conv import escape_filter_chars
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.security import decrypt_secret
from ..models import AuthProvider, LdapConfig, User, UserRole


class LdapAuthError(Exception):
    """Base error for LDAP authentication failures."""


class LdapDisabledError(LdapAuthError):
    """Raised when LDAP authentication is disabled or unconfigured."""


class LdapConnectionError(LdapAuthError):
    """Raised when the Domain Controller / LDAP server is unreachable or times out."""


class LdapInvalidCredentialsError(LdapAuthError):
    """Raised when LDAP user lookup or re-bind fails due to invalid credentials."""


class LdapAccountConflictError(LdapAuthError):
    """Raised when an LDAP username collides with an existing LOCAL account."""


@dataclass(frozen=True)
class EffectiveLdapConfig:
    server_url: str
    bind_dn: str
    bind_password: str
    base_dn: str
    user_search_filter: str
    group_operator_dn: str | None
    group_approver_dn: str | None
    group_admin_dn: str | None
    is_enabled: bool
    source: str  # "database" or "environment"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def get_effective_ldap_config(db: Session) -> EffectiveLdapConfig:
    """Load LDAP settings from ldap_configs table first, falling back to environment variables."""
    db_cfg = db.scalar(select(LdapConfig).limit(1))
    if db_cfg is not None:
        return EffectiveLdapConfig(
            server_url=db_cfg.server_url,
            bind_dn=db_cfg.bind_dn,
            bind_password=decrypt_secret(db_cfg.bind_password_encrypted),
            base_dn=db_cfg.base_dn,
            user_search_filter=db_cfg.user_search_filter,
            group_operator_dn=db_cfg.group_operator_dn,
            group_approver_dn=db_cfg.group_approver_dn,
            group_admin_dn=db_cfg.group_admin_dn,
            is_enabled=db_cfg.is_enabled,
            source="database",
        )

    return EffectiveLdapConfig(
        server_url=os.getenv("LDAP_SERVER_URL", "").strip(),
        bind_dn=os.getenv("LDAP_BIND_DN", "").strip(),
        bind_password=os.getenv("LDAP_BIND_PASSWORD", ""),
        base_dn=os.getenv("LDAP_BASE_DN", "").strip(),
        user_search_filter=os.getenv("LDAP_USER_FILTER", "(sAMAccountName={username})").strip(),
        group_operator_dn=os.getenv("LDAP_GROUP_OPERATOR_DN") or None,
        group_approver_dn=os.getenv("LDAP_GROUP_APPROVER_DN") or None,
        group_admin_dn=os.getenv("LDAP_GROUP_ADMIN_DN") or None,
        is_enabled=_env_bool("LDAP_ENABLED", False),
        source="environment",
    )


def _normalize_dn(dn: str | None) -> str:
    return (dn or "").strip().lower()


def resolve_role_from_groups(
    member_of: list[str],
    config: EffectiveLdapConfig,
) -> UserRole:
    """Map LDAP memberOf DNs to RBAC role, defaulting to lowest role (OPERATOR) if unmatched."""
    normalized_groups = {_normalize_dn(group_dn) for group_dn in member_of if group_dn}

    admin_dn = _normalize_dn(config.group_admin_dn)
    approver_dn = _normalize_dn(config.group_approver_dn)
    operator_dn = _normalize_dn(config.group_operator_dn)

    if admin_dn and admin_dn in normalized_groups:
        return UserRole.ADMIN
    if approver_dn and approver_dn in normalized_groups:
        return UserRole.APPROVER
    if operator_dn and operator_dn in normalized_groups:
        return UserRole.OPERATOR

    # Fallback wajib: role terendah (OPERATOR) jika tidak cocok dengan grup mana pun
    return UserRole.OPERATOR


def _extract_attr(entry_attrs: dict[str, Any], key: str) -> str | None:
    value = entry_attrs.get(key)
    if isinstance(value, list):
        return str(value[0]).strip() if value else None
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _extract_list_attr(entry_attrs: dict[str, Any], key: str) -> list[str]:
    value = entry_attrs.get(key)
    if isinstance(value, list):
        return [str(v).strip() for v in value if v]
    if value:
        return [str(value).strip()]
    return []


def authenticate_ldap_user(db: Session, username: str, password: str) -> User:
    """Authenticate user against Domain Controller / LDAP without storing LDAP password in DB."""
    if not password:
        raise LdapInvalidCredentialsError("Password is required for LDAP authentication")

    config = get_effective_ldap_config(db)
    if not config.is_enabled:
        raise LdapDisabledError("LDAP authentication is disabled")
    if not config.server_url or not config.base_dn or not config.bind_dn:
        raise LdapDisabledError("LDAP server configuration is incomplete")

    use_ssl = config.server_url.lower().startswith("ldaps://")
    server = Server(config.server_url, use_ssl=use_ssl, get_info=NONE, connect_timeout=5)

    safe_username = escape_filter_chars(username)
    search_filter = config.user_search_filter.replace("{username}", safe_username)

    service_conn: Connection | None = None
    user_conn: Connection | None = None
    try:
        # 1. Service account bind to locate user DN & read attributes
        service_conn = Connection(
            server,
            user=config.bind_dn,
            password=config.bind_password,
            auto_bind=True,
            receive_timeout=10,
        )
        found = service_conn.search(
            search_base=config.base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["distinguishedName", "mail", "displayName", "cn", "memberOf"],
        )
        if not found or not service_conn.entries:
            raise LdapInvalidCredentialsError("Invalid LDAP username or password")

        entry = service_conn.entries[0]
        attrs = entry.entry_attributes_as_dict
        user_dn = _extract_attr(attrs, "distinguishedName") or str(entry.entry_dn)
        email = _extract_attr(attrs, "mail")
        full_name = (
            _extract_attr(attrs, "displayName")
            or _extract_attr(attrs, "cn")
            or username
        )
        member_of = _extract_list_attr(attrs, "memberOf")

        # 2. Re-bind using the discovered user DN and user-supplied password
        user_conn = Connection(
            server,
            user=user_dn,
            password=password,
            auto_bind=True,
            receive_timeout=10,
        )
    except LdapInvalidCredentialsError:
        raise
    except LDAPBindError as exc:
        # Either service bind failed or user password re-bind failed
        raise LdapInvalidCredentialsError("Invalid LDAP username or password") from exc
    except (LDAPException, OSError, TimeoutError) as exc:
        raise LdapConnectionError(
            f"Unable to reach LDAP/Domain Controller at {config.server_url}: {exc}"
        ) from exc
    finally:
        if user_conn is not None:
            try:
                user_conn.unbind()
            except LDAPException:
                pass
        if service_conn is not None:
            try:
                service_conn.unbind()
            except LDAPException:
                pass

    # 3 & 4. Map memberOf groups -> Role (fallback OPERATOR) & never store LDAP password
    resolved_role = resolve_role_from_groups(member_of, config)
    now = datetime.now(timezone.utc)

    existing_user = db.scalar(select(User).where(User.username == username))
    if existing_user is not None:
        if existing_user.auth_provider == AuthProvider.LOCAL:
            raise LdapAccountConflictError(
                f"Username '{username}' is registered as a LOCAL account"
            )
        if not existing_user.is_active:
            raise LdapInvalidCredentialsError("User account is disabled")

        # Avoid unique email collision if another user already holds that email
        if email and email != existing_user.email:
            email_owner = db.scalar(select(User).where(User.email == email, User.id != existing_user.id))
            if email_owner is None:
                existing_user.email = email
        elif email is None:
            existing_user.email = None

        existing_user.full_name = full_name
        existing_user.ldap_dn = user_dn
        existing_user.password_hash = None
        existing_user.role = resolved_role
        existing_user.last_login_at = now
        db.commit()
        db.refresh(existing_user)
        return existing_user

    safe_email = email
    if safe_email:
        email_taken = db.scalar(select(User).where(User.email == safe_email))
        if email_taken is not None:
            safe_email = None

    new_user = User(
        username=username,
        email=safe_email,
        full_name=full_name,
        auth_provider=AuthProvider.LDAP,
        password_hash=None,  # Dilarang menyimpan password LDAP
        ldap_dn=user_dn,
        role=resolved_role,
        is_active=True,
        last_login_at=now,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

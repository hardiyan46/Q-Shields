"""Startup initial local admin user seeder."""

from __future__ import annotations

import logging
import os

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.security import hash_password
from ..models import AuthProvider, User, UserRole

logger = logging.getLogger(__name__)


def seed_initial_admin(db: Session) -> User | None:
    """Create the initial local ADMIN user if the users table is completely empty."""
    user_count = db.scalar(select(func.count(User.id))) or 0
    if user_count > 0:
        return None

    username = os.getenv("INITIAL_ADMIN_USERNAME", "admin").strip() or "admin"
    password = os.getenv("INITIAL_ADMIN_PASSWORD", "QShieldsAdmin!2026")
    email = os.getenv("INITIAL_ADMIN_EMAIL", "admin@qshields.local").strip() or None

    admin_user = User(
        username=username,
        email=email,
        full_name="Initial Platform Administrator",
        auth_provider=AuthProvider.LOCAL,
        password_hash=hash_password(password),
        role=UserRole.ADMIN,
        is_active=True,
    )
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)
    logger.info("Seeded initial local ADMIN account '%s'", admin_user.username)
    return admin_user

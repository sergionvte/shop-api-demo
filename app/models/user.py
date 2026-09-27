from __future__ import annotations

from datetime import datetime

from sqlalchemy import String
from sqlmodel import Field

from app.core.permissions import Role
from app.db.types import UTCDateTime
from app.models.base import IDMixin, TimestampMixin


class User(IDMixin, TimestampMixin, table=True):
    __tablename__ = "users"

    email: str = Field(max_length=320, unique=True, index=True)
    hashed_password: str = Field(max_length=255)
    full_name: str | None = Field(default=None, max_length=120)
    role: Role = Field(default=Role.user, sa_type=String(20))
    is_active: bool = Field(default=True)
    # Incrementarlo invalida al instante todos los access tokens emitidos.
    token_version: int = Field(default=0)
    failed_login_attempts: int = Field(default=0)
    locked_until: datetime | None = Field(default=None, sa_type=UTCDateTime)
    last_login_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    password_changed_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    # None = email sin verificar. La migración marca a los usuarios ya existentes.
    email_verified_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    # Idioma de los correos (de Accept-Language al registrarse o al usar un enlace).
    locale: str | None = Field(default=None, max_length=10)

    @property
    def email_verified(self) -> bool:
        return self.email_verified_at is not None

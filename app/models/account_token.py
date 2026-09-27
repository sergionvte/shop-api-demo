"""Tokens de un solo uso de los flujos de cuenta (reset, verificación, cambio de email).

Solo se guarda el SHA-256 del token: el token en claro solo existe en el correo.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Index
from sqlmodel import Field

from app.db.types import UTCDateTime, utcnow
from app.models.base import IDMixin


class TokenPurpose(StrEnum):
    password_reset = "password_reset"  # noqa: S105
    email_verify = "email_verify"
    email_change = "email_change"


class AccountToken(IDMixin, table=True):
    __tablename__ = "account_tokens"
    __table_args__ = (Index("ix_account_tokens_user_purpose", "user_id", "purpose", "created_at"),)

    user_id: uuid.UUID = Field(foreign_key="users.id", ondelete="CASCADE")
    purpose: str = Field(max_length=20)
    token_hash: str = Field(max_length=64, unique=True)
    # Dirección a la que se envió: si users.email ya no coincide, el token no vale.
    # En el cambio de email es la dirección NUEVA.
    email: str = Field(max_length=320)
    created_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime, nullable=False)
    expires_at: datetime = Field(sa_type=UTCDateTime, nullable=False, index=True)
    used_at: datetime | None = Field(default=None, sa_type=UTCDateTime)

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Index
from sqlmodel import Field

from app.db.types import UTCDateTime, utcnow, uuid7
from app.models.base import IDMixin


class RefreshToken(IDMixin, table=True):
    """Refresh token opaco. Solo se guarda su hash SHA-256.

    Todos los tokens de una misma sesión comparten `family_id`: cada refresh
    rota el token y, si alguien reutiliza uno ya rotado (robo), se revoca la
    familia entera.
    """

    __tablename__ = "refresh_tokens"
    # Búsqueda de "IP conocida" en el login (smart lockout).
    __table_args__ = (Index("ix_refresh_tokens_user_id_client_ip", "user_id", "client_ip"),)

    user_id: uuid.UUID = Field(foreign_key="users.id", ondelete="CASCADE", index=True)
    family_id: uuid.UUID = Field(default_factory=uuid7, index=True)
    token_hash: str = Field(max_length=64, unique=True, index=True)
    scope: str = Field(default="", max_length=200)
    user_agent: str | None = Field(default=None, max_length=200)
    # Cliente que obtuvo el token (IP, o prefijo /64 en IPv6). Sirve para el
    # "smart lockout" (orígenes conocidos) y el periodo de gracia del refresh.
    client_ip: str | None = Field(default=None, max_length=64)
    created_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime, nullable=False)
    expires_at: datetime = Field(sa_type=UTCDateTime, nullable=False)
    revoked_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    replaced_by_id: uuid.UUID | None = Field(default=None)

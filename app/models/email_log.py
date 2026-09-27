"""Registro mínimo de envíos: cupos por cuenta, idempotencia por trabajo y cortacircuitos.

Sin direcciones ni contenido (solo IDs y el tipo de correo).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlmodel import Field

from app.db.types import UTCDateTime, utcnow
from app.models.base import IDMixin


class EmailLog(IDMixin, table=True):
    __tablename__ = "email_log"

    # Un registro por trabajo: un reintento del mismo trabajo no cuenta dos veces.
    job_id: uuid.UUID | None = Field(default=None, unique=True)
    user_id: uuid.UUID | None = Field(
        default=None, foreign_key="users.id", ondelete="CASCADE", index=True
    )
    kind: str = Field(max_length=40)
    # SHA-256 de la dirección de destino (cupo por destino de los cambios de email).
    recipient_hash: str | None = Field(default=None, max_length=64, index=True)
    created_at: datetime = Field(
        default_factory=utcnow, sa_type=UTCDateTime, nullable=False, index=True
    )
    # Cuándo lo aceptó el proveedor. Con sent_at, un reintento no reenvía (REQ-Q04).
    sent_at: datetime | None = Field(default=None, sa_type=UTCDateTime)

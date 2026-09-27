"""Mixins comunes para todas las tablas."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlmodel import Field, SQLModel

from app.db.types import UTCDateTime, utcnow, uuid7

# Nombres de constraints deterministas: imprescindible para que Alembic pueda
# modificarlas/borrarlas después (sobre todo en SQLite y PostgreSQL).
SQLModel.metadata.naming_convention = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class IDMixin(SQLModel):
    id: uuid.UUID = Field(default_factory=uuid7, primary_key=True)


class TimestampMixin(SQLModel):
    created_at: datetime = Field(
        default_factory=utcnow, sa_type=UTCDateTime, nullable=False, index=True
    )
    updated_at: datetime = Field(
        default_factory=utcnow,
        sa_type=UTCDateTime,
        nullable=False,
        sa_column_kwargs={"onupdate": utcnow},
    )


class SoftDeleteMixin(SQLModel):
    deleted_at: datetime | None = Field(default=None, sa_type=UTCDateTime, index=True)

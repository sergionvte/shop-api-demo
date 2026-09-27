"""Cola de trabajos en segundo plano guardada en la propia base de datos.

Así no hace falta Redis ni otro broker: funciona igual con SQLite y PostgreSQL.
Un proceso aparte (`apigen worker`) reclama los trabajos pendientes y los
ejecuta sin cargar a los workers que atienden peticiones HTTP.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Index
from sqlmodel import Field

from app.db.types import UTCDateTime, utcnow
from app.models.base import IDMixin


class JobStatus(StrEnum):
    queued = "queued"  # esperando a un worker
    running = "running"  # reclamado por un worker
    succeeded = "succeeded"
    failed = "failed"  # agotó los reintentos
    cancelled = "cancelled"


PENDING_STATUSES = (JobStatus.queued, JobStatus.running)


class Job(IDMixin, table=True):
    __tablename__ = "jobs"
    # El worker busca por (status, run_after): este índice mantiene rápida la cola.
    __table_args__ = (Index("ix_jobs_status_run_after", "status", "run_after"),)

    name: str = Field(max_length=100, index=True)
    status: str = Field(default=JobStatus.queued, max_length=20)
    payload: dict[str, Any] = Field(default_factory=dict, sa_type=JSON)
    result: dict[str, Any] | list[Any] | None = Field(default=None, sa_type=JSON)
    # Mensaje apto para el cliente (nunca trazas internas: esas van al log).
    error: str | None = Field(default=None, max_length=500)
    attempts: int = Field(default=0)
    max_attempts: int = Field(default=3)
    priority: int = Field(default=0)
    owner_id: uuid.UUID | None = Field(
        default=None, foreign_key="users.id", ondelete="CASCADE", index=True
    )
    created_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime, nullable=False)
    run_after: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime, nullable=False)
    started_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    finished_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    # Arrendamiento: si el worker muere, el trabajo vuelve a la cola al expirar.
    locked_by: str | None = Field(default=None, max_length=100)
    locked_until: datetime | None = Field(default=None, sa_type=UTCDateTime)

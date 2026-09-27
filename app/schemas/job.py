from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class JobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    status: str
    attempts: int
    max_attempts: int
    result: dict[str, Any] | list[Any] | None
    error: str | None
    created_at: datetime
    run_after: datetime
    started_at: datetime | None
    finished_at: datetime | None


class JobAccepted(BaseModel):
    """Respuesta 202 de un endpoint con proceso en segundo plano."""

    job_id: uuid.UUID
    status: str
    status_url: str

"""Hooks de lógica personalizada para los recursos generados.

Cada recurso tiene su módulo `app/hooks/<recurso>.py`, que `apigen` crea UNA vez
y nunca sobrescribe (ni con `--force`): es el sitio para tu lógica de negocio.
El router generado llama a estas funciones en cada operación CRUD.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlmodel.ext.asyncio.session import AsyncSession

from app.api.deps import Principal
from app.models.job import Job


@dataclass(slots=True)
class HookContext:
    """Lo que recibe cada hook: sesión de BD y quién hace la petición."""

    session: AsyncSession
    principal: Principal

    @property
    def user_id(self) -> uuid.UUID | None:
        return self.principal.user_id

    async def enqueue(self, name: str, payload: dict[str, Any] | None = None, **kwargs) -> Job:
        """Encola una tarea pesada para el worker (no bloquea la petición)."""
        from app.tasks.queue import enqueue

        kwargs.setdefault("owner_id", self.principal.user_id)
        return await enqueue(self.session, name, payload, **kwargs)

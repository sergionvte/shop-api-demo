"""Registro de auditoría: eventos de seguridad estructurados en el logger `app.audit`.

Cada evento lleva `event` (p. ej. `auth.login.failure`), el actor/objetivo y la IP;
el `request_id` lo añade el filtro de logging. Nunca se registran contraseñas,
tokens ni emails (solo IDs).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

audit_logger = logging.getLogger("app.audit")


def audit(event: str, *, level: int = logging.INFO, **fields: Any) -> None:
    data: dict[str, Any] = {"event": event}
    for key, value in fields.items():
        if value is None:
            continue
        data[key] = str(value) if isinstance(value, uuid.UUID) else value
    audit_logger.log(level, event, extra=data)

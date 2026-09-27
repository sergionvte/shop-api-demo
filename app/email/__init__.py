"""Envío de correo: API pública para el código del proyecto.

    from app.email import send_email

    await send_email(session, to=["cliente@example.com"], template="order_shipped",
                     context={"order": order.code}, commit=False)

El correo sale por la cola (`apigen worker`): la petición HTTP no espera al proveedor.
Las plantillas propias van en EMAIL_TEMPLATES_DIR (`email_templates/<lang>/...`).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import BackgroundTasks, Request
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import settings
from app.db.types import utcnow
from app.email.render import resolve_language

__all__ = ["enqueue_account_email", "mask_email", "request_language", "send_email"]

logger = logging.getLogger("app.email")
ACCOUNT_PRIORITY = 10  # los correos de cuenta no esperan detrás de trabajos pesados


def request_language(request: Request) -> str | None:
    """Idioma pedido en Accept-Language (validado contra MAIL_LANGUAGES), o None si la
    petición no lo indica: entonces el worker usa `users.locale` o MAIL_DEFAULT_LANGUAGE."""
    header = request.headers.get("accept-language")
    return resolve_language(header) if header else None


def mask_email(address: str) -> str:
    """n***@dominio.com: para mostrar en avisos sin exponer la dirección completa."""
    local, _, domain = address.partition("@")
    return f"{local[:1]}***@{domain}" if domain else "***"


async def send_email(
    session: AsyncSession,
    *,
    to: list[str],
    template: str,
    context: dict[str, Any] | None = None,
    lang: str | None = None,
    commit: bool = False,
    delay: float = 0,
) -> uuid.UUID:
    """Encola un correo con una plantilla (de serie o de EMAIL_TEMPLATES_DIR).

    Con `commit=False` (por defecto) el correo sale solo si la transacción del hook se
    confirma. Devuelve el id del trabajo."""
    from app.tasks.queue import enqueue

    job = await enqueue(
        session,
        "email.send",
        {"to": to, "template": template, "context": context or {}, "lang": lang},
        delay=delay,
        commit=commit,
    )
    return job.id


async def enqueue_account_email(
    session: AsyncSession,
    name: str,
    payload: dict[str, Any],
    background: BackgroundTasks | None = None,
    *,
    commit: bool = True,
) -> uuid.UUID:
    """Encola un correo de cuenta como trabajo de SISTEMA (owner_id=None, REQ-Q01).

    Solo inserta una fila: la petición cuesta lo mismo exista o no la cuenta (REQ-E07).
    Con EMAIL_DELIVERY=inline (desarrollo) la propia API lo ejecuta tras responder."""
    from app.tasks.queue import enqueue

    data = {**payload, "requested_at": utcnow().isoformat()}
    job = await enqueue(session, name, data, priority=ACCOUNT_PRIORITY, commit=commit)
    if settings.email_delivery == "inline" and background is not None:
        from app.tasks.worker import run_now

        background.add_task(run_now, job.id)
    return job.id

"""Backend en memoria para tests: los mensajes quedan en `outbox`."""

from __future__ import annotations

from app.email.message import EmailMessage, build_mime

outbox: list[EmailMessage] = []


class MemoryBackend:
    name = "memory"

    async def send(self, message: EmailMessage) -> None:
        build_mime(message)  # mismas validaciones de cabeceras que un envío real
        outbox.append(message)

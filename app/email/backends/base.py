"""Interfaz de los backends de correo y sus errores.

Los mensajes de error son NUESTROS (nunca la respuesta cruda del proveedor, ni
direcciones, ni credenciales: REQ-G01/G02/Q08). `code` sirve para diagnosticar
(`apigen email test` lo traduce).
"""

from __future__ import annotations

from typing import Protocol

from app.email.message import EmailMessage


class EmailError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class TransientEmailError(EmailError):
    """Fallo pasajero (red, timeout, SMTP 4xx): se reintenta con el backoff de la cola."""


class PermanentEmailError(EmailError):
    """Fallo definitivo (SMTP 5xx, autenticación, destinatario rechazado): no se reintenta."""


class EmailBackend(Protocol):
    name: str

    async def send(self, message: EmailMessage) -> None: ...


class DisabledBackend:
    name = "disabled"

    async def send(self, message: EmailMessage) -> None:
        raise PermanentEmailError("email_disabled", "Email sending is disabled (EMAIL_BACKEND)")

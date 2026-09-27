"""Backend de desarrollo: escribe el correo en el log (con el enlace en su línea)."""

from __future__ import annotations

import logging

from app.core.config import settings
from app.email.message import EmailMessage, build_mime

logger = logging.getLogger("app.email")


class ConsoleBackend:
    name = "console"

    async def send(self, message: EmailMessage) -> None:
        mime = build_mime(message)
        if settings.is_production:
            # Nunca el cuerpo en producción: puede llevar un enlace con token (REQ-C05).
            logger.warning("console email backend in production: message body omitted")
            return
        logger.warning(
            "\n----- EMAIL (EMAIL_BACKEND=console, solo desarrollo: el enlace contiene "
            "un token de un solo uso) -----\nTo: %s\nSubject: %s\n\n%s\n----- END EMAIL -----",
            mime["To"],
            mime["Subject"],
            message.text.strip(),
        )

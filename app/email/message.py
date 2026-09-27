"""Mensaje de correo y su construcción MIME.

`email.policy.default` rechaza CR/LF en las cabeceras (inyección de cabeceras) y
`formataddr` codifica los nombres; el asunto sale siempre de una plantilla (REQ-M04/M05).
"""

from __future__ import annotations

import email.policy
from dataclasses import dataclass
from email.message import EmailMessage as MIMEMessage
from email.utils import format_datetime, formataddr, make_msgid

from app.core.config import settings
from app.db.types import utcnow

MAX_SUBJECT = 200


@dataclass(frozen=True, slots=True)
class EmailMessage:
    to: tuple[str, ...]
    subject: str
    text: str
    html: str | None = None
    # Estable entre reintentos (<job_id@dominio>): los clientes de correo agrupan duplicados.
    message_id: str | None = None
    reply_to: str | None = None


def clean_subject(subject: str) -> str:
    """Una sola línea, sin espacios repetidos y acotada."""
    return " ".join(subject.split())[:MAX_SUBJECT]


def sender_domain() -> str:
    return settings.EMAIL_FROM.rpartition("@")[2] or "localhost"


def message_id_for(key: str) -> str:
    return f"<{key}@{sender_domain()}>"


def build_mime(message: EmailMessage) -> MIMEMessage:
    """Construye el MIME (multipart/alternative si hay HTML). Lanza ValueError si
    algún valor de cabecera contiene CR/LF."""
    mime = MIMEMessage(policy=email.policy.default)
    mime["From"] = formataddr(
        (settings.EMAIL_FROM_NAME or settings.mail_brand_name, settings.EMAIL_FROM)
    )
    mime["To"] = ", ".join(formataddr(("", address)) for address in message.to)
    mime["Subject"] = clean_subject(message.subject)
    mime["Date"] = format_datetime(utcnow())
    mime["Message-ID"] = message.message_id or make_msgid(domain=sender_domain())
    reply_to = message.reply_to or settings.EMAIL_REPLY_TO
    if reply_to:
        mime["Reply-To"] = reply_to
    # Correo automático: que los autorrespondedores no contesten (RFC 3834).
    mime["Auto-Submitted"] = "auto-generated"
    mime.set_content(message.text)
    if message.html:
        mime.add_alternative(message.html, subtype="html")
    return mime

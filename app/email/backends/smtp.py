"""SMTP genérico (SES, Brevo, Mailgun, SendGrid, Postmark, Resend, Zoho, M365, Mailpit...).

- `smtplib` de la biblioteca estándar en un hilo: cero dependencias. El timeout del
  socket (SMTP_TIMEOUT) acota lo que puede tardar aunque la tarea se cancele.
- TLS siempre verificado (`ssl.create_default_context()`); con `starttls`, si el
  servidor no lo anuncia se falla en vez de seguir en claro (REQ-C07).
- `debuglevel=0` y errores propios: nada de credenciales ni respuestas crudas del
  servidor en logs ni en `job.error` (REQ-G01/G02). `from None` corta la cadena de
  excepciones para que la traza tampoco las arrastre.
"""

from __future__ import annotations

import smtplib
import socket
import ssl
from email.message import EmailMessage as MIMEMessage

import anyio

from app.core.config import settings
from app.email.backends.base import EmailError, PermanentEmailError, TransientEmailError
from app.email.message import EmailMessage, build_mime


def _classify_response(code: int, what: str) -> EmailError:
    if 400 <= code < 500:
        return TransientEmailError(
            f"smtp_{code}", f"SMTP server temporarily refused {what} ({code})"
        )
    return PermanentEmailError(f"smtp_{code}", f"SMTP server rejected {what} ({code})")


class SMTPBackend:
    name = "smtp"

    def __init__(self) -> None:
        self.host = settings.SMTP_HOST
        self.port = settings.SMTP_PORT
        self.security = settings.SMTP_SECURITY
        self.timeout = settings.SMTP_TIMEOUT
        self.user = settings.SMTP_USER

    async def send(self, message: EmailMessage) -> None:
        mime = build_mime(message)
        await anyio.to_thread.run_sync(self._send_sync, mime, abandon_on_cancel=True)

    def _connect(self, context: ssl.SSLContext) -> smtplib.SMTP:
        if self.security == "ssl":
            return smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=context)
        return smtplib.SMTP(self.host, self.port, timeout=self.timeout)

    def _send_sync(self, mime: MIMEMessage) -> None:
        if not self.host:
            raise PermanentEmailError("smtp_not_configured", "SMTP_HOST is not configured")
        context = ssl.create_default_context()
        try:
            with self._connect(context) as client:
                client.set_debuglevel(0)
                if self.security == "starttls":
                    client.ehlo()
                    if not client.has_extn("starttls"):
                        raise PermanentEmailError(
                            "smtp_starttls_unavailable",
                            "SMTP server does not offer STARTTLS (refusing to send in clear)",
                        )
                    client.starttls(context=context)
                    client.ehlo()
                if self.user:
                    client.login(self.user, settings.smtp_password())
                refused = client.send_message(mime)
                if refused:
                    raise PermanentEmailError(
                        "smtp_recipient_refused", "SMTP server refused a recipient"
                    )
        except EmailError:
            raise
        except smtplib.SMTPAuthenticationError:
            raise PermanentEmailError("smtp_auth_failed", "SMTP authentication rejected") from None
        except smtplib.SMTPRecipientsRefused:
            raise PermanentEmailError(
                "smtp_recipient_refused", "SMTP server refused the recipient"
            ) from None
        except smtplib.SMTPNotSupportedError:
            raise PermanentEmailError(
                "smtp_not_supported", "SMTP server does not support a required command"
            ) from None
        except smtplib.SMTPResponseException as exc:
            raise _classify_response(exc.smtp_code, "the message") from None
        except ssl.SSLCertVerificationError:
            raise PermanentEmailError(
                "smtp_tls_certificate", "SMTP server certificate could not be verified"
            ) from None
        except ssl.SSLError:
            raise PermanentEmailError(
                "smtp_tls_error",
                "TLS handshake with the SMTP server failed (check SMTP_SECURITY and SMTP_PORT)",
            ) from None
        except socket.gaierror:
            raise TransientEmailError(
                "smtp_host_not_found", "SMTP_HOST could not be resolved"
            ) from None
        except OSError:
            # Incluye TimeoutError, conexión rechazada y el resto de SMTPException.
            raise TransientEmailError(
                "smtp_connection", "Could not connect to the SMTP server (timeout or refused)"
            ) from None

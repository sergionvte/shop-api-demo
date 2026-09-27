"""Backend de desarrollo: guarda cada correo como .eml (y .html) en EMAIL_FILE_DIR."""

from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path

import anyio

from app.core.config import settings
from app.db.types import utcnow
from app.email.message import EmailMessage, build_mime

logger = logging.getLogger("app.email")


def _write_new(path: Path, data: bytes) -> None:
    # O_EXCL + 0600: no sigue enlaces ni pisa ficheros existentes.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


class FileBackend:
    name = "file"

    def __init__(self, directory: str | None = None) -> None:
        self.directory = Path(directory or settings.EMAIL_FILE_DIR)
        self.last_path: Path | None = None

    async def send(self, message: EmailMessage) -> None:
        mime = build_mime(message)
        # El .txt va decodificado: en el .eml el texto va en quoted-printable y un token
        # copiado de ahí sale partido (UX-71).
        readable = f"To: {mime['To']}\nSubject: {mime['Subject']}\n\n{message.text}"
        self.last_path = await anyio.to_thread.run_sync(
            self._write, mime.as_bytes(), readable, message.html
        )
        logger.info("email guardado en %s (.eml, .txt y .html)", self.last_path)

    def _write(self, eml: bytes, text: str, html: str | None) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        stem = self.directory / f"{utcnow():%Y%m%d-%H%M%S}-{secrets.token_hex(4)}"
        _write_new(stem.with_suffix(".eml"), eml)
        _write_new(stem.with_suffix(".txt"), text.encode("utf-8"))
        if html:
            _write_new(stem.with_suffix(".html"), html.encode("utf-8"))
        return stem.with_suffix(".txt")

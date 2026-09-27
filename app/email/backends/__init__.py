"""Selección del backend de correo según EMAIL_BACKEND (o el de por defecto del entorno)."""

from __future__ import annotations

import importlib

from app.core.config import settings
from app.email.backends.base import (
    DisabledBackend,
    EmailBackend,
    EmailError,
    PermanentEmailError,
    TransientEmailError,
)

__all__ = [
    "EmailBackend", "EmailError", "PermanentEmailError", "TransientEmailError",
    "get_backend", "reset_backend",
]  # fmt: skip

_cache: dict[str, EmailBackend] = {}


def _build(name: str | None) -> EmailBackend:
    if name == "console":
        from app.email.backends.console import ConsoleBackend

        return ConsoleBackend()
    if name == "file":
        from app.email.backends.file import FileBackend

        return FileBackend()
    if name == "memory":
        from app.email.backends.memory import MemoryBackend

        return MemoryBackend()
    if name == "smtp":
        from app.email.backends.smtp import SMTPBackend

        return SMTPBackend()
    if name == "custom":
        # Solo clases del propio proyecto (app.*): validado en la configuración.
        module_name, _, class_name = settings.EMAIL_BACKEND_CLASS.partition(":")
        return getattr(importlib.import_module(module_name), class_name)()
    return DisabledBackend()


def get_backend() -> EmailBackend:
    name = settings.email_backend or "disabled"
    if name not in _cache:
        _cache.clear()
        _cache[name] = _build(name)
    return _cache[name]


def reset_backend() -> None:
    _cache.clear()

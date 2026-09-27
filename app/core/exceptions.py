"""Excepciones HTTP con código estable legible por máquinas.

Todas las respuestas de error llevan `detail` (texto en inglés para humanos o,
en los 422, la lista de errores) y `code` (identificador estable que el
frontend puede traducir o usar para decidir qué hacer).
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

DEFAULT_CODES = {
    400: "bad_request",
    401: "not_authenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "body_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
}


class APIError(HTTPException):
    def __init__(
        self,
        status_code: int,
        detail: Any,
        code: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.code = code


def error_code(exc: Exception, status_code: int) -> str:
    return getattr(exc, "code", None) or DEFAULT_CODES.get(status_code, "error")


EMAIL_NOT_VERIFIED = APIError(
    403,
    "Email address not verified: check your inbox or ask for a new link",
    code="email_not_verified",
)


class DatabaseValueError(Exception):
    """Un valor que el esquema aceptó pero el driver de la BD no puede guardar
    (p. ej. OverflowError de sqlite3 con enteros de más de 64 bits). Solo se lanza
    desde la capa de datos: un OverflowError de otro origen sigue siendo un 500."""

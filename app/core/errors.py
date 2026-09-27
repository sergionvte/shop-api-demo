"""Manejadores de errores: respuestas JSON uniformes que no filtran detalles internos.

Formato común: `{"detail": ..., "code": "..."}`.
- `detail`: texto en inglés (o, en los 422, la lista de errores con `loc`, `msg`
  y `type`), compatible con el formato habitual de FastAPI.
- `code`: identificador estable para que el cliente decida qué hacer.
"""

from __future__ import annotations

import logging
import re

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from fastapi.responses import JSONResponse, Response
from slowapi.errors import RateLimitExceeded
from sqlalchemy.exc import DataError, IntegrityError
from sqlmodel import SQLModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.audit import audit
from app.core.config import settings
from app.core.exceptions import DatabaseValueError, error_code
from app.core.rate_limit import check_unrouted_limit, client_ip, limiter

logger = logging.getLogger("app.errors")


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    if "/auth/" in request.url.path or request.url.path.endswith("/users/me/email"):
        # Un 429 en login/registro/refresh es señal de fuerza bruta: se audita. El resto
        # de endpoints no, para no convertir un flood en un flood de logs.
        audit(
            "auth.rate_limited",
            level=logging.WARNING,
            path=request.url.path,
            client_ip=client_ip(request),
        )
    content = {"detail": f"Rate limit exceeded: {exc.detail}", "code": "rate_limited"}
    if not settings.is_production:
        # Pista solo fuera de producción: en desarrollo es fácil agotar el cupo.
        content["hint"] = (
            "Adjust the RATE_LIMIT_* variables in .env or set RATE_LIMIT_ENABLED=false "
            "(development only); in-memory counters reset when the server restarts."
        )
    response = JSONResponse(content, status_code=status.HTTP_429_TOO_MANY_REQUESTS)
    view_limit = getattr(request.state, "view_rate_limit", None)
    if view_limit is not None:
        response = limiter._inject_headers(response, view_limit)
    return response


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> Response:
    # Rutas inexistentes: no pasan por la dependencia de rate limit (no hay
    # endpoint), así que el límite por defecto se aplica aquí (SEC-11).
    if exc.status_code in (404, 405) and request.scope.get("endpoint") is None:
        try:
            check_unrouted_limit(request)
        except RateLimitExceeded as limited:
            return await rate_limit_handler(request, limited)
    headers = getattr(exc, "headers", None)
    if exc.status_code in (204, 304):
        return Response(status_code=exc.status_code, headers=headers)
    return JSONResponse(
        {"detail": exc.detail, "code": error_code(exc, exc.status_code)},
        status_code=exc.status_code,
        headers=headers,
    )


_BODY_SHAPE_ERRORS = {"model_attributes_type", "dict_type", "model_type"}


def _wrong_media_type(request: Request, exc: RequestValidationError) -> bool:
    """¿El 422 se debe solo a que el cuerpo no es JSON (form, text/plain...)?"""
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if not content_type or content_type == "application/json" or content_type.endswith("+json"):
        return False
    return any(
        tuple(err.get("loc", ())) == ("body",) and err.get("type") in _BODY_SHAPE_ERRORS
        for err in exc.errors()
    )


async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    if _wrong_media_type(request, exc):
        # Coherente con el 415 del login (UX-37).
        return JSONResponse(
            {"detail": "This endpoint expects application/json", "code": "expects_json"},
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        )
    # FastAPI devuelve por defecto el valor recibido (`input`): podría reflejar
    # contraseñas o tokens en logs/proxies. Solo devolvemos ubicación, mensaje y tipo.
    errors = [
        {
            "loc": list(err.get("loc", ())),
            "msg": str(err.get("msg", "")).removeprefix("Value error, "),
            "type": err.get("type", ""),
        }
        for err in exc.errors()
    ]
    return JSONResponse(
        {"detail": errors, "code": "validation_error"},
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
    )


# --- Restricciones de la BD ---------------------------------------------------
_SQLITE_UNIQUE = re.compile(r"UNIQUE constraint failed: (.+)$")
_SQLITE_INDEX = re.compile(r"index '([^']+)'")


def _constraint_columns(name: str) -> list[str]:
    for table in SQLModel.metadata.tables.values():
        for item in (*table.indexes, *table.constraints):
            if item.name == name:
                return [c.name for c in item.columns]
    return []


def describe_integrity_error(exc: IntegrityError, method: str) -> tuple[str, str, list[str]]:
    """(code, detail, campos) a partir del error del driver, sin exponer SQL ni valores.

    Solo se devuelven nombres de columna, que ya son públicos en el esquema de la
    API. En recursos con propietario la unicidad es por usuario (UniqueConstraint
    con owner_id), así que el 409 no revela datos de otros usuarios (SEC-09).
    """
    orig = exc.orig
    cause = getattr(orig, "__cause__", None)
    sqlstate = getattr(orig, "sqlstate", None) or getattr(cause, "sqlstate", None)
    text = str(orig)
    fields: list[str] = []

    if sqlstate == "23505" or "UNIQUE constraint failed" in text:
        constraint = getattr(cause, "constraint_name", None)
        if constraint:
            fields = _constraint_columns(constraint)
        elif match := _SQLITE_INDEX.search(text):
            fields = _constraint_columns(match.group(1))
        elif match := _SQLITE_UNIQUE.search(text):
            fields = [part.strip().rsplit(".", 1)[-1] for part in match.group(1).split(",")]
        fields = [f for f in fields if f != "owner_id"]
        what = ", ".join(fields) if fields else "a unique field"
        return "unique_violation", f"A record with the same {what} already exists", fields
    if sqlstate == "23503" or "FOREIGN KEY constraint failed" in text:
        if method == "DELETE":
            return (
                "has_dependents",
                "Cannot delete this record: other records reference it",
                [],
            )
        return "reference_violation", "A referenced record does not exist", []
    if sqlstate == "23502" or "NOT NULL constraint failed" in text:
        return "not_null_violation", "A required value is missing", []
    return "conflict", "Conflict: a database constraint was violated", []


async def integrity_handler(request: Request, exc: IntegrityError) -> JSONResponse:
    code, detail, fields = describe_integrity_error(exc, request.method)
    logger.info("integrity error: %s (%s)", exc.orig.__class__.__name__, code)
    content: dict[str, object] = {"detail": detail, "code": code}
    if fields:
        content["fields"] = fields
    return JSONResponse(content, status_code=status.HTTP_409_CONFLICT)


async def data_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Valor que el esquema aceptó pero la BD no (fuera de rango, NUL en PostgreSQL...):
    # es un error del cliente, no un 500.
    logger.info("data error: %s", exc.__class__.__name__)
    return JSONResponse(
        {"detail": "Value out of range or not accepted by the database", "code": "invalid_value"},
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
    )


def log_unhandled(request_id: str | None, exc: BaseException) -> None:
    if isinstance(exc, ResponseValidationError):
        # Sus errores incluyen los valores de la respuesta (p. ej. emails): solo
        # registramos ubicación y tipo, nunca los datos (SEC-12).
        summary = [(list(e.get("loc", ())), e.get("type")) for e in exc.errors()]
        logger.error(
            "response validation error: %s", summary, extra={"request_id": request_id or "-"}
        )
        return
    logger.error("unhandled error", exc_info=exc, extra={"request_id": request_id or "-"})


def internal_error_body(request_id: str | None) -> dict[str, object]:
    return {"detail": "Internal server error", "code": "internal_error", "request_id": request_id}


async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    # Último recurso: solo llega aquí un error de un middleware externo; los de la
    # aplicación los captura antes `UnhandledErrorMiddleware` (con cabeceras).
    log_unhandled(_request_id(request), exc)
    return JSONResponse(
        internal_error_body(_request_id(request)),
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(RateLimitExceeded, rate_limit_handler)  # type: ignore[arg-type]
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_handler)  # type: ignore[arg-type]
    app.add_exception_handler(IntegrityError, integrity_handler)  # type: ignore[arg-type]
    app.add_exception_handler(DataError, data_error_handler)
    # Solo el OverflowError de la capa de datos (Repository lo convierte); uno de
    # otro origen es un bug y debe dar 500 (SEC-24).
    app.add_exception_handler(DatabaseValueError, data_error_handler)
    app.add_exception_handler(Exception, unhandled_handler)

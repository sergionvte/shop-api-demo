"""Middlewares ASGI puros (más rápidos que BaseHTTPMiddleware)."""

from __future__ import annotations

import logging
import re
import time
import uuid

from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings
from app.core.logging import request_id_ctx

access_logger = logging.getLogger("app.access")
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


class RequestContextMiddleware:
    """Asigna un X-Request-ID, lo propaga a los logs y registra cada petición."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = ""
        for name, value in scope["headers"]:
            if name == b"x-request-id":
                incoming = value.decode("latin-1")
                break
        # Solo aceptamos IDs con formato seguro (evita inyección en logs).
        request_id = incoming if _SAFE_REQUEST_ID.match(incoming) else uuid.uuid4().hex
        token = request_id_ctx.set(request_id)
        scope.setdefault("state", {})["request_id"] = request_id
        start = time.perf_counter()
        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                MutableHeaders(scope=message).append("X-Request-ID", request_id)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            client = scope.get("client")
            access_logger.info(
                "%s %s %s %.2fms",
                scope["method"],
                scope["path"],
                status,
                elapsed_ms,
                extra={
                    "method": scope["method"],
                    "path": scope["path"],
                    "status": status,
                    "duration_ms": elapsed_ms,
                    "client_ip": client[0] if client else None,
                },
            )
            request_id_ctx.reset(token)


_DOCS_PATHS = ("/docs", "/redoc")
_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
# Swagger UI / ReDoc cargan sus assets desde jsDelivr (solo cuando los docs están activos).
_DOCS_CSP = (
    "default-src 'none'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.redoc.ly; "
    "font-src https://fonts.gstatic.com; connect-src 'self'; worker-src blob:; "
    "frame-ancestors 'none'; base-uri 'none'"
)


class SecurityHeadersMiddleware:
    """Cabeceras de seguridad en todas las respuestas."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.static_headers = [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
        ]
        self.hsts = (
            f"max-age={settings.HSTS_SECONDS}; includeSubDomains" if settings.HSTS_SECONDS else None
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope["path"]
        is_docs = settings.docs_enabled and path.endswith(_DOCS_PATHS)
        https = scope.get("scheme") == "https"

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in self.static_headers:
                    headers.setdefault(name, value)
                headers.setdefault("Content-Security-Policy", _DOCS_CSP if is_docs else _API_CSP)
                # Las respuestas de la API pueden contener datos personales: no cachear.
                headers.setdefault("Cache-Control", "no-store")
                if https and self.hsts:
                    headers.setdefault("Strict-Transport-Security", self.hsts)
                if "server" in headers:
                    del headers["server"]
            await send(message)

        await self.app(scope, receive, send_wrapper)


class BodyTooLarge(HTTPException):
    # Subclase de HTTPException: FastAPI la propaga tal cual al leer el body
    # (cualquier otra excepción la convertiría en un 400 genérico).
    code = "body_too_large"

    def __init__(self) -> None:
        super().__init__(status_code=413, detail="Request body too large")


class BodySizeLimitMiddleware:
    """Rechaza cuerpos mayores que MAX_BODY_SIZE (también con chunked encoding)."""

    def __init__(self, app: ASGIApp, max_size: int) -> None:
        self.app = app
        self.max_size = max_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        for name, value in scope["headers"]:
            if name == b"content-length":
                try:
                    too_big = int(value) > self.max_size
                except ValueError:
                    too_big = True
                if too_big:
                    await _send_413(send)
                    return
                break

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_size:
                    raise BodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except BodyTooLarge:
            if not response_started:
                await _send_413(send)


async def _send_413(send: Send) -> None:
    body = b'{"detail":"Request body too large","code":"body_too_large"}'
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class NullByteGuardMiddleware:
    """Rechaza NUL (``\\x00`` o ``%00``) en la ruta o la query con un 422.

    PostgreSQL no admite NUL en columnas de texto: sin esto, ``?q=%00`` llegaba a
    la BD y acababa en un 500 (visto al validar con Docker + PostgreSQL). El
    cuerpo JSON ya lo filtran los esquemas (`StrictInput`)."""

    @staticmethod
    def _body(where: str) -> bytes:
        return (
            b'{"detail":[{"loc":["' + where.encode() + b'"],"msg":"NUL character is not '
            b'allowed","type":"null_character"}],"code":"validation_error"}'
        )

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    @staticmethod
    def _has_nul(value: bytes | str) -> bool:
        return (
            (b"%00" in value or b"\x00" in value) if isinstance(value, bytes) else ("\x00" in value)
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            where = None
            if self._has_nul(scope.get("raw_path") or b"") or self._has_nul(scope.get("path", "")):
                where = "path"
            elif self._has_nul(scope.get("query_string", b"")):
                where = "query"
            if where is not None:
                body = self._body(where)
                await send(
                    {
                        "type": "http.response.start",
                        "status": 422,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


class UnhandledErrorMiddleware:
    """Convierte excepciones no controladas en un 500 JSON *dentro* de la pila de
    middlewares, de modo que la respuesta sí lleva cabeceras de seguridad,
    X-Request-ID y CORS (SEC-06). El handler de `Exception` de Starlette corre en
    la capa más externa, por fuera de todos ellos.

    Con DEBUG=true se deja pasar para que Starlette muestre la traza.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or settings.DEBUG:
            await self.app(scope, receive, send)
            return
        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception as exc:
            if started:
                raise
            # Import diferido: errors importa rate_limit, que importa este módulo indirectamente.
            from app.core.errors import internal_error_body, log_unhandled

            request_id = scope.get("state", {}).get("request_id")
            log_unhandled(request_id, exc)
            response = JSONResponse(internal_error_body(request_id), status_code=500)
            await response(scope, receive, send)


class RateLimitHeadersMiddleware:
    """Pule las cabeceras de SlowAPI: `X-RateLimit-Reset` como entero (epoch) y
    `Retry-After` solo en las respuestas 429, que es donde tiene sentido."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                reset = headers.get("x-ratelimit-reset")
                if reset and "." in reset:
                    try:
                        headers["X-RateLimit-Reset"] = str(int(float(reset)))
                    except ValueError:
                        pass
                if message["status"] != 429 and "retry-after" in headers:
                    del headers["retry-after"]
            await send(message)

        await self.app(scope, receive, send_wrapper)


class JSONTrustedHostMiddleware(TrustedHostMiddleware):
    """`TrustedHostMiddleware` de Starlette con el 400 en JSON y con `code` (contrato T6).

    Starlette responde `400 Invalid host header` en texto plano. Reutilizamos su
    validación (comodines, redirección www) y solo reescribimos esa respuesta.
    """

    def __init__(self, app: ASGIApp, allowed_hosts: list[str]) -> None:
        super().__init__(self._accepted, allowed_hosts=allowed_hosts)
        self._inner = app

    async def _accepted(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Host válido: la aplicación recibe el `send` original, sin reescritura.
        await self._inner(scope, receive, getattr(send, "original", send))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await super().__call__(scope, receive, _HostRejectionSend(send))


class _HostRejectionSend:
    """`send` que convierte el 400 de texto plano de Starlette en JSON."""

    body = b'{"detail":"Invalid host header","code":"invalid_host"}'

    def __init__(self, send: Send) -> None:
        self.original = send
        self.rewrite = False

    async def __call__(self, message: Message) -> None:
        if message["type"] == "http.response.start" and message["status"] == 400:
            self.rewrite = True
            headers = [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(self.body)).encode()),
            ]
            await self.original({**message, "headers": headers})
        elif message["type"] == "http.response.body" and self.rewrite:
            await self.original({"type": "http.response.body", "body": self.body})
        else:
            await self.original(message)

"""Rate limiting con SlowAPI.

- Clave por usuario autenticado (`user:<id>`) o, si no hay token válido, por IP.
- Las IPv6 se agrupan por /64: un atacante suele controlar la subred entera.
- `key_style="endpoint"`: el contador es por endpoint, no por URL, así que
  variar el ID de la ruta (/items/1, /items/2...) no abre contadores nuevos.
- Con Redis caído se degrada a memoria en lugar de tumbar la API.
- RATE_LIMIT_GLOBAL es por cliente (suma de todos los endpoints), no un total
  del servidor; RATE_LIMIT_DEFAULT es por cliente y endpoint.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from itertools import chain

import anyio
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings
from app.core.security import TokenError, decode_access_token


def client_ip(request: Request) -> str:
    """IP real del cliente. Si hay proxies de confianza, `ProxyHeadersMiddleware`
    ya ha sustituido `request.client` por la IP de X-Forwarded-For."""
    host = request.client.host if request.client else ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host or "unknown"
    if ip.version == 6:
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def ip_key(request: Request) -> str:
    return f"ip:{client_ip(request)}"


def user_or_ip_key(request: Request) -> str:
    cached = getattr(request.state, "rate_limit_key", None)
    if cached:
        return cached
    key = ip_key(request)
    auth = request.headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() == "bearer" and token:
        try:
            key = f"user:{decode_access_token(token)['sub']}"
        except TokenError:
            pass
    request.state.rate_limit_key = key
    return key


limiter = Limiter(
    key_func=user_or_ip_key,
    default_limits=[settings.RATE_LIMIT_DEFAULT],
    application_limits=[settings.RATE_LIMIT_GLOBAL],
    storage_uri=settings.RATE_LIMIT_STORAGE_URI,
    strategy=settings.RATE_LIMIT_STRATEGY,
    headers_enabled=settings.RATE_LIMIT_HEADERS,
    enabled=settings.RATE_LIMIT_ENABLED,
    key_style="endpoint",
    key_prefix=settings.PROJECT_NAME.lower().replace(" ", "-"),
    in_memory_fallback_enabled=True,
)


_logger = logging.getLogger("app.rate_limit")
# Atributos privados de SlowAPI (fijada a <0.2 en pyproject); el test
# `test_default_rate_limit_applies_to_included_routers` detecta si cambian.
_evaluate = limiter._Limiter__evaluate_limits  # type: ignore[attr-defined]
_BACKEND_RETRY_SECONDS = 30
_last_backend_check = 0.0


async def _maybe_recover_backend() -> None:
    """Cada 30 s, con el backend marcado como caído, comprueba si volvió.

    `storage.check()` es síncrono (red): se ejecuta en un hilo y se espera como
    mucho 0,5 s, así un Redis colgado no bloquea el event loop (SEC-24). Pon
    también `socket_timeout` en la URI de Redis (ver .env.example).
    """
    global _last_backend_check
    if not limiter._storage_dead:
        return
    if time.monotonic() - _last_backend_check <= _BACKEND_RETRY_SECONDS:
        return
    _last_backend_check = time.monotonic()
    with anyio.move_on_after(0.5):
        try:
            alive = await anyio.to_thread.run_sync(limiter._storage.check, abandon_on_cancel=True)
        except Exception:  # noqa: BLE001
            alive = False
        if alive:
            limiter._storage_dead = False
            _logger.info("rate limit storage recovered")


def _evaluate_with_fallback(request: Request, name: str, limits: list) -> None:
    """Evalúa límites; si el backend (Redis) falla, pasa al almacenamiento en
    memoria (como hace SlowAPI en los endpoints decorados) en lugar de dejar
    pasar la petición sin límite. La recuperación la intenta `_maybe_recover_backend`."""
    global _last_backend_check
    try:
        _evaluate(request, name, limits)
    except RateLimitExceeded:
        raise
    except Exception:
        if limiter._storage_dead or not limiter._in_memory_fallback_enabled:
            # Ni siquiera la memoria funciona: no tumbamos la API por esto.
            _logger.warning("rate limit storage error", exc_info=True)
            return
        _logger.warning("rate limit storage unreachable: using in-memory fallback")
        limiter._storage_dead = True
        _last_backend_check = time.monotonic()
        _evaluate(request, name, limits)


def check_unrouted_limit(request: Request) -> None:
    """Límite por defecto (por IP/usuario) para peticiones a rutas inexistentes:
    escaneos y ruido de logs también consumen cupo."""
    if not limiter.enabled:
        return
    limits = list(chain(*limiter._default_limits)) + list(chain(*limiter._application_limits))
    _evaluate_with_fallback(request, "__unrouted__", limits)


async def enforce_rate_limits(request: Request, response: Response) -> None:
    """Dependencia global que aplica los límites global y por defecto.

    FastAPI >= 0.140 ya no aplana los routers incluidos en `app.routes`, así que
    `SlowAPIMiddleware` no encuentra el endpoint y se salta en silencio los
    límites por defecto. Aquí el endpoint ya está resuelto (`scope["endpoint"]`).
    Los endpoints con `@limiter.limit(...)` solo reciben el límite global aquí;
    su límite específico lo aplica el propio decorador.
    """
    if not limiter.enabled:
        return
    endpoint = request.scope.get("endpoint")
    if endpoint is None:
        return
    name = f"{endpoint.__module__}.{endpoint.__name__}"
    if name in limiter._exempt_routes:
        return
    decorated = name in limiter._route_limits or name in limiter._dynamic_route_limits
    # Primero el límite por defecto: así las cabeceras X-RateLimit-* muestran el más estricto.
    limits = [] if decorated else list(chain(*limiter._default_limits))
    limits += list(chain(*limiter._application_limits))
    await _maybe_recover_backend()
    _evaluate_with_fallback(request, name, limits)
    if not decorated and limiter._headers_enabled:
        view_limit = getattr(request.state, "view_rate_limit", None)
        if view_limit is not None:
            limiter._inject_headers(response, view_limit)

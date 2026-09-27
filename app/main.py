"""Punto de entrada: `uvicorn app.main:app`."""

from __future__ import annotations

import importlib
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.api import health
from app.api.versions import VERSIONS, APIVersion
from app.core.config import settings
from app.core.errors import register_exception_handlers
from app.core.logging import setup_logging
from app.core.middleware import (
    BodySizeLimitMiddleware,
    JSONTrustedHostMiddleware,
    NullByteGuardMiddleware,
    RateLimitHeadersMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    UnhandledErrorMiddleware,
)
from app.core.rate_limit import enforce_rate_limits, limiter
from app.db.session import engine

logger = logging.getLogger("app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "starting %s (%s) db=%s rate_limit=%s",
        settings.PROJECT_NAME,
        settings.ENVIRONMENT,
        engine.url.get_backend_name(),
        settings.RATE_LIMIT_STORAGE_URI.split(":", 1)[0] if settings.RATE_LIMIT_ENABLED else "off",
    )
    yield
    await engine.dispose()


def _deprecation_dependency(version: APIVersion):
    headers = version.deprecation_headers()

    async def add_headers(response: Response) -> None:
        response.headers.update(headers)

    return add_headers


# En desarrollo, sin CORS_ORIGINS, se permite cualquier frontend local (UX-17).
_DEV_LOCAL_ORIGINS = r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$"


class VersionInfo(BaseModel):
    name: str
    prefix: str
    deprecated: bool
    sunset: str | None


def create_app() -> FastAPI:
    setup_logging()
    import app.tasks  # noqa: F401  (registra las tareas: enqueue valida los nombres)

    docs = settings.docs_enabled
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.PROJECT_VERSION,
        description=settings.PROJECT_DESCRIPTION,
        debug=settings.DEBUG,
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
        swagger_ui_parameters={"persistAuthorization": False},
        dependencies=[Depends(enforce_rate_limits)],
    )
    app.state.limiter = limiter
    register_exception_handlers(app)

    # --- Rutas -------------------------------------------------------------
    app.include_router(health.router)
    for version in VERSIONS:
        module = importlib.import_module(version.module)
        deps = [Depends(_deprecation_dependency(version))] if version.deprecated else []
        app.include_router(
            module.api_router,
            prefix=f"{settings.API_PREFIX}/{version.name}",
            dependencies=deps,
            deprecated=version.deprecated or None,
        )

    @app.get(f"{settings.API_PREFIX}/versions", response_model=list[VersionInfo], tags=["meta"])
    async def list_versions() -> list[VersionInfo]:
        return [
            VersionInfo(
                name=v.name,
                prefix=f"{settings.API_PREFIX}/{v.name}",
                deprecated=v.deprecated,
                sunset=v.sunset,
            )
            for v in VERSIONS
        ]

    if docs:

        @app.get("/", include_in_schema=False)
        async def index() -> dict[str, str]:
            # Solo con los docs activos (desarrollo): en producción `/` sigue dando 404.
            return {
                "name": settings.PROJECT_NAME,
                "docs": "/docs",
                "versions": f"{settings.API_PREFIX}/versions",
                "health": "/health/live",
            }

    # --- Middlewares (el último añadido es el más externo) -------------------
    # Lo más interno: convierte excepciones en 500 JSON que luego reciben las
    # cabeceras de CORS, seguridad y X-Request-ID de las capas exteriores.
    app.add_middleware(UnhandledErrorMiddleware)
    if settings.GZIP_MIN_SIZE:
        app.add_middleware(GZipMiddleware, minimum_size=settings.GZIP_MIN_SIZE)
    # Dentro de CORS: su 422 lleva las cabeceras CORS (si no, el navegador solo ve un
    # error de red opaco).
    app.add_middleware(NullByteGuardMiddleware)
    dev_cors = settings.ENVIRONMENT == "development" and not settings.CORS_ORIGINS
    if settings.CORS_ORIGINS or dev_cors:
        if dev_cors:
            logger.info("CORS: permitido cualquier origen localhost (solo desarrollo)")
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.CORS_ORIGINS,
            allow_origin_regex=_DEV_LOCAL_ORIGINS if dev_cors else None,
            allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
            expose_headers=[
                "X-Request-ID",
                "Retry-After",
                "X-RateLimit-Limit",
                "X-RateLimit-Remaining",
                "X-RateLimit-Reset",
            ],
            max_age=600,
        )
    app.add_middleware(BodySizeLimitMiddleware, max_size=settings.MAX_BODY_SIZE)
    app.add_middleware(RateLimitHeadersMiddleware)
    # Dentro de SecurityHeaders: el 400 de Host no permitido también lleva las cabeceras.
    app.add_middleware(JSONTrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)
    if settings.TRUSTED_PROXIES:
        app.add_middleware(ProxyHeadersMiddleware, trusted_hosts=settings.TRUSTED_PROXIES)
    return app


app = create_app()

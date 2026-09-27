"""Motor async y sesiones. Cambiar de base de datos = cambiar DATABASE_URL."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import settings


def _engine_kwargs() -> dict[str, Any]:
    kwargs: dict[str, Any] = {"echo": settings.DB_ECHO, "pool_pre_ping": True}
    if settings.is_sqlite:
        kwargs["connect_args"] = {"timeout": 30}
        return kwargs
    kwargs.update(
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT,
        pool_recycle=settings.DB_POOL_RECYCLE,
    )
    if settings.is_postgres and "asyncpg" in settings.DATABASE_URL:
        server_settings = {"application_name": settings.PROJECT_NAME[:60]}
        if settings.DB_STATEMENT_TIMEOUT_MS:
            server_settings["statement_timeout"] = str(settings.DB_STATEMENT_TIMEOUT_MS)
        kwargs["connect_args"] = {"server_settings": server_settings}
    return kwargs


def create_engine() -> AsyncEngine:
    engine = create_async_engine(settings.DATABASE_URL, **_engine_kwargs())
    if settings.is_sqlite:

        @event.listens_for(engine.sync_engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")  # lectores no bloquean escritores
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")  # SQLite no las aplica por defecto
            # Espera hasta 30 s por el lock de escritura en vez de fallar con
            # "database is locked" (varios workers escribiendo a la vez).
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()

    return engine


engine = create_engine()
SessionFactory = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionFactory() as session:
        yield session

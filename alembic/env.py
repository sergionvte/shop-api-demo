"""Entorno de Alembic (async). La URL sale de DATABASE_URL, nunca de alembic.ini."""

import asyncio
import logging
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel

import app.models  # noqa: F401  (registra todas las tablas en SQLModel.metadata)
from alembic import context
from app.core.config import settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)
if config.attributes.get("quiet"):
    # `apigen db migrate` sin --verbose: solo avisos y errores de Alembic.
    logging.getLogger("alembic").setLevel(logging.WARNING)

target_metadata = SQLModel.metadata


def _skip_empty(_context, _revision, directives) -> None:
    # `apigen db migrate` no crea migraciones vacías si no hay cambios.
    if config.attributes.get("skip_empty") and directives and directives[0].upgrade_ops.is_empty():
        directives[:] = []


def _configure(**kwargs) -> None:
    context.configure(
        target_metadata=target_metadata,
        process_revision_directives=_skip_empty,
        compare_type=True,
        # SQLite no soporta ALTER TABLE completo: "batch mode" recrea la tabla.
        render_as_batch=settings.is_sqlite,
        **kwargs,
    )


def run_migrations_offline() -> None:
    _configure(url=settings.DATABASE_URL, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    _configure(connection=connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = create_async_engine(settings.DATABASE_URL, poolclass=pool.NullPool)
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_async_migrations())

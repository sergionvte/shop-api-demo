"""Derechos del interesado y retención de datos personales.

- Exportación (ISO 27701 7.3.8, SOC 2 P5.1, RGPD art. 15/20): copia en JSON de todo
  lo que la API guarda de un usuario, incluidas las filas de los recursos generados
  que le pertenecen (cualquier FK a `users.id`, p. ej. `owner_id`).
- Supresión (ISO 27701 7.3.6, SOC 2 P4.3, RGPD art. 17): borrar el usuario borra en
  cascada sus sesiones, tokens, registros de envío, trabajos y recursos `owned`.
- Retención (ISO 27701 7.4.7/7.4.8, SOC 2 C1.2): `apigen db prune` borra cuentas
  nunca verificadas y filas borradas lógicamente pasado su plazo.

Las tablas se descubren en los metadatos, así que cubre también los recursos que se
generen después. Las columnas `write_only` (marcadas por apigen en `Column.info`) no
se exportan: se aceptan pero nunca se devuelven, tampoco aquí.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from decimal import Decimal
from typing import Any

from fastapi.encoders import jsonable_encoder
from sqlalchemy import Column, Table, delete, or_, select
from sqlalchemy.exc import IntegrityError
from sqlmodel import SQLModel, col
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import settings
from app.core.permissions import Role
from app.db.types import utcnow
from app.models.account_token import AccountToken
from app.models.email_log import EmailLog
from app.models.job import Job
from app.models.refresh_token import RefreshToken
from app.models.user import User

logger = logging.getLogger("app.privacy")

EXPORT_FORMAT = "apigen-export/1"
# Tablas del núcleo: se exportan con columnas escogidas (sin hashes de tokens).
CORE_TABLES = {"users", "refresh_tokens", "account_tokens", "email_log", "jobs"}
_ACCOUNT_FIELDS = (
    "id", "email", "full_name", "role", "is_active", "email_verified_at", "locale",
    "created_at", "updated_at", "last_login_at", "password_changed_at",
    "failed_login_attempts", "locked_until",
)  # fmt: skip


def user_columns(table: Table) -> list[Column]:
    """Columnas de `table` que apuntan a un usuario (owner_id, autor...)."""
    return [fk.parent for fk in table.foreign_keys if fk.column.table.name == "users"]


def personal_tables() -> list[Table]:
    """Tablas de recursos (no del núcleo) con filas asociadas a un usuario."""
    return [
        table
        for table in SQLModel.metadata.sorted_tables
        if table.name not in CORE_TABLES and user_columns(table)
    ]


async def _rows(
    session: AsyncSession, columns: list[Any], where: Any, order: Any
) -> tuple[list[dict[str, Any]], bool]:
    limit = settings.PRIVACY_EXPORT_MAX_ROWS
    result = await session.execute(select(*columns).where(where).order_by(order).limit(limit + 1))
    rows = [dict(row._mapping) for row in result]
    return rows[:limit], len(rows) > limit


async def export_user_data(session: AsyncSession, user: User) -> dict[str, Any]:
    uid = user.id
    sessions, _ = await _rows(
        session,
        [
            RefreshToken.id,
            RefreshToken.family_id,
            RefreshToken.scope,
            RefreshToken.user_agent,
            RefreshToken.client_ip,
            RefreshToken.created_at,
            RefreshToken.expires_at,
            RefreshToken.revoked_at,
        ],  # fmt: skip
        col(RefreshToken.user_id) == uid,
        col(RefreshToken.created_at),
    )
    tokens, _ = await _rows(
        session,
        [
            AccountToken.purpose,
            AccountToken.email,
            AccountToken.created_at,
            AccountToken.expires_at,
            AccountToken.used_at,
        ],  # fmt: skip
        col(AccountToken.user_id) == uid,
        col(AccountToken.created_at),
    )
    emails, _ = await _rows(
        session,
        [EmailLog.kind, EmailLog.created_at, EmailLog.sent_at],
        col(EmailLog.user_id) == uid,
        col(EmailLog.created_at),
    )
    jobs, _ = await _rows(
        session,
        [Job.id, Job.name, Job.status, Job.created_at, Job.finished_at],
        col(Job.owner_id) == uid,
        col(Job.created_at),
    )
    resources: dict[str, Any] = {}
    for table in personal_tables():
        columns = [c for c in table.c if not c.info.get("write_only")]
        where = or_(*(c == uid for c in user_columns(table)))
        order = table.c.created_at if "created_at" in table.c else table.c.id
        rows, truncated = await _rows(session, columns, where, order)
        if rows:
            resources[table.name] = {"rows": rows, "truncated": truncated}
    data = {
        "format": EXPORT_FORMAT,
        "generated_at": utcnow(),
        "account": {name: getattr(user, name) for name in _ACCOUNT_FIELDS},
        "sessions": sessions,
        "account_tokens": tokens,
        "emails": emails,
        "jobs": jobs,
        "resources": resources,
    }
    # Decimal como texto: un float perdería precisión (importes...).
    return jsonable_encoder(data, custom_encoder={Decimal: str})


# ---------------------------------------------------------------------------
# Retención (`apigen db prune`)
# ---------------------------------------------------------------------------
async def prune_unverified_users(session: AsyncSession) -> int:
    """Borra las cuentas que nunca verificaron su email en UNVERIFIED_ACCOUNT_RETENTION_DAYS.

    Solo con EMAIL_VERIFICATION=required: con `optional` u `off` una cuenta sin
    verificar se usa con normalidad y no se puede borrar por esto. Nunca borra admins.
    Una a una: si otra fila la referencia (FK RESTRICT), se conserva y se sigue."""
    days = settings.UNVERIFIED_ACCOUNT_RETENTION_DAYS
    if not days or settings.email_verification != "required":
        return 0
    cutoff = utcnow() - timedelta(days=days)
    result = await session.execute(
        select(User.id).where(
            col(User.email_verified_at).is_(None),
            col(User.created_at) < cutoff,
            col(User.role) != Role.admin,
        )
    )
    ids = result.scalars().all()
    removed = 0
    for user_id in ids:
        try:
            await session.execute(delete(User).where(col(User.id) == user_id))
            await session.commit()
            removed += 1
        except IntegrityError:
            await session.rollback()
            logger.warning("retention: user %s kept (referenced by other rows)", user_id)
    return removed


async def prune_soft_deleted(session: AsyncSession) -> int:
    """Borra de verdad las filas borradas lógicamente hace más de SOFT_DELETE_RETENTION_DAYS.

    Los hijos van antes que los padres (orden inverso de dependencias): un borrado
    lógico en cascada marcó a ambos a la vez, así que caen juntos."""
    days = settings.SOFT_DELETE_RETENTION_DAYS
    if not days:
        return 0
    cutoff = utcnow() - timedelta(days=days)
    removed = 0
    for table in reversed(SQLModel.metadata.sorted_tables):
        if "deleted_at" not in table.c:
            continue
        try:
            result = await session.execute(
                delete(table).where(table.c.deleted_at.is_not(None), table.c.deleted_at < cutoff)
            )
            await session.commit()
            removed += result.rowcount or 0
        except IntegrityError:
            await session.rollback()
            logger.warning("retention: soft-deleted rows of %s kept (still referenced)", table.name)
    return removed

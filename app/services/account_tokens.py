"""Tokens de un solo uso de los flujos de cuenta (REQ-T01..T13).

- Opacos: prefijo por propósito + `secrets.token_urlsafe(32)` (256 bits).
- En BD solo `sha256(token)`; toda consulta filtra por `purpose` (el prefijo no basta).
- Consumo atómico: `UPDATE ... WHERE used_at IS NULL AND expires_at > now`.
- Máximo MAX_ACTIVE vigentes por usuario y propósito: tolera reintentos de la cola
  (dos correos, dos enlaces válidos) sin acumular enlaces vivos.
"""

from __future__ import annotations

import re
import secrets
import uuid
from datetime import timedelta

from sqlalchemy import delete, or_, update
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import settings
from app.core.security import hash_token
from app.db.types import utcnow
from app.models.account_token import AccountToken, TokenPurpose
from app.models.email_log import EmailLog
from app.models.user import User

PREFIX = {
    TokenPurpose.password_reset: "pr_",
    TokenPurpose.email_verify: "ev_",
    TokenPurpose.email_change: "ec_",
}
MAX_ACTIVE = 3
_BODY = re.compile(r"^[A-Za-z0-9_-]+$")


def ttl(purpose: TokenPurpose) -> timedelta:
    if purpose == TokenPurpose.password_reset:
        return timedelta(minutes=settings.TOKEN_TTL_RESET_MINUTES)
    if purpose == TokenPurpose.email_verify:
        return timedelta(hours=settings.TOKEN_TTL_VERIFY_HOURS)
    return timedelta(minutes=settings.TOKEN_TTL_EMAIL_CHANGE_MINUTES)


def purpose_of(token: object, allowed: tuple[TokenPurpose, ...]) -> TokenPurpose | None:
    """Propósito según la FORMA del token (antes de hashear o consultar; REQ-T02/T04).
    None si no tiene un prefijo permitido, longitud 40-128 o solo base64url."""
    if not isinstance(token, str) or not 40 <= len(token) <= 128:
        return None
    for purpose in allowed:
        prefix = PREFIX[purpose]
        if token.startswith(prefix) and _BODY.match(token[len(prefix) :]):
            return purpose
    return None


async def issue(
    session: AsyncSession, user: User, purpose: TokenPurpose, email: str
) -> tuple[str, AccountToken]:
    """Crea un token (sin commit) y devuelve (token_en_claro, fila)."""
    now = utcnow()
    active = (
        await session.exec(
            select(AccountToken.id)
            .where(
                col(AccountToken.user_id) == user.id,
                col(AccountToken.purpose) == purpose,
                col(AccountToken.used_at).is_(None),
                col(AccountToken.expires_at) > now,
            )
            .order_by(col(AccountToken.created_at).desc())
        )
    ).all()
    stale = list(active[MAX_ACTIVE - 1 :])
    if stale:
        await session.execute(
            update(AccountToken).where(col(AccountToken.id).in_(stale)).values(used_at=now)
        )
    token = PREFIX[purpose] + secrets.token_urlsafe(32)
    row = AccountToken(
        user_id=user.id,
        purpose=purpose,
        token_hash=hash_token(token),
        email=email,
        created_at=now,
        expires_at=now + ttl(purpose),
    )
    session.add(row)
    await session.flush()
    return token, row


async def find_valid(
    session: AsyncSession, token: str, purpose: TokenPurpose
) -> tuple[AccountToken, User] | None:
    """Token vigente del propósito pedido y su usuario (sin consumirlo).

    Se rechaza si la cuenta está inactiva, si su email ya no es el del token (salvo en
    el cambio de email, donde el token lleva la dirección nueva) o si la contraseña se
    cambió después de emitirlo (REQ-T11)."""
    row = (
        await session.exec(
            select(AccountToken).where(
                col(AccountToken.token_hash) == hash_token(token),
                col(AccountToken.purpose) == purpose,
                col(AccountToken.used_at).is_(None),
                col(AccountToken.expires_at) > utcnow(),
            )
        )
    ).first()
    if row is None:
        return None
    user = await session.get(User, row.user_id)
    if user is None or not user.is_active:
        return None
    if purpose != TokenPurpose.email_change and user.email != row.email:
        return None
    if user.password_changed_at is not None and user.password_changed_at > row.created_at:
        return None
    return row, user


async def consume(session: AsyncSession, row_id: uuid.UUID, purpose: TokenPurpose) -> bool:
    """Marca el token como usado (sin commit). False si otra petición ganó (REQ-T07)."""
    result = await session.execute(
        update(AccountToken)
        .where(
            col(AccountToken.id) == row_id,
            col(AccountToken.purpose) == purpose,
            col(AccountToken.used_at).is_(None),
            col(AccountToken.expires_at) > utcnow(),
        )
        .values(used_at=utcnow())
    )
    return result.rowcount == 1


async def invalidate(
    session: AsyncSession, user_id: uuid.UUID, purposes: tuple[TokenPurpose, ...] | None = None
) -> None:
    """Invalida los tokens pendientes del usuario (sin commit; REQ-T08)."""
    query = update(AccountToken).where(
        col(AccountToken.user_id) == user_id, col(AccountToken.used_at).is_(None)
    )
    if purposes:
        query = query.where(col(AccountToken.purpose).in_(purposes))
    await session.execute(query.values(used_at=utcnow()))


async def prune(session: AsyncSession) -> tuple[int, int]:
    """Borra tokens usados/caducados hace más de un día y el registro de envíos de
    más de dos días (los cupos miran como mucho 24 h). Devuelve (tokens, registros)."""
    now = utcnow()
    day_ago = now - timedelta(days=1)
    tokens = await session.execute(
        delete(AccountToken).where(
            or_(col(AccountToken.expires_at) < day_ago, col(AccountToken.used_at) < day_ago)
        )
    )
    logs = await session.execute(
        delete(EmailLog).where(col(EmailLog.created_at) < now - timedelta(days=2))
    )
    await session.commit()
    return tokens.rowcount or 0, logs.rowcount or 0

"""Lógica de autenticación: login con bloqueo, emisión y rotación de tokens."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy import delete, update
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.audit import audit
from app.core.config import settings
from app.core.exceptions import EMAIL_NOT_VERIFIED, APIError
from app.core.permissions import ROLE_SCOPES, Role
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_token,
    looks_like_refresh_token,
    verify_password,
)
from app.db.types import utcnow, uuid7
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth import TokenPair

logger = logging.getLogger("app.security")

INVALID_CREDENTIALS = APIError(
    status.HTTP_401_UNAUTHORIZED,
    # Mensaje único: no revela si el email existe, si la cuenta está bloqueada o inactiva.
    "Invalid credentials or account temporarily locked",
    code="invalid_credentials",
    headers={"WWW-Authenticate": "Bearer"},
)
INVALID_REFRESH = APIError(
    status.HTTP_401_UNAUTHORIZED, "Invalid refresh token", code="invalid_refresh_token"
)
REFRESH_ROTATED = APIError(
    status.HTTP_409_CONFLICT,
    "Refresh token already rotated by a concurrent request; use the most recent refresh token",
    code="refresh_token_rotated",
)


def resolve_scopes(role: Role | str, requested: list[str] | None) -> list[str]:
    allowed = ROLE_SCOPES[Role(role)]
    if not requested:
        return sorted(allowed)
    granted = allowed & set(requested)
    if not granted:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid scope")
    return sorted(granted)


# ---------------------------------------------------------------------------
# Login y bloqueo de cuenta
# ---------------------------------------------------------------------------
async def authenticate(
    session: AsyncSession,
    email: str,
    password: str,
    *,
    client_ip: str | None = None,
    require_verified: bool = False,
) -> User:
    """Verifica credenciales aplicando "smart lockout".

    Tras LOGIN_MAX_ATTEMPTS fallos la cuenta se bloquea para orígenes
    desconocidos (el atacante distribuido sigue limitado a N intentos por
    ventana), pero el titular puede seguir entrando desde una IP en la que ya
    inició sesión (LOGIN_FAMILIAR_DAYS). Así un anónimo que solo conoce el email
    ya no puede dejar fuera a la víctima (SEC-02).
    """
    email = email.strip().lower()
    if (
        not email
        or len(email) > 320
        or "\x00" in email
        or len(password) > settings.PASSWORD_MAX_LENGTH
    ):
        await verify_password(password[:64], None)  # mismo coste que un intento real
        audit("auth.login.failure", reason="malformed", client_ip=client_ip)
        raise INVALID_CREDENTIALS

    user = (await session.exec(select(User).where(User.email == email))).first()
    now = utcnow()
    locked = user is not None and user.locked_until is not None and user.locked_until > now
    familiar = locked and await _is_familiar(session, user, client_ip, now)  # type: ignore[arg-type]
    # Cerramos la transacción ANTES de Argon2 (decenas de ms): así no retenemos una
    # conexión del pool ni un snapshot de lectura (en SQLite provocaría "database is
    # locked" al escribir después).
    await session.commit()

    if locked and not familiar:
        await verify_password(password, None)
        audit(
            "auth.login.blocked",
            level=logging.WARNING,
            user_id=user.id,  # type: ignore[union-attr]
            client_ip=client_ip,
        )
        raise INVALID_CREDENTIALS

    valid, new_hash = await verify_password(password, user.hashed_password if user else None)

    if user is None:
        audit("auth.login.failure", reason="unknown_user", client_ip=client_ip)
        raise INVALID_CREDENTIALS
    if not valid:
        await _register_failure(session, user, client_ip)
        raise INVALID_CREDENTIALS
    if not user.is_active:
        audit("auth.login.failure", reason="inactive", user_id=user.id, client_ip=client_ip)
        raise INVALID_CREDENTIALS
    if require_verified and user.email_verified_at is None:
        # Solo tras comprobar la contraseña (REQ-F12) y sin tocar last_login_at ni los
        # contadores: no ha iniciado sesión (UX-76).
        audit("auth.login.unverified", user_id=user.id, client_ip=client_ip)
        raise EMAIL_NOT_VERIFIED

    values: dict[str, object] = {"last_login_at": now}
    if not locked:
        # Solo un login correcto FUERA de un bloqueo reinicia el contador. Si el
        # titular entra desde una IP conocida durante un bloqueo, el bloqueo y el
        # escalado siguen vigentes para el resto de orígenes (SEC-20): si no, cada
        # login suyo regalaría al atacante otros N intentos.
        values.update(failed_login_attempts=0, locked_until=None)
    if new_hash:
        values["hashed_password"] = new_hash
    await session.execute(update(User).where(col(User.id) == user.id).values(**values))
    await session.commit()
    for key, value in values.items():
        setattr(user, key, value)
    audit("auth.login.success", user_id=user.id, client_ip=client_ip, while_locked=locked or None)
    return user


async def _is_familiar(
    session: AsyncSession, user: User, client_ip: str | None, now: datetime
) -> bool:
    """¿Ha iniciado sesión este usuario con contraseña desde este cliente hace poco?

    - Solo cuentan los tokens emitidos por un login (id == family_id), no los
      obtenidos por rotación: quien robe un refresh token no convierte su IP en
      "conocida".
    - Solo cuentan los logins posteriores al último cambio de contraseña: quien
      conociera la contraseña anterior no conserva una IP exenta del bloqueo.
    """
    if not client_ip or not settings.LOGIN_FAMILIAR_DAYS:
        return False
    since = now - timedelta(days=settings.LOGIN_FAMILIAR_DAYS)
    if user.password_changed_at is not None and user.password_changed_at > since:
        since = user.password_changed_at
    query = (
        select(RefreshToken.id)
        .where(
            col(RefreshToken.user_id) == user.id,
            col(RefreshToken.client_ip) == client_ip,
            col(RefreshToken.id) == col(RefreshToken.family_id),
            col(RefreshToken.created_at) >= since,
        )
        .limit(1)
    )
    return (await session.exec(query)).first() is not None


def lockout_minutes(attempts: int) -> int:
    """Duración del bloqueo: se dobla con cada bloqueo consecutivo, con tope."""
    strikes = attempts // settings.LOGIN_MAX_ATTEMPTS
    minutes = settings.LOGIN_LOCKOUT_MINUTES * 2 ** min(max(strikes - 1, 0), 16)
    return min(minutes, max(settings.LOGIN_LOCKOUT_MAX_MINUTES, settings.LOGIN_LOCKOUT_MINUTES))


async def _register_failure(session: AsyncSession, user: User, client_ip: str | None) -> None:
    # UPDATE atómico: peticiones concurrentes no pueden "perder" intentos fallidos.
    # El contador no se reinicia al bloquear (solo con un login correcto o un
    # desbloqueo de admin), así cada bloqueo consecutivo dura más.
    result = await session.execute(
        update(User)
        .where(col(User.id) == user.id)
        .values(failed_login_attempts=User.failed_login_attempts + 1)
        .returning(User.failed_login_attempts)
    )
    attempts = result.scalar_one()
    audit("auth.login.failure", reason="bad_password", user_id=user.id, client_ip=client_ip)
    if attempts >= settings.LOGIN_MAX_ATTEMPTS and attempts % settings.LOGIN_MAX_ATTEMPTS == 0:
        minutes = lockout_minutes(attempts)
        await session.execute(
            update(User)
            .where(col(User.id) == user.id)
            .values(locked_until=utcnow() + timedelta(minutes=minutes))
        )
        is_admin = user.role == Role.admin
        audit(
            "auth.account.locked",
            # Un admin bloqueado merece alerta: suele indicar un ataque dirigido.
            level=logging.ERROR if is_admin else logging.WARNING,
            user_id=user.id,
            client_ip=client_ip,
            attempts=attempts,
            minutes=minutes,
            admin=is_admin or None,
        )
    await session.commit()


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------
async def issue_tokens(
    session: AsyncSession,
    user: User,
    scopes: list[str],
    *,
    user_agent: str | None = None,
    client_ip: str | None = None,
    family_id: uuid.UUID | None = None,
    expires_at=None,
) -> tuple[TokenPair, RefreshToken]:
    access = create_access_token(
        subject=user.id, token_version=user.token_version, role=user.role, scopes=scopes
    )
    refresh_plain, refresh_hash = generate_refresh_token()
    token_id = uuid7()
    row = RefreshToken(
        id=token_id,
        user_id=user.id,
        # El primer token de una sesión (login) tiene id == family_id.
        family_id=family_id or token_id,
        token_hash=refresh_hash,
        scope=" ".join(scopes),
        user_agent=(user_agent or "")[:200] or None,
        client_ip=(client_ip or "")[:64] or None,
        expires_at=expires_at or utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    session.add(row)
    await session.flush()
    pair = TokenPair(
        access_token=access.token,
        refresh_token=refresh_plain,
        expires_in=access.expires_in,
        scope=" ".join(scopes),
    )
    return pair, row


async def start_session(
    session: AsyncSession,
    user: User,
    scopes: list[str],
    user_agent: str | None,
    client_ip: str | None = None,
) -> TokenPair:
    pair, _ = await issue_tokens(session, user, scopes, user_agent=user_agent, client_ip=client_ip)
    await _enforce_session_limit(session, user.id)
    # Limpieza oportunista de las filas caducadas de este usuario (SEC-23); el resto
    # de usuarios se purga con `apigen db prune`.
    await prune_refresh_tokens(session, user_id=user.id, commit=False)
    await session.commit()
    return pair


def _prune_filter(now: datetime):
    """Filas que ya no sirven para nada: su sesión está muerta (caducada o sin
    ningún token vivo en la familia) y son anteriores a LOGIN_FAMILIAR_DAYS.

    Las filas rotadas de una sesión viva se conservan: sin ellas no se detectaría
    la reutilización de un token robado.
    """
    sibling = RefreshToken.__table__.alias("sibling")  # type: ignore[attr-defined]
    alive = (
        select(sibling.c.id)
        .where(
            sibling.c.family_id == RefreshToken.family_id,
            sibling.c.revoked_at.is_(None),
            sibling.c.expires_at > now,
        )
        .exists()
    )
    cutoff = now - timedelta(days=settings.LOGIN_FAMILIAR_DAYS)
    return (col(RefreshToken.created_at) < cutoff) & ~alive


async def prune_refresh_tokens(
    session: AsyncSession, *, user_id: uuid.UUID | None = None, commit: bool = True
) -> int:
    """Borra refresh tokens inútiles (y con ellos la IP guardada). Devuelve cuántos."""
    query = delete(RefreshToken).where(_prune_filter(utcnow()))
    if user_id is not None:
        query = query.where(col(RefreshToken.user_id) == user_id)
    result = await session.execute(query)
    if commit:
        await session.commit()
    return result.rowcount or 0


async def _enforce_session_limit(session: AsyncSession, user_id: uuid.UUID) -> None:
    now = utcnow()
    active = (
        await session.exec(
            select(RefreshToken.family_id)
            .where(
                col(RefreshToken.user_id) == user_id,
                col(RefreshToken.revoked_at).is_(None),
                col(RefreshToken.expires_at) > now,
            )
            .order_by(col(RefreshToken.created_at).desc())
        )
    ).all()
    families = list(dict.fromkeys(active))
    stale = families[settings.MAX_SESSIONS_PER_USER :]
    if stale:
        await session.execute(
            update(RefreshToken)
            .where(col(RefreshToken.family_id).in_(stale), col(RefreshToken.revoked_at).is_(None))
            .values(revoked_at=now)
        )


async def rotate_refresh_token(
    session: AsyncSession, token: str, user_agent: str | None, client_ip: str | None = None
) -> TokenPair:
    if not looks_like_refresh_token(token):
        raise INVALID_REFRESH
    row = (
        await session.exec(select(RefreshToken).where(RefreshToken.token_hash == hash_token(token)))
    ).first()
    if row is None:
        raise INVALID_REFRESH
    # Copiamos los valores ANTES de cualquier rollback: un rollback expira las
    # instancias ORM y leerlas después fuerza una carga perezosa síncrona que en
    # async falla con MissingGreenlet (SEC-01).
    token_id, family_id, user_id = row.id, row.family_id, row.user_id
    expires_at, scope = row.expires_at, row.scope

    if row.revoked_at is not None:
        await _handle_revoked(session, token_id, family_id, user_id, client_ip)
    if expires_at <= utcnow():
        raise INVALID_REFRESH

    # Revocación atómica: si dos peticiones usan el mismo token a la vez, solo una gana.
    result = await session.execute(
        update(RefreshToken)
        .where(col(RefreshToken.id) == token_id, col(RefreshToken.revoked_at).is_(None))
        .values(revoked_at=utcnow())
    )
    if result.rowcount != 1:
        # Otra petición ganó la carrera: mismo tratamiento que una reutilización.
        await session.rollback()
        await _handle_revoked(session, token_id, family_id, user_id, client_ip)

    user = await session.get(User, user_id)
    if user is None or not user.is_active:
        await session.commit()
        raise INVALID_REFRESH
    if settings.email_verification == "required" and user.email_verified_at is None:
        # Ninguna vía emite tokens a una cuenta sin verificar (REQ-F12).
        await session.commit()
        raise INVALID_REFRESH

    scopes = resolve_scopes(user.role, scope.split() or None)
    pair, new_row = await issue_tokens(
        session,
        user,
        scopes,
        user_agent=user_agent,
        client_ip=client_ip,
        family_id=family_id,
        # Vida absoluta de la sesión: rotar no la alarga indefinidamente.
        expires_at=expires_at,
    )
    await session.execute(
        update(RefreshToken)
        .where(col(RefreshToken.id) == token_id)
        .values(replaced_by_id=new_row.id)
    )
    await session.commit()
    return pair


async def _handle_revoked(
    session: AsyncSession,
    token_id: uuid.UUID,
    family_id: uuid.UUID,
    user_id: uuid.UUID,
    client_ip: str | None,
) -> None:
    """Se ha presentado un refresh token ya revocado. Siempre lanza una excepción.

    - Revocado por logout/límite de sesiones (sin sucesor): 401 sin más.
    - Rotado hace <= REFRESH_REUSE_GRACE_SECONDS, desde la MISMA IP que obtuvo el
      sucesor y con la sesión viva: carrera legítima (dos pestañas, reintento
      tras timeout) -> 409 sin revocar ni emitir nada. Un atacante con el token
      robado no gana nada: no recibe tokens y, desde otra IP, dispara la revocación.
    - En cualquier otro caso es una reutilización (posible robo): se revoca la
      familia entera y se invalidan los access tokens del usuario (token_version).
    """
    replaced_by = (
        await session.exec(select(RefreshToken.replaced_by_id).where(RefreshToken.id == token_id))
    ).first()
    if replaced_by is None:
        await session.commit()
        raise INVALID_REFRESH

    grace = settings.REFRESH_REUSE_GRACE_SECONDS
    if grace and client_ip:
        successor = (
            await session.exec(
                select(
                    RefreshToken.created_at, RefreshToken.client_ip, RefreshToken.revoked_at
                ).where(RefreshToken.id == replaced_by)
            )
        ).first()
        if successor is not None:
            created_at, successor_ip, successor_revoked = successor
            recent = utcnow() - created_at <= timedelta(seconds=grace)
            if recent and successor_ip == client_ip and successor_revoked is None:
                await session.commit()
                audit(
                    "auth.refresh.concurrent",
                    user_id=user_id,
                    family_id=family_id,
                    client_ip=client_ip,
                )
                raise REFRESH_ROTATED

    audit(
        "auth.refresh.reuse",
        level=logging.WARNING,
        user_id=user_id,
        family_id=family_id,
        client_ip=client_ip,
    )
    await session.execute(
        update(User).where(col(User.id) == user_id).values(token_version=User.token_version + 1)
    )
    await revoke_family(session, family_id)
    raise INVALID_REFRESH


async def revoke_family(session: AsyncSession, family_id: uuid.UUID) -> None:
    await session.execute(
        update(RefreshToken)
        .where(col(RefreshToken.family_id) == family_id, col(RefreshToken.revoked_at).is_(None))
        .values(revoked_at=utcnow())
    )
    await session.commit()


async def revoke_by_token(session: AsyncSession, token: str) -> None:
    if not looks_like_refresh_token(token):
        return
    family_id = (
        await session.exec(
            select(RefreshToken.family_id).where(RefreshToken.token_hash == hash_token(token))
        )
    ).first()
    if family_id is not None:
        await revoke_family(session, family_id)


async def revoke_sessions(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Como revoke_all_sessions pero SIN commit: para hacerlo en la misma transacción
    que el cambio que lo motiva (reset, cambio de email; Info-1)."""
    await session.execute(
        update(User).where(col(User.id) == user_id).values(token_version=User.token_version + 1)
    )
    await session.execute(
        update(RefreshToken)
        .where(col(RefreshToken.user_id) == user_id, col(RefreshToken.revoked_at).is_(None))
        .values(revoked_at=utcnow())
    )


async def revoke_all_sessions(session: AsyncSession, user: User) -> None:
    """Invalida todos los access tokens (token_version) y refresh tokens del usuario."""
    await revoke_sessions(session, user.id)
    await session.commit()
    await session.refresh(user)

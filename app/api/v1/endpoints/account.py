"""Flujos de cuenta por correo: recuperar la contraseña y verificar el email.

- `forgot` y `resend` responden SIEMPRE 202 con el mismo cuerpo: solo encolan un
  trabajo de sistema; buscar la cuenta, aplicar el cupo y enviar lo hace el worker
  (REQ-E06/E07). La respuesta no revela si la cuenta existe, ni por el contenido ni
  por el tiempo.
- Los tokens se consumen solo por POST con el token en el cuerpo (los escáneres de
  correo abren los enlaces con GET; REQ-L04). Cualquier token malo, caducado, usado,
  de otro propósito o de una cuenta inactiva da el mismo 400 (REQ-F02/T04).
- Todas las respuestas llevan `Cache-Control: no-store` (SecurityHeadersMiddleware).
"""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response, status
from sqlalchemy import func, update
from sqlalchemy.exc import IntegrityError
from sqlmodel import col, select

from app.api.deps import PrincipalDep, SessionDep, error_responses
from app.core.audit import audit
from app.core.config import settings
from app.core.exceptions import APIError
from app.core.rate_limit import client_ip, ip_key, limiter
from app.core.security import hash_password, hash_token, password_problems
from app.db.types import utcnow
from app.email import enqueue_account_email, mask_email, request_language
from app.models.account_token import AccountToken, TokenPurpose
from app.models.user import User
from app.schemas.account import (
    AccountFeatures,
    EmailRequest,
    PasswordResetRequest,
    ResendVerificationRequest,
    TokenRequest,
)
from app.schemas.common import Message
from app.services import account_tokens
from app.services import auth as auth_service

router = APIRouter(prefix="/auth", tags=["account"])

INVALID_TOKEN = APIError(
    status.HTTP_400_BAD_REQUEST,
    "Invalid or expired token: ask for a new link",
    code="invalid_or_expired_token",
)
RESET_DISABLED = APIError(
    status.HTTP_403_FORBIDDEN, "Password reset is not enabled", code="password_reset_disabled"
)
VERIFICATION_DISABLED = APIError(
    status.HTTP_403_FORBIDDEN,
    "Email verification is not enabled",
    code="email_verification_disabled",
)
EMAIL_TAKEN = APIError(status.HTTP_409_CONFLICT, "Email already registered", code="email_taken")
FORGOT_ACCEPTED = Message(
    detail="If an account exists for that email, we have sent instructions to reset the password"
)
RESEND_ACCEPTED = Message(
    detail="If the account exists and is pending verification, we have sent a new link"
)
_TOKEN_ERRORS = {
    400: {"model": Message, "description": "`invalid_or_expired_token`: ask for a new link"}
}


def _reset_enabled() -> None:
    if not settings.password_reset_enabled:
        raise RESET_DISABLED


# `include_in_schema`: lo desactivado no aparece en /docs (ni en el README del cliente).
_RESET_DOCS = settings.password_reset_enabled
_VERIFY_DOCS = settings.account_emails_enabled


@router.get("/features", response_model=AccountFeatures)
async def features() -> AccountFeatures:
    """Flujos de cuenta que ofrece esta API: el frontend puede mostrar u ocultar
    "¿Olvidaste tu contraseña?" o el aviso de verificar el email sin hardcodearlo."""
    return AccountFeatures(
        registration=settings.ALLOW_REGISTRATION,
        email_verification=settings.email_verification,  # type: ignore[arg-type]
        password_reset=settings.password_reset_enabled,
        email_change=settings.account_emails_enabled,
    )


# --- Recuperación de contraseña -------------------------------------------------
@router.post(
    "/password/forgot",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=Message,
    responses=error_responses(403, 429),
    include_in_schema=_RESET_DOCS,
)
@limiter.limit(settings.RATE_LIMIT_EMAIL_REQUEST, key_func=ip_key)
async def forgot_password(
    request: Request,
    response: Response,
    payload: EmailRequest,
    session: SessionDep,
    background: BackgroundTasks,
) -> Message:
    """Pide un enlace para restablecer la contraseña. Responde siempre 202, exista o no
    la cuenta (el correo solo sale si existe y está activa)."""
    _reset_enabled()
    await enqueue_account_email(
        session,
        "auth.password_reset",
        {"email": payload.email, "lang": request_language(request)},
        background,
    )
    audit("auth.password_reset.requested", client_ip=client_ip(request))
    return FORGOT_ACCEPTED


@router.post(
    "/password/reset/validate",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={**_TOKEN_ERRORS, **error_responses(403, 429)},
    include_in_schema=_RESET_DOCS,
)
@limiter.limit(settings.RATE_LIMIT_TOKEN_CONFIRM, key_func=ip_key)
async def validate_reset_token(
    request: Request, response: Response, payload: TokenRequest, session: SessionDep
) -> None:
    """Comprueba (sin consumirlo) si el enlace sigue valiendo: la página del frontend
    puede decir "el enlace ha caducado" antes de pedir la contraseña nueva."""
    _reset_enabled()
    found = None
    if account_tokens.purpose_of(payload.token, (TokenPurpose.password_reset,)):
        found = await account_tokens.find_valid(session, payload.token, TokenPurpose.password_reset)
    await session.commit()
    if found is None:
        raise INVALID_TOKEN


@router.post(
    "/password/reset",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={**_TOKEN_ERRORS, **error_responses(403, 429)},
    include_in_schema=_RESET_DOCS,
)
@limiter.limit(settings.RATE_LIMIT_TOKEN_CONFIRM, key_func=ip_key)
async def reset_password(
    request: Request,
    response: Response,
    payload: PasswordResetRequest,
    session: SessionDep,
    background: BackgroundTasks,
) -> None:
    """Fija la contraseña nueva con el token del correo (un solo uso).

    Cierra todas las sesiones, desbloquea la cuenta si estaba bloqueada, marca el email
    como verificado y envía un aviso de "contraseña cambiada". No inicia sesión.
    Una contraseña que no cumple la política da 422 y el enlace sigue valiendo."""
    _reset_enabled()
    ip = client_ip(request)
    purpose = TokenPurpose.password_reset
    found = None
    if account_tokens.purpose_of(payload.token, (purpose,)):
        found = await account_tokens.find_valid(session, payload.token, purpose)
    if found is None:
        await session.commit()
        audit("auth.password_reset.invalid_token", client_ip=ip)
        raise INVALID_TOKEN
    row, user = found
    problems = password_problems(payload.new_password, user.email)
    if problems:
        await session.commit()
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=[
                {"loc": ["body", "new_password"], "msg": f"Password {p}", "type": "password_policy"}
                for p in problems
            ],
        )
    row_id, user_id = row.id, user.id
    await session.commit()  # libera la conexión mientras se calcula Argon2
    new_hash = await hash_password(payload.new_password)

    # Consumo atómico y cambio de contraseña en la MISMA transacción (REQ-T07).
    if not await account_tokens.consume(session, row_id, purpose):
        await session.rollback()
        audit("auth.password_reset.invalid_token", client_ip=ip, user_id=user_id)
        raise INVALID_TOKEN
    now = utcnow()
    lang = request_language(request)
    values: dict[str, object] = {
        "hashed_password": new_hash,
        "password_changed_at": now,
        # Completar el reset prueba el control del email (D2, REQ-S05): se desbloquea
        # en silencio y el email queda verificado.
        "failed_login_attempts": 0,
        "locked_until": None,
        "email_verified_at": func.coalesce(User.email_verified_at, now),
    }
    if lang:
        values["locale"] = lang  # quien tiene el enlace controla el buzón (UX-77)
    await session.execute(update(User).where(col(User.id) == user_id).values(**values))
    await account_tokens.invalidate(session, user_id, (purpose,))
    # Sesiones revocadas y aviso encolado en la MISMA transacción (Info-1).
    await auth_service.revoke_sessions(session, user_id)
    await enqueue_account_email(
        session,
        "auth.notice",
        {"user_id": str(user_id), "kind": "password_changed", "lang": lang},
        background,
        commit=False,
    )
    await session.commit()
    audit("auth.password_reset.completed", user_id=user_id, client_ip=ip)


# --- Verificación de email (alta y cambio de email) -------------------------------
async def _already_done(session: SessionDep, token: str, purpose: TokenPurpose) -> bool:
    """¿Es un token ya usado cuya verificación ya está hecha? Pulsar dos veces el enlace
    (o que el cliente de correo lo precargue) cuenta como éxito (F-08)."""
    row = (
        await session.exec(
            select(AccountToken).where(
                col(AccountToken.token_hash) == hash_token(token),
                col(AccountToken.purpose) == purpose,
                col(AccountToken.used_at).is_not(None),
            )
        )
    ).first()
    if row is None:
        return False
    user = await session.get(User, row.user_id)
    return (
        user is not None
        and user.is_active
        and user.email == row.email
        and user.email_verified_at is not None
    )


@router.post(
    "/email/verify",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={**_TOKEN_ERRORS, **error_responses(403, 409, 429)},
    include_in_schema=_VERIFY_DOCS,
)
@limiter.limit(settings.RATE_LIMIT_TOKEN_CONFIRM, key_func=ip_key)
async def verify_email(
    request: Request,
    response: Response,
    payload: TokenRequest,
    session: SessionDep,
    background: BackgroundTasks,
) -> None:
    """Confirma el email con el token del correo: el del alta o el del cambio de email.

    No inicia sesión. Verificar dos veces cuenta como éxito (204)."""
    if not settings.account_emails_enabled:
        raise VERIFICATION_DISABLED
    ip = client_ip(request)
    purpose = account_tokens.purpose_of(
        payload.token, (TokenPurpose.email_verify, TokenPurpose.email_change)
    )
    found = await account_tokens.find_valid(session, payload.token, purpose) if purpose else None
    if found is None:
        if purpose and await _already_done(session, payload.token, purpose):
            await session.commit()
            return None
        await session.commit()
        audit("auth.email_verification.invalid_token", client_ip=ip)
        raise INVALID_TOKEN
    row, user = found
    row_id, user_id, target, old_email = row.id, user.id, row.email, user.email
    old_verified = user.email_verified_at is not None
    lang = request_language(request)
    if not await account_tokens.consume(session, row_id, purpose):  # type: ignore[arg-type]
        await session.rollback()
        if await _already_done(session, payload.token, purpose):  # type: ignore[arg-type]
            return None
        raise INVALID_TOKEN
    now = utcnow()
    if purpose == TokenPurpose.email_verify:
        values: dict[str, object] = {
            "email_verified_at": func.coalesce(User.email_verified_at, now)
        }
        if lang:
            values["locale"] = lang
        await session.execute(update(User).where(col(User.id) == user_id).values(**values))
        await account_tokens.invalidate(session, user_id, (TokenPurpose.email_verify,))
        await session.commit()
        audit("auth.email_verification.verified", user_id=user_id, client_ip=ip)
        return None

    # Cambio de email: la unicidad se vuelve a comprobar ahora (y UNIQUE lo garantiza).
    try:
        await session.execute(
            update(User).where(col(User.id) == user_id).values(email=target, email_verified_at=now)
        )
        # Todo lo pendiente iba ligado al email anterior (REQ-T08).
        await account_tokens.invalidate(session, user_id)
        # Sesiones y aviso en la misma transacción que el cambio (Info-1).
        await auth_service.revoke_sessions(session, user_id)
        await enqueue_account_email(
            session,
            "auth.notice",
            {
                "user_id": str(user_id),
                "kind": "email_changed",
                "old_email": old_email,
                # Sin texto libre del usuario si la dirección antigua nunca se probó (SEC-42).
                "old_verified": old_verified,
                "new_email_masked": mask_email(target),
                "lang": lang,
            },
            background,
            commit=False,
        )
        await session.commit()
    except IntegrityError:
        await session.rollback()
        raise EMAIL_TAKEN from None
    audit("auth.email_change.completed", user_id=user_id, client_ip=ip)


@router.post(
    "/email/verify/resend",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=Message,
    responses=error_responses(403, 429),
    include_in_schema=settings.email_verification != "off",
)
@limiter.limit(settings.RATE_LIMIT_EMAIL_REQUEST, key_func=ip_key)
async def resend_verification(
    request: Request,
    response: Response,
    session: SessionDep,
    background: BackgroundTasks,
    principal: PrincipalDep,
    payload: ResendVerificationRequest | None = None,
) -> Message:
    """Reenvía el enlace de verificación. Con sesión, sin cuerpo; sin sesión (modo
    `required`, en el que no se puede iniciar sesión), con `{"email": ...}`.
    Responde siempre 202 con el mismo cuerpo."""
    if settings.email_verification == "off":
        raise VERIFICATION_DISABLED
    if principal.user is not None:
        target: dict[str, str] = {"user_id": str(principal.user.id)}
    elif payload is not None and payload.email:
        target = {"email": payload.email}
    else:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=[
                {
                    "loc": ["body", "email"],
                    "msg": "Field required when not authenticated",
                    "type": "missing",
                }
            ],
        )
    await enqueue_account_email(
        session,
        "auth.email_verification",
        {**target, "lang": request_language(request)},
        background,
    )
    audit(
        "auth.email_verification.requested",
        user_id=principal.user_id,
        client_ip=client_ip(request),
    )
    return RESEND_ACCEPTED

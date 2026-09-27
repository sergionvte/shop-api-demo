"""Tareas de correo: envío genérico (`email.send`) y correos de los flujos de cuenta.

El token de un solo uso se genera AQUÍ, justo antes de enviar: nunca pasa por
`jobs.payload` ni por la respuesta de la API (REQ-T10/Q02). Antes de enviar:

1. Idempotencia: si este trabajo ya se envió (`email_log.sent_at`), no se repite.
2. Cortacircuitos global (EMAIL_MAX_PER_HOUR/DAY).
3. Revalidación: la cuenta existe, está activa, el email no cambió y la petición no es
   más antigua que la vida del token (REQ-Q07).
4. Cupo por cuenta (60 s / 3 por hora / 10 al día por defecto; REQ-R02), que se aplica
   aquí con datos de la BD y no depende de la IP.
Lo descartado termina `succeeded` con `{"status": "suppressed"}` y se audita.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import func, update
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.audit import audit
from app.core.config import settings
from app.db.types import utcnow
from app.email import mask_email
from app.email.backends import PermanentEmailError, TransientEmailError, get_backend
from app.email.links import build_link
from app.email.message import EmailMessage, message_id_for
from app.email.render import TEMPLATE_NAME, TemplateError, format_duration, render
from app.models.account_token import TokenPurpose
from app.models.email_log import EmailLog
from app.models.user import User
from app.services import account_tokens
from app.tasks.registry import TaskContext, TaskError, task

logger = logging.getLogger("app.email")

# Cupos por cuenta (REQ-R02/R03). Los correos que un tercero puede provocar sin sesión
# (forgot, resend, registro repetido) comparten un cupo; la confirmación de un cambio de
# email (con sesión y contraseña) tiene el suyo, para no bloquear al titular.
QUOTA_GROUPS = (
    ("password_reset", "verify_email", "account_exists"),
    ("email_change_confirm",),
)
# Correos de seguridad: su propio presupuesto en el cortacircuitos global, para que las
# altas masivas o los correos propios no los bloqueen (SEC-40).
SECURITY_KINDS = ("password_reset", "password_changed", "email_change_requested", "email_changed")
NOTICES = ("password_changed", "email_change_requested", "email_changed")
# Nombres de los eventos de auditoría de envío (REQ-G03).
SENT_EVENTS = {
    "verify_email": "auth.email_verification.sent",
    "password_reset": "auth.password_reset.sent",
    "email_change_confirm": "auth.email_change.sent",
}
# Por debajo del arrendamiento (timeout + JOBS_LEASE_GRACE) y por encima de SMTP_TIMEOUT.
EMAIL_TASK_TIMEOUT = 120


class _Payload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lang: str | None = Field(default=None, max_length=50)
    requested_at: datetime | None = None


class EmailPayload(_Payload):
    email: EmailStr = Field(max_length=320)


class VerificationPayload(_Payload):
    user_id: uuid.UUID | None = None
    email: EmailStr | None = Field(default=None, max_length=320)


class EmailChangePayload(_Payload):
    user_id: uuid.UUID
    new_email: EmailStr = Field(max_length=320)


class NoticePayload(_Payload):
    user_id: uuid.UUID
    kind: str = Field(pattern="^(password_changed|email_change_requested|email_changed)$")
    new_email_masked: str | None = Field(default=None, max_length=330)
    # Solo en `email_changed`: la dirección ANTIGUA (ya no es users.email) y si estaba
    # verificada: si no, el aviso no lleva texto libre del usuario (SEC-42, REQ-M06).
    old_email: EmailStr | None = Field(default=None, max_length=320)
    old_verified: bool = False


class SendEmailPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    to: list[EmailStr] = Field(min_length=1, max_length=10)
    template: str = Field(pattern=TEMPLATE_NAME.pattern)
    context: dict[str, Any] = Field(default_factory=dict)
    lang: str | None = Field(default=None, max_length=50)


# ---------------------------------------------------------------------------
# Piezas comunes
# ---------------------------------------------------------------------------
class _Suppressed(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason


def _suppress(reason: str, kind: str, ctx: TaskContext, user_id: uuid.UUID | None = None):
    if reason in {"quota", "cooldown", "address_quota"} and not settings.is_production:
        # En desarrollo, que no parezca que "el correo no llega" sin motivo (UX-70).
        logger.warning(
            "correo NO enviado (%s, %s): cupo por cuenta (%s/h, %s s entre correos). Para "
            "pruebas, sube EMAIL_PER_ACCOUNT_PER_HOUR o baja EMAIL_PER_ACCOUNT_COOLDOWN_SECONDS",
            kind,
            reason,
            settings.EMAIL_PER_ACCOUNT_PER_HOUR,
            settings.EMAIL_PER_ACCOUNT_COOLDOWN_SECONDS,
        )
    audit(
        "email.suppressed",
        level=logging.ERROR if reason == "circuit_open" else logging.INFO,
        reason=reason,
        kind=kind,
        user_id=user_id,
        job_id=ctx.job_id,
    )
    return {"status": "suppressed", "reason": reason}


def _stale(payload: _Payload, lifetime: timedelta) -> bool:
    return payload.requested_at is not None and utcnow() - payload.requested_at > lifetime


async def _user_by_email(session: AsyncSession, email: str) -> User | None:
    return (await session.exec(select(User).where(User.email == email.lower()))).first()


async def _count_since(session: AsyncSession, since: datetime, *conditions) -> int:
    query = select(func.count()).select_from(EmailLog).where(col(EmailLog.created_at) >= since)
    return (await session.exec(query.where(*conditions))).one()


def recipient_hash(address: str) -> str:
    """Seudónimo de la dirección para el cupo por destino (nunca la dirección en claro)."""
    return hashlib.sha256(address.strip().lower().encode()).hexdigest()


async def _circuit_open(session: AsyncSession, kind: str) -> bool:
    """Cortacircuitos global con dos presupuestos: seguridad y el resto (SEC-40)."""
    now = utcnow()
    security = kind in SECURITY_KINDS
    in_bucket = (
        col(EmailLog.kind).in_(SECURITY_KINDS)
        if security
        else col(EmailLog.kind).not_in(SECURITY_KINDS)
    )
    per_hour = settings.EMAIL_MAX_SECURITY_PER_HOUR if security else settings.EMAIL_MAX_PER_HOUR
    per_day = settings.EMAIL_MAX_SECURITY_PER_DAY if security else settings.EMAIL_MAX_PER_DAY
    sent = col(EmailLog.sent_at).is_not(None)
    for limit, window in ((per_hour, timedelta(hours=1)), (per_day, timedelta(days=1))):
        if limit and await _count_since(session, now - window, sent, in_bucket) >= limit:
            return True
    return False


def _limits(kind: str) -> tuple[tuple[str, ...], int, int, int]:
    """(grupo, enfriamiento s, por hora, por día) del cupo por cuenta de este tipo."""
    if kind in NOTICES:
        hourly = settings.EMAIL_NOTICES_PER_ACCOUNT_PER_HOUR
        return NOTICES, 0, hourly, hourly * 4
    group = next((g for g in QUOTA_GROUPS if kind in g), (kind,))
    return (
        group,
        settings.EMAIL_PER_ACCOUNT_COOLDOWN_SECONDS or 0,
        settings.EMAIL_PER_ACCOUNT_PER_HOUR or 3,
        settings.EMAIL_PER_ACCOUNT_PER_DAY or 10,
    )


async def _quota_reason(
    session: AsyncSession, user_id: uuid.UUID, kind: str, recipient: str | None
) -> str | None:
    now = utcnow()
    group, cooldown, hourly, daily = _limits(kind)
    mine = (col(EmailLog.user_id) == user_id, col(EmailLog.kind).in_(group))
    if cooldown and await _count_since(session, now - timedelta(seconds=cooldown), *mine):
        return "cooldown"
    if await _count_since(session, now - timedelta(hours=1), *mine) >= hourly:
        return "quota"
    if await _count_since(session, now - timedelta(days=1), *mine) >= daily:
        return "quota"
    if kind == "email_change_confirm" and recipient:
        # Direcciones de TERCEROS elegidas por el usuario: cupo por destino (SEC-40).
        same = (
            col(EmailLog.kind) == kind,
            col(EmailLog.recipient_hash) == recipient_hash(recipient),
        )
        if await _count_since(session, now - timedelta(hours=1), *same) >= (
            settings.EMAIL_PER_ADDRESS_PER_HOUR
        ):
            return "address_quota"
    return None


async def _lock_account(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Serializa el cupo por cuenta entre trabajos simultáneos (SEC-41): un UPDATE inocuo
    de la fila del usuario bloquea la fila en PostgreSQL y toma el bloqueo de escritura en
    SQLite hasta el commit, antes de contar."""
    await session.execute(
        update(User).where(col(User.id) == user_id).values(updated_at=User.updated_at)
    )


async def _gate(
    session: AsyncSession,
    ctx: TaskContext,
    kind: str,
    user_id: uuid.UUID | None,
    *,
    quota: bool,
    recipient: str | None = None,
) -> uuid.UUID:
    """Idempotencia, cortacircuitos y cupo. Devuelve el id del registro de envío o lanza
    _Suppressed. Un reintento del mismo trabajo no vuelve a consumir cupo. El llamador
    hace commit enseguida (libera el bloqueo de la cuenta antes de enviar)."""
    if quota and user_id is not None:
        await _lock_account(session, user_id)
    log = (await session.exec(select(EmailLog).where(col(EmailLog.job_id) == ctx.job_id))).first()
    if log is not None and log.sent_at is not None:
        raise _Suppressed("already_sent")
    if await _circuit_open(session, kind):
        _suppress("circuit_open", kind, ctx, user_id)  # nivel ERROR (REQ-G03/G06)
        # Se reintenta más tarde (backoff de la cola); al agotarlo, el trabajo falla.
        raise TaskError("Email sending paused: hourly/daily limit reached", retry=True)
    if log is not None:
        return log.id
    if quota and user_id is not None:
        if reason := await _quota_reason(session, user_id, kind, recipient):
            raise _Suppressed(reason)
    log = EmailLog(
        job_id=ctx.job_id,
        user_id=user_id,
        kind=kind,
        recipient_hash=recipient_hash(recipient) if recipient else None,
    )
    session.add(log)
    await session.flush()
    return log.id


async def _deliver(ctx: TaskContext, kind: str, to: str | list[str], rendered) -> None:
    recipients = tuple([to] if isinstance(to, str) else to)
    message = EmailMessage(
        to=recipients,
        subject=rendered.subject,
        text=rendered.text,
        html=rendered.html,
        message_id=message_id_for(str(ctx.job_id)),
    )
    backend = get_backend()
    try:
        await backend.send(message)
    except TransientEmailError as exc:
        audit(
            "email.send.failed",
            level=logging.WARNING,
            backend=backend.name,
            error=exc.code,
            kind=kind,
            job_id=ctx.job_id,
        )
        raise TaskError("Email delivery failed (transient)", retry=True) from None
    except (PermanentEmailError, ValueError) as exc:
        code = getattr(exc, "code", "invalid_message")
        audit(
            "email.send.failed",
            # Credenciales rechazadas o sin STARTTLS: hay que avisar a alguien (REQ-G06).
            level=logging.ERROR,
            backend=backend.name,
            error=code,
            kind=kind,
            job_id=ctx.job_id,
        )
        raise TaskError("Email delivery failed (permanent)", retry=False) from None


async def _mark_sent(ctx: TaskContext, log_id: uuid.UUID) -> None:
    async with ctx.session() as session:
        await session.execute(
            update(EmailLog).where(col(EmailLog.id) == log_id).values(sent_at=utcnow())
        )
        await session.commit()


def _render(name: str, lang: str | None, context: dict[str, Any]):
    try:
        return render(name, lang, context)
    except TemplateError:
        logger.exception("email template error")
        raise TaskError("Email template error", retry=False) from None


def _user_name(user: User) -> str:
    # Texto libre del usuario solo hacia direcciones ya probadas (REQ-M06/M07).
    return (user.full_name or "")[:120] if user.email_verified_at else ""


async def _send_token_email(
    ctx: TaskContext,
    *,
    kind: str,
    purpose: TokenPurpose,
    template: str,
    link: str,
    user_id: uuid.UUID,
    to: str,
    lang: str | None,
    session: AsyncSession,
) -> dict[str, Any]:
    """Tras la revalidación: cupo, token nuevo, correo y `sent_at`."""
    try:
        log_id = await _gate(session, ctx, kind, user_id, quota=True, recipient=to)
    except _Suppressed as exc:
        await session.commit()
        return _suppress(exc.reason, kind, ctx, user_id)
    user = await session.get(User, user_id)
    assert user is not None
    token, _ = await account_tokens.issue(session, user, purpose, to)
    await session.commit()
    minutes = int(account_tokens.ttl(purpose).total_seconds() // 60)
    rendered = _render(
        template,
        lang,
        {
            "action_url": build_link(link, token),  # type: ignore[arg-type]
            "expires_in": format_duration(minutes, lang or settings.MAIL_DEFAULT_LANGUAGE),
        },
    )
    del token
    await _deliver(ctx, kind, to, rendered)
    await _mark_sent(ctx, log_id)
    audit(SENT_EVENTS.get(kind, f"auth.{kind}.sent"), user_id=user_id, job_id=ctx.job_id)
    return {"status": "sent"}


# ---------------------------------------------------------------------------
# Tareas
# ---------------------------------------------------------------------------
@task(
    "auth.password_reset",
    max_attempts=5,
    timeout=EMAIL_TASK_TIMEOUT,
    payload_model=EmailPayload,
    scrub_payload=True,
)
async def password_reset(ctx: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Correo con el enlace para restablecer la contraseña."""
    data = EmailPayload.model_validate(payload)
    kind = "password_reset"
    async with ctx.session() as session:
        user = await _user_by_email(session, data.email)
        if user is None:
            return _suppress("unknown_email", kind, ctx)  # sin la dirección (REQ-G04)
        if not user.is_active:
            return _suppress("inactive", kind, ctx, user.id)
        if _stale(data, account_tokens.ttl(TokenPurpose.password_reset)):
            return _suppress("stale", kind, ctx, user.id)
        return await _send_token_email(
            ctx,
            kind=kind,
            purpose=TokenPurpose.password_reset,
            template="password_reset",
            link="reset",
            user_id=user.id,
            to=user.email,  # la de la BD, nunca la tecleada (REQ-E10)
            lang=data.lang or user.locale,
            session=session,
        )


@task(
    "auth.email_verification",
    max_attempts=5,
    timeout=EMAIL_TASK_TIMEOUT,
    payload_model=VerificationPayload,
    scrub_payload=True,
)
async def email_verification(ctx: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Correo con el enlace para verificar el email."""
    data = VerificationPayload.model_validate(payload)
    kind = "verify_email"
    async with ctx.session() as session:
        if data.user_id is not None:
            user = await session.get(User, data.user_id)
        elif data.email is not None:
            user = await _user_by_email(session, data.email)
        else:
            user = None
        if user is None:
            return _suppress("unknown_email", kind, ctx)
        if not user.is_active:
            return _suppress("inactive", kind, ctx, user.id)
        if user.email_verified_at is not None:
            return _suppress("already_verified", kind, ctx, user.id)
        if _stale(data, account_tokens.ttl(TokenPurpose.email_verify)):
            return _suppress("stale", kind, ctx, user.id)
        return await _send_token_email(
            ctx,
            kind=kind,
            purpose=TokenPurpose.email_verify,
            template="verify_email",
            link="verify",
            user_id=user.id,
            to=user.email,
            lang=data.lang or user.locale,
            session=session,
        )


@task(
    "auth.account_exists",
    max_attempts=5,
    timeout=EMAIL_TASK_TIMEOUT,
    payload_model=EmailPayload,
    scrub_payload=True,
)
async def account_exists(ctx: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Aviso "ya tienes cuenta" cuando alguien se registra con un email existente."""
    data = EmailPayload.model_validate(payload)
    kind = "account_exists"
    async with ctx.session() as session:
        user = await _user_by_email(session, data.email)
        if user is None:
            return _suppress("unknown_email", kind, ctx)
        if not user.is_active:
            return _suppress("inactive", kind, ctx, user.id)
        if _stale(data, timedelta(hours=1)):
            return _suppress("stale", kind, ctx, user.id)
        try:
            log_id = await _gate(session, ctx, kind, user.id, quota=True)
        except _Suppressed as exc:
            await session.commit()
            return _suppress(exc.reason, kind, ctx, user.id)
        to, user_id, lang = user.email, user.id, data.lang or user.locale
        await session.commit()
    # Sin texto libre del usuario: la dirección puede no ser suya (REQ-M06).
    rendered = _render(kind, lang, {"password_reset": settings.password_reset_enabled})
    await _deliver(ctx, kind, to, rendered)
    await _mark_sent(ctx, log_id)
    audit("auth.account_exists.sent", user_id=user_id, job_id=ctx.job_id)
    return {"status": "sent"}


@task(
    "auth.email_change",
    max_attempts=5,
    timeout=EMAIL_TASK_TIMEOUT,
    payload_model=EmailChangePayload,
    scrub_payload=True,
)
async def email_change(ctx: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Enlace de confirmación a la dirección NUEVA y aviso a la antigua."""
    from app.email import enqueue_account_email

    data = EmailChangePayload.model_validate(payload)
    kind = "email_change_confirm"
    new_email = data.new_email.lower()
    async with ctx.session() as session:
        user = await session.get(User, data.user_id)
        if user is None or not user.is_active:
            return _suppress("inactive", kind, ctx, data.user_id)
        if _stale(data, account_tokens.ttl(TokenPurpose.email_change)):
            return _suppress("stale", kind, ctx, user.id)
        first_attempt = (
            await session.exec(select(EmailLog.id).where(col(EmailLog.job_id) == ctx.job_id))
        ).first() is None
        notice_job = None
        if first_attempt:
            # Aviso a la dirección antigua (REQ-F23), como trabajo aparte: su envío y
            # sus reintentos no afectan a la confirmación.
            notice_job = await enqueue_account_email(
                session,
                "auth.notice",
                {
                    "user_id": str(user.id),
                    "kind": "email_change_requested",
                    "new_email_masked": mask_email(new_email),
                    "lang": data.lang or user.locale,
                },
                commit=False,
            )
        taken = await _user_by_email(session, new_email)
        if taken is not None and taken.id != user.id:
            await session.commit()
            result = _suppress("email_taken", kind, ctx, user.id)
        else:
            result = await _send_token_email(
                ctx,
                kind=kind,
                purpose=TokenPurpose.email_change,
                template="email_change_confirm",
                link="verify",
                user_id=user.id,
                to=new_email,
                lang=data.lang or user.locale,
                session=session,
            )
    if notice_job is not None and settings.email_delivery == "inline":
        from app.tasks.worker import run_now

        await run_now(notice_job)  # desarrollo sin worker: el aviso sale también
    return result


@task(
    "auth.notice",
    max_attempts=5,
    timeout=EMAIL_TASK_TIMEOUT,
    payload_model=NoticePayload,
    scrub_payload=True,
)
async def notice(ctx: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Avisos de seguridad sin enlaces de acción: contraseña o email cambiados."""
    data = NoticePayload.model_validate(payload)
    async with ctx.session() as session:
        user = await session.get(User, data.user_id)
        if user is None:
            return _suppress("unknown_user", data.kind, ctx)
        to = str(data.old_email) if data.kind == "email_changed" and data.old_email else user.email
        try:
            # Con cupo por cuenta: pedir cambios de email en bucle no bombardea (SEC-40).
            log_id = await _gate(session, ctx, data.kind, user.id, quota=True)
        except _Suppressed as exc:
            await session.commit()
            return _suppress(exc.reason, data.kind, ctx, user.id)
        if data.kind == "email_changed":
            name = (user.full_name or "")[:120] if data.old_verified else ""
        else:
            name = _user_name(user)
        lang = data.lang or user.locale
        context = {
            "user_name": name,
            "changed_at": f"{utcnow():%Y-%m-%d %H:%M} UTC",
            "new_email": data.new_email_masked or mask_email(user.email),
        }
        user_id = user.id
        await session.commit()
    rendered = _render(data.kind, lang, context)
    await _deliver(ctx, data.kind, to, rendered)
    await _mark_sent(ctx, log_id)
    audit(f"auth.{data.kind}.sent", user_id=user_id, job_id=ctx.job_id)
    return {"status": "sent"}


@task(
    "email.send",
    max_attempts=5,
    timeout=EMAIL_TASK_TIMEOUT,
    payload_model=SendEmailPayload,
    scrub_payload=True,
)
async def send(ctx: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Envío genérico con una plantilla (de serie o de EMAIL_TEMPLATES_DIR)."""
    data = SendEmailPayload.model_validate(payload)
    kind = f"custom:{data.template}"[:40]
    async with ctx.session() as session:
        try:
            log_id = await _gate(session, ctx, kind, None, quota=False)
        except _Suppressed as exc:
            await session.commit()
            return _suppress(exc.reason, kind, ctx)
        await session.commit()
    rendered = _render(data.template, data.lang, data.context)
    await _deliver(ctx, kind, [str(address) for address in data.to], rendered)
    await _mark_sent(ctx, log_id)
    return {"status": "sent", "recipients": len(data.to)}

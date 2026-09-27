from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from sqlalchemy import func
from sqlmodel import col, select

from app.api.deps import AdminPrincipal, PaginationDep, Principal, SessionDep, require
from app.core.audit import audit
from app.core.config import settings
from app.core.exceptions import APIError
from app.core.permissions import Access, Role, Scope
from app.core.rate_limit import client_ip, limiter
from app.core.security import hash_password, password_problems, verify_password
from app.crud.base import Repository
from app.db.types import utcnow
from app.email import enqueue_account_email, request_language
from app.models.account_token import TokenPurpose
from app.models.user import User
from app.schemas.account import EmailChangeRequest
from app.schemas.common import Message, Page
from app.schemas.user import (
    PasswordChange,
    UserAdminCreate,
    UserAdminRead,
    UserAdminUpdate,
    UserRead,
    UserUpdateMe,
)
from app.services import account_tokens
from app.services import auth as auth_service

router = APIRouter(prefix="/users", tags=["users"])
repo = Repository(
    User, search_fields=("email", "full_name"), ordering_fields=("email", "created_at")
)

EMAIL_CHANGE_ACCEPTED = Message(
    detail="If the address is available, we have sent a confirmation link to it"
)
LAST_ADMIN = APIError(status.HTTP_409_CONFLICT, "Cannot remove the last admin", code="last_admin")

ReadMe = Annotated[Principal, Depends(require(Access.user, Scope.read))]
WriteMe = Annotated[Principal, Depends(require(Access.user, Scope.write))]


# --- Cuenta propia ------------------------------------------------------------
@router.get("/me", response_model=UserRead)
async def read_me(principal: ReadMe) -> User:
    return principal.user  # type: ignore[return-value]


@router.patch("/me", response_model=UserRead)
async def update_me(principal: WriteMe, payload: UserUpdateMe, session: SessionDep) -> User:
    return await repo.update(session, principal.user, payload)  # type: ignore[arg-type]


@router.post("/me/password", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def change_password(
    request: Request,
    response: Response,
    principal: WriteMe,
    payload: PasswordChange,
    session: SessionDep,
    background: BackgroundTasks,
) -> None:
    """Cambia la contraseña y cierra todas las sesiones (hay que volver a hacer login)."""
    user = principal.user
    assert user is not None
    await session.commit()  # libera la conexión mientras se calcula Argon2
    valid, _ = await verify_password(payload.current_password, user.hashed_password)
    if not valid:
        raise APIError(
            status.HTTP_400_BAD_REQUEST, "Current password is incorrect", code="wrong_password"
        )
    problems = password_problems(payload.new_password, user.email)
    if problems:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=[
                {"loc": ["body", "new_password"], "msg": f"Password {p}", "type": "password_policy"}
                for p in problems
            ],
        )
    user.hashed_password = await hash_password(payload.new_password)
    user.password_changed_at = utcnow()
    session.add(user)
    # Los enlaces de recuperación pendientes dejan de valer (REQ-T08).
    await account_tokens.invalidate(session, user.id, (TokenPurpose.password_reset,))
    await session.commit()
    await auth_service.revoke_all_sessions(session, user)
    if settings.email_enabled:
        await enqueue_account_email(
            session,
            "auth.notice",
            {
                "user_id": str(user.id),
                "kind": "password_changed",
                "lang": request_language(request),
            },
            background,
        )
    audit("auth.password.change", user_id=user.id, client_ip=client_ip(request))


@router.post(
    "/me/email",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=Message,
    include_in_schema=settings.account_emails_enabled,
)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def change_email(
    request: Request,
    response: Response,
    principal: WriteMe,
    payload: EmailChangeRequest,
    session: SessionDep,
    background: BackgroundTasks,
) -> Message:
    """Pide cambiar el email. No cambia nada hasta que se confirme con el enlace que llega
    a la dirección NUEVA (`POST /auth/email/verify`); la antigua recibe un aviso.

    Responde 202 igual aunque la dirección nueva ya esté en uso (no revela cuentas).
    Al confirmarse se cierran todas las sesiones."""
    if not settings.account_emails_enabled:
        raise APIError(
            status.HTTP_403_FORBIDDEN,
            "Changing the email requires email delivery (EMAIL_VERIFICATION or PASSWORD_RESET)",
            code="email_change_disabled",
        )
    user = principal.user
    assert user is not None
    await session.commit()  # libera la conexión mientras se calcula Argon2
    valid, _ = await verify_password(payload.current_password, user.hashed_password)
    if not valid:
        audit("auth.email_change.wrong_password", user_id=user.id, client_ip=client_ip(request))
        raise APIError(
            status.HTTP_400_BAD_REQUEST, "Current password is incorrect", code="wrong_password"
        )
    if payload.new_email == user.email:
        raise APIError(status.HTTP_400_BAD_REQUEST, "That is already your email", code="same_email")
    await enqueue_account_email(
        session,
        "auth.email_change",
        {
            "user_id": str(user.id),
            "new_email": payload.new_email,
            "lang": request_language(request),
        },
        background,
    )
    audit("auth.email_change.requested", user_id=user.id, client_ip=client_ip(request))
    return EMAIL_CHANGE_ACCEPTED


# --- Administración -------------------------------------------------------------
@router.get("", response_model=Page[UserAdminRead])
async def list_users(
    _: AdminPrincipal,
    session: SessionDep,
    page: PaginationDep,
    q: Annotated[str | None, Query(max_length=100)] = None,
    role: Role | None = None,
    is_active: bool | None = None,
    order_by: Annotated[str, Query(pattern=r"^-?(created_at|email)$")] = "-created_at",
) -> Page[User]:
    items, total = await repo.list(
        session,
        offset=page.offset,
        limit=page.limit,
        filters={"role": role, "is_active": is_active},
        search=q,
        order_by=order_by,
    )
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)


@router.post("", response_model=UserAdminRead, status_code=status.HTTP_201_CREATED)
async def create_user(payload: UserAdminCreate, admin: AdminPrincipal, session: SessionDep) -> User:
    """(admin) Crea un usuario con rol. Funciona aunque ALLOW_REGISTRATION=false."""
    exists = (await session.exec(select(User.id).where(User.email == payload.email))).first()
    await session.commit()  # libera la conexión mientras se calcula Argon2
    if exists:
        raise APIError(status.HTTP_409_CONFLICT, "Email already registered", code="email_taken")
    user = User(
        email=payload.email,
        full_name=payload.full_name,
        role=payload.role,
        hashed_password=await hash_password(payload.password),
        # Lo da de alta un admin: nace verificado (REQ-F15).
        email_verified_at=utcnow(),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    audit("admin.user.create", actor_id=admin.user_id, target_user_id=user.id, role=user.role)
    return user


async def _get_user_or_404(session: SessionDep, user_id: uuid.UUID) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("/{user_id}", response_model=UserAdminRead)
async def get_user(user_id: uuid.UUID, _: AdminPrincipal, session: SessionDep) -> User:
    return await _get_user_or_404(session, user_id)


async def _admin_count(session: SessionDep) -> int:
    query = select(func.count()).where(col(User.role) == Role.admin, col(User.is_active).is_(True))
    return (await session.exec(query)).one()


def _counts_as_admin(user: User) -> bool:
    """¿Cuenta para el mínimo de un admin? Solo los admins activos (SEC-30): un admin
    ya desactivado (p. ej. comprometido) se puede degradar o borrar aunque quede un
    único admin activo."""
    return user.role == Role.admin and user.is_active


def _reject_last_admin(action: str, admin: Principal, user: User) -> None:
    # Un intento rechazado de quitar el último admin es una señal útil (SEC ronda 5).
    audit(
        "admin.user.rejected",
        level=logging.WARNING,
        actor_id=admin.user_id,
        target_user_id=user.id,
        action=action,
        reason="last_admin",
    )
    raise LAST_ADMIN


@router.patch("/{user_id}", response_model=UserAdminRead)
async def update_user(
    user_id: uuid.UUID, payload: UserAdminUpdate, admin: AdminPrincipal, session: SessionDep
) -> User:
    user = await _get_user_or_404(session, user_id)
    changes = payload.model_dump(exclude_unset=True)
    demoting = changes.get("role", user.role) != Role.admin or changes.get("is_active") is False
    if _counts_as_admin(user) and demoting and await _admin_count(session) <= 1:
        _reject_last_admin("update", admin, user)
    privilege_change = ("role" in changes and changes["role"] != user.role) or (
        changes.get("is_active") is False
    )
    user = await repo.update(session, user, changes)
    if privilege_change:
        # Los tokens emitidos con el rol/estado anterior dejan de valer al instante.
        await auth_service.revoke_all_sessions(session, user)
    audit(
        "admin.user.update",
        actor_id=admin.user_id,
        target_user_id=user.id,
        changes=",".join(sorted(changes)),
    )
    return user


@router.post("/{user_id}/unlock", response_model=UserAdminRead)
async def unlock_user(user_id: uuid.UUID, admin: AdminPrincipal, session: SessionDep) -> User:
    """Desbloquea una cuenta bloqueada por intentos fallidos (y reinicia el contador)."""
    user = await _get_user_or_404(session, user_id)
    user = await repo.update(session, user, {"locked_until": None, "failed_login_attempts": 0})
    audit("admin.user.unlock", actor_id=admin.user_id, target_user_id=user.id)
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: uuid.UUID, admin: AdminPrincipal, session: SessionDep) -> None:
    user = await _get_user_or_404(session, user_id)
    if user.id == admin.user_id:
        audit(
            "admin.user.rejected",
            level=logging.WARNING,
            actor_id=admin.user_id,
            target_user_id=user.id,
            action="delete",
            reason="self_delete",
        )
        raise APIError(status.HTTP_409_CONFLICT, "You cannot delete yourself", code="self_delete")
    if _counts_as_admin(user) and await _admin_count(session) <= 1:
        _reject_last_admin("delete", admin, user)
    await repo.delete(session, user)
    audit("admin.user.delete", actor_id=admin.user_id, target_user_id=user_id)

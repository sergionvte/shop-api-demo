"""Dependencias compartidas: sesión de BD, usuario actual y control de acceso."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Query, Request, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import settings
from app.core.exceptions import EMAIL_NOT_VERIFIED as _EMAIL_NOT_VERIFIED
from app.core.exceptions import APIError
from app.core.permissions import ROLE_SCOPES, SCOPE_DESCRIPTIONS, Access, Role, Scope
from app.core.security import TokenError, TokenExpired, decode_access_token
from app.db.session import get_session
from app.models.user import User

SessionDep = Annotated[AsyncSession, Depends(get_session)]


def _login_version() -> str:
    """Versión para el botón Authorize de Swagger: la más reciente no deprecada."""
    from app.api.versions import VERSIONS

    active = [v.name for v in VERSIONS if not v.deprecated] or [v.name for v in VERSIONS]
    return max(active, key=lambda name: int(name[1:]))


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_PREFIX}/{_login_version()}/auth/login",
    scopes=SCOPE_DESCRIPTIONS,
    auto_error=False,
)


def _unauthorized(
    detail: str = "Could not validate credentials",
    code: str = "invalid_token",
    description: str | None = None,
) -> HTTPException:
    # RFC 6750: `error="invalid_token"` cuando se envió un token que no vale; sin
    # token, solo el esquema. `code` permite al cliente decidir: `token_expired`
    # -> usar el refresh token; `invalid_token` -> volver al login.
    challenge = "Bearer"
    if code in {"invalid_token", "token_expired"}:
        challenge += ' error="invalid_token"'
        if description:
            challenge += f', error_description="{description}"'
    return APIError(
        status.HTTP_401_UNAUTHORIZED, detail, code=code, headers={"WWW-Authenticate": challenge}
    )


_FORBIDDEN = HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")


@dataclass(frozen=True, slots=True)
class Principal:
    """Quién hace la petición (o nadie, en endpoints públicos)."""

    user: User | None
    scopes: frozenset[str]

    @property
    def is_admin(self) -> bool:
        return self.user is not None and self.user.role == Role.admin

    @property
    def user_id(self) -> uuid.UUID | None:
        return self.user.id if self.user else None

    def owner_filter(self) -> uuid.UUID | None:
        """ID por el que filtrar filas en recursos con propietario (None = todas)."""
        if self.user is None or self.is_admin:
            return None
        return self.user.id


async def get_principal(
    request: Request,
    session: SessionDep,
    token: Annotated[str | None, Depends(oauth2_scheme)],
) -> Principal:
    if not token:
        return Principal(user=None, scopes=frozenset())
    try:
        payload = decode_access_token(token)
    except TokenExpired:
        raise _unauthorized(
            "Access token expired", code="token_expired", description="The access token expired"
        ) from None
    except TokenError:
        # Un token presente pero inválido se rechaza siempre, incluso en endpoints públicos.
        raise _unauthorized() from None

    user = await session.get(User, payload["sub"])
    # token_version permite revocar al instante (logout-all, cambio de contraseña o rol).
    if user is None or not user.is_active or user.token_version != payload["ver"]:
        raise _unauthorized(description="The access token was revoked")

    # Scopes efectivos = los del token ∩ los que el rol ACTUAL permite.
    granted = frozenset(str(payload.get("scope", "")).split()) & ROLE_SCOPES[Role(user.role)]
    request.state.user_id = user.id
    return Principal(user=user, scopes=granted)


PrincipalDep = Annotated[Principal, Depends(get_principal)]


def require(level: Access | str, scope: Scope | None = None):
    """Dependencia de control de acceso para un nivel y (opcional) un scope."""
    level = Access(level)

    async def dependency(principal: PrincipalDep) -> Principal:
        if level == Access.public:
            return principal
        if principal.user is None:
            raise _unauthorized("Not authenticated", code="not_authenticated")
        needed: set[str] = {scope} if scope else set()
        if level == Access.admin:
            if not principal.is_admin:
                raise _FORBIDDEN
            needed.add(Scope.admin)
        if not needed <= principal.scopes:
            raise APIError(
                status.HTTP_403_FORBIDDEN, "Insufficient token scope", code="insufficient_scope"
            )
        return principal

    return dependency


async def current_user(principal: Annotated[Principal, Depends(require(Access.user))]) -> User:
    assert principal.user is not None
    return principal.user


CurrentUser = Annotated[User, Depends(current_user)]
AdminPrincipal = Annotated[Principal, Depends(require(Access.admin))]


@dataclass(frozen=True, slots=True)
class Pagination:
    limit: int
    offset: int


def pagination(
    limit: Annotated[int, Query(ge=1, le=settings.PAGE_SIZE_MAX)] = settings.PAGE_SIZE_DEFAULT,
    offset: Annotated[int, Query(ge=0, le=settings.MAX_OFFSET)] = 0,
) -> Pagination:
    return Pagination(limit=limit, offset=offset)


PaginationDep = Annotated[Pagination, Depends(pagination)]


# Nombres habituales de paginación/orden en otras APIs: si llegan, casi seguro que
# el cliente espera que hagan algo y conviene avisarle en vez de ignorarlos.
_FOREIGN_PARAMS = {
    "page": "use limit/offset",
    "size": "use limit",
    "per_page": "use limit",
    "page_size": "use limit",
    "sort": "use order_by",
    "sort_by": "use order_by",
    "order": "use order_by",
    "ordering": "use order_by",  # la clave del YAML se llama así (UX-60)
    "search": "use q",
}


def query_guard(allowed: frozenset[str], fields: frozenset[str]):
    """Dependencia para listados: rechaza (422) parámetros de query que parecen un
    error del cliente (un campo del recurso que no es filtrable, o `page`/`size`)
    en lugar de ignorarlos en silencio. El resto (p. ej. `_=123` anti-caché) se ignora."""

    async def dependency(request: Request) -> None:
        errors = []
        for name in request.query_params:
            if name in allowed:
                continue
            if name in fields:
                hint = f"field '{name}' is not filterable"
                if allowed - {"limit", "offset", "order_by", "q"}:
                    options = ", ".join(sorted(allowed - {"limit", "offset", "order_by", "q"}))
                    hint += f" (filters: {options})"
            elif name in _FOREIGN_PARAMS:
                hint = f"unknown parameter '{name}': {_FOREIGN_PARAMS[name]}"
            else:
                continue
            errors.append({"loc": ["query", name], "msg": hint, "type": "unknown_parameter"})
        if errors:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=errors)

    return dependency


class ErrorBody(BaseModel):
    """Forma de las respuestas de error (para OpenAPI y clientes generados)."""

    detail: Any
    code: str


_ERROR_DESCRIPTIONS = {
    401: "Not authenticated, invalid credentials or invalid/expired token (`code`: "
    "not_authenticated, invalid_credentials, invalid_token, token_expired, "
    "invalid_refresh_token)",
    403: "Not enough permissions or insufficient token scope",
    404: "Not found (or not yours)",
    409: "Conflict (`code`: unique_violation, has_dependents, reference_violation)",
    415: "Wrong Content-Type (`code`: login_expects_form, expects_json)",
    429: "Rate limit exceeded (see Retry-After)",
}


def error_responses(*codes: int) -> dict[int | str, dict[str, Any]]:
    """Respuestas de error documentadas en OpenAPI para los endpoints generados."""
    return {code: {"model": ErrorBody, "description": _ERROR_DESCRIPTIONS[code]} for code in codes}


EMAIL_NOT_VERIFIED = _EMAIL_NOT_VERIFIED  # reexportado (app.core.exceptions)


async def verified_user(principal: Annotated[Principal, Depends(require(Access.user))]) -> User:
    """Usuario autenticado con el email verificado (si EMAIL_VERIFICATION no es `off`).

    Para hooks y endpoints propios en modo `optional`; con `required` los no
    verificados ni siquiera obtienen tokens."""
    assert principal.user is not None
    if settings.email_verification != "off" and principal.user.email_verified_at is None:
        raise EMAIL_NOT_VERIFIED
    return principal.user


VerifiedUser = Annotated[User, Depends(verified_user)]

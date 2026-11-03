from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.core.permissions import Role
from app.core.security import password_problems
from app.schemas.common import PartialUpdate, StrictInput, raise_field_errors


def _check_password(title: str, field: str, password: str, email: str | None) -> None:
    """Un error `password_policy` por problema, con `loc` en el campo (UX-29)."""
    problems = password_problems(password, email)
    if problems:
        raise_field_errors(
            title,
            [(field, "password_policy", "Password {problem}", {"problem": p}) for p in problems],
        )


class UserRegister(StrictInput):
    email: EmailStr = Field(max_length=320)
    password: str = Field(min_length=1, max_length=1024)
    full_name: str | None = Field(default=None, max_length=120)

    @field_validator("email")
    @classmethod
    def _lower(cls, value: str) -> str:
        return value.lower()

    @model_validator(mode="after")
    def _password_policy(self) -> UserRegister:
        # En el esquema (y no en el endpoint) para que el 422 se produzca antes del
        # rate limit de registro: una contraseña débil no consume cupo.
        _check_password(type(self).__name__, "password", self.password, self.email)
        return self


class UserAdminCreate(UserRegister):
    role: Role = Role.user


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    # `str` y no `EmailStr`: la salida no se revalida. Un email guardado por
    # script/migración que no pase las reglas actuales de email-validator
    # rompería /users/me y todo el listado con un 500 (SEC-12).
    email: str
    full_name: str | None
    role: Role
    is_active: bool
    email_verified: bool
    created_at: datetime


class UserAdminRead(UserRead):
    email_verified_at: datetime | None
    failed_login_attempts: int
    locked_until: datetime | None
    last_login_at: datetime | None
    updated_at: datetime


class UserUpdateMe(PartialUpdate):
    full_name: str | None = Field(default=None, max_length=120)


class UserAdminUpdate(PartialUpdate):
    __non_nullable__ = frozenset({"role", "is_active"})

    full_name: str | None = Field(default=None, max_length=120)
    role: Role | None = None
    is_active: bool | None = None


class PasswordChange(StrictInput):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


class AccountDeletion(StrictInput):
    """Confirmación para borrar la propia cuenta: la contraseña actual (un token robado
    no basta para destruir la cuenta)."""

    current_password: str = Field(min_length=1, max_length=1024)

"""Esquemas de los flujos de cuenta: recuperación, verificación y cambio de email."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.schemas.common import StrictInput


class EmailRequest(StrictInput):
    # Un único EmailStr estricto: listas, objetos o campos extra -> 422 (REQ-E09).
    email: EmailStr = Field(max_length=320)

    @field_validator("email")
    @classmethod
    def _lower(cls, value: str) -> str:
        return value.lower()


class ResendVerificationRequest(StrictInput):
    email: EmailStr | None = Field(default=None, max_length=320)

    @field_validator("email")
    @classmethod
    def _lower(cls, value: str | None) -> str | None:
        return value.lower() if value else value


def _no_nul(value: Any) -> Any:
    if isinstance(value, str) and "\x00" in value:
        raise ValueError("NUL characters are not allowed")
    return value


class _TokenInput(BaseModel):
    """El token NO se valida aquí: un token enorme, con NUL o con caracteres raros debe
    dar el mismo 400 que uno inexistente, no un 422 que los distinga (REQ-T04)."""

    model_config = ConfigDict(extra="forbid")
    token: str


class TokenRequest(_TokenInput):
    pass


class PasswordResetRequest(_TokenInput):
    new_password: str = Field(min_length=1, max_length=1024)

    @field_validator("new_password", mode="before")
    @classmethod
    def _password_without_nul(cls, value: Any) -> Any:
        return _no_nul(value)


class EmailChangeRequest(StrictInput):
    new_email: EmailStr = Field(max_length=320)
    current_password: str = Field(min_length=1, max_length=1024)

    @field_validator("new_email")
    @classmethod
    def _lower(cls, value: str) -> str:
        return value.lower()


class AccountFeatures(BaseModel):
    """Qué flujos de cuenta ofrece esta API (para que el frontend muestre u oculte)."""

    registration: bool
    email_verification: Literal["off", "optional", "required"]
    password_reset: bool
    email_change: bool

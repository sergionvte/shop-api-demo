from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.common import StrictInput


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105
    expires_in: int
    scope: str


class RefreshRequest(StrictInput):
    refresh_token: str = Field(min_length=1, max_length=256)

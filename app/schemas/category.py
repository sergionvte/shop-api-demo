"""Esquemas de entrada/salida de `category` (generados por apigen, puedes editarlos).

- `CategoryCreate`: lo que el cliente puede enviar al crear (campos extra -> 422).
- `CategoryUpdate`: PATCH parcial; solo se modifican los campos enviados.
- `CategoryRead`: lo que la API devuelve (nunca incluye campos write_only).
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import PartialUpdate, StrictInput


class CategoryCreate(StrictInput):
    name: str = Field(max_length=80)
    slug: str = Field(max_length=80, pattern="^[a-z0-9-]+$", examples=["ropa-deportiva"])
    description: str | None = Field(default=None, max_length=500)


class CategoryUpdate(PartialUpdate):
    __non_nullable__ = frozenset({"name"})
    # Campos que solo se fijan al crear: enviarlos en PATCH da un 422 `immutable_field`.
    __immutable__ = frozenset({"slug"})

    name: str | None = Field(default=None, max_length=80)
    description: str | None = Field(default=None, max_length=500)


class CategoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    description: str | None
    created_at: datetime
    updated_at: datetime

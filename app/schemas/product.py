"""Esquemas de entrada/salida de `product` (generados por apigen, puedes editarlos).

- `ProductCreate`: lo que el cliente puede enviar al crear (campos extra -> 422).
- `ProductUpdate`: PATCH parcial; solo se modifican los campos enviados.
- `ProductRead`: lo que la API devuelve (nunca incluye campos write_only).
"""

import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import PartialUpdate, StrictInput


class ProductCreate(StrictInput):
    name: str = Field(max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    price: Decimal = Field(ge=0, max_digits=10, decimal_places=2)
    stock: int = Field(default=0, ge=0, le=9223372036854775807)
    active: bool = Field(default=True)
    image_url: str | None = Field(default=None, max_length=500)
    category_id: uuid.UUID | None = Field(default=None)


class ProductUpdate(PartialUpdate):
    __non_nullable__ = frozenset({"active", "name", "price", "stock"})

    name: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    price: Decimal | None = Field(default=None, ge=0, max_digits=10, decimal_places=2)
    stock: int | None = Field(default=None, ge=0, le=9223372036854775807)
    active: bool | None = Field(default=None)
    image_url: str | None = Field(default=None, max_length=500)
    category_id: uuid.UUID | None = Field(default=None)


class ProductRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    price: Decimal
    stock: int
    active: bool
    image_url: str | None
    category_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

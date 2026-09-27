"""Esquemas de entrada/salida de `order` (generados por apigen, puedes editarlos).

- `OrderCreate`: lo que el cliente puede enviar al crear (campos extra -> 422).
- `OrderUpdate`: PATCH parcial; solo se modifican los campos enviados.
- `OrderRead`: lo que la API devuelve (nunca incluye campos write_only).
"""

import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from app.models.order import OrderStatus
from app.schemas.common import PartialUpdate, StrictInput


class OrderCreate(StrictInput):
    product_id: uuid.UUID = Field()
    quantity: int = Field(ge=1, le=20)
    shipping_address: str = Field(max_length=500)
    status: OrderStatus = Field(default=OrderStatus.pending)
    total: Decimal | None = Field(
        default=None, ge=0, max_digits=12, decimal_places=2, description="Lo calcula el servidor"
    )


class OrderUpdate(PartialUpdate):
    __non_nullable__ = frozenset({"product_id", "quantity", "shipping_address", "status"})

    product_id: uuid.UUID | None = Field(default=None)
    quantity: int | None = Field(default=None, ge=1, le=20)
    shipping_address: str | None = Field(default=None, max_length=500)
    status: OrderStatus | None = Field(default=None)
    total: Decimal | None = Field(
        default=None, ge=0, max_digits=12, decimal_places=2, description="Lo calcula el servidor"
    )


class OrderRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    owner_id: uuid.UUID
    product_id: uuid.UUID
    quantity: int
    shipping_address: str
    status: OrderStatus
    total: Decimal | None
    created_at: datetime
    updated_at: datetime


class OrderInvoiceInput(StrictInput):
    """Cuerpo de la acción `invoice` (sin campos: `{}` o sin cuerpo)."""


class OrderSummaryInput(StrictInput):
    """Cuerpo de la acción `summary` (sin campos: `{}` o sin cuerpo)."""

"""Modelo de tabla `orders` (generado por apigen, puedes editarlo).

Tras cambiar columnas crea una migración: `apigen db migrate -m "..."`.
"""

import uuid
from decimal import Decimal
from enum import StrEnum

from sqlalchemy import String, Text
from sqlmodel import Field

from app.models.base import IDMixin, TimestampMixin


class OrderStatus(StrEnum):
    pending = "pending"
    paid = "paid"
    shipped = "shipped"
    cancelled = "cancelled"


class Order(IDMixin, TimestampMixin, table=True):
    __tablename__ = "orders"

    owner_id: uuid.UUID = Field(foreign_key="users.id", ondelete="CASCADE", index=True)
    product_id: uuid.UUID = Field(foreign_key="products.id", ondelete="RESTRICT", index=True)
    quantity: int = Field()
    shipping_address: str = Field(sa_type=Text, sa_column_kwargs={"info": {"pii": True}})
    status: OrderStatus = Field(default=OrderStatus.pending, sa_type=String(9))
    total: Decimal | None = Field(
        default=None, max_digits=12, decimal_places=2, description="Lo calcula el servidor"
    )

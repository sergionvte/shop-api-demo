"""Modelo de tabla `products` (generado por apigen, puedes editarlo).

Tras cambiar columnas crea una migración: `apigen db migrate -m "..."`.
"""

import uuid
from decimal import Decimal

from sqlalchemy import BigInteger, Text
from sqlmodel import Field

from app.models.base import IDMixin, SoftDeleteMixin, TimestampMixin


class Product(IDMixin, TimestampMixin, SoftDeleteMixin, table=True):
    __tablename__ = "products"

    name: str = Field(max_length=120, index=True)
    description: str | None = Field(default=None, sa_type=Text)
    price: Decimal = Field(max_digits=10, decimal_places=2)
    stock: int = Field(default=0, sa_type=BigInteger)
    active: bool = Field(default=True)
    image_url: str | None = Field(default=None, max_length=500)
    category_id: uuid.UUID | None = Field(
        default=None, foreign_key="categories.id", ondelete="SET NULL", index=True
    )

"""Modelo de tabla `categories` (generado por apigen, puedes editarlo).

Tras cambiar columnas crea una migración: `apigen db migrate -m "..."`.
"""

from sqlalchemy import Text
from sqlmodel import Field

from app.models.base import IDMixin, TimestampMixin


class Category(IDMixin, TimestampMixin, table=True):
    __tablename__ = "categories"

    name: str = Field(max_length=80, unique=True)
    slug: str = Field(max_length=80, unique=True)
    description: str | None = Field(default=None, sa_type=Text)

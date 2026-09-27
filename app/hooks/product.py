"""Lógica personalizada de `product`. ESTE FICHERO ES TUYO.

apigen lo crea una vez y nunca lo sobrescribe (ni con `generate --force`): si
añades acciones al YAML solo añade al final las funciones que falten. Los
endpoints de `app/api/vN/endpoints/products.py` llaman a estas funciones.

- before_*: valida/normaliza o rechaza con `raise APIError(...)`.
- after_*: efectos secundarios; lo pesado, encólalo con `await ctx.enqueue(...)`
  para que lo ejecute el worker sin ralentizar la API.
"""

from __future__ import annotations

from typing import Any  # noqa: F401

from app.core.exceptions import APIError  # noqa: F401
from app.hooks import HookContext
from app.models.product import Product
from app.schemas.product import ProductCreate, ProductRead, ProductUpdate  # noqa: F401


async def before_create(ctx: HookContext, data: ProductCreate) -> ProductCreate:
    """Antes de insertar: valida reglas de negocio, normaliza o rechaza con
    `raise APIError(422, "...", code="...")`. Devuelve los datos (puedes
    modificarlos con `data.model_copy(update={...})`)."""
    return data


async def after_create(ctx: HookContext, obj: Product) -> None:
    """Tras insertar (ya guardado). Lo pesado, encólalo: `await ctx.enqueue(...)`."""
    return None


async def before_update(ctx: HookContext, obj: Product, data: ProductUpdate) -> ProductUpdate:
    """Antes de aplicar un PATCH. `obj` es la fila actual; `data` solo trae los campos
    enviados (`data.model_fields_set`). Devuelve los datos a aplicar."""
    return data


async def after_update(ctx: HookContext, obj: Product) -> None:
    """Tras guardar los cambios."""
    return None


async def before_delete(ctx: HookContext, obj: Product) -> None:
    """Antes de borrar: lanza APIError para impedirlo (p. ej. 409 si está en uso)."""
    return None


async def after_delete(ctx: HookContext, obj: Product) -> None:
    """Tras borrar."""
    return None

"""Lógica personalizada de `order`. ESTE FICHERO ES TUYO.

apigen lo crea una vez y nunca lo sobrescribe (ni con `generate --force`): si
añades acciones al YAML solo añade al final las funciones que falten. Los
endpoints de `app/api/vN/endpoints/orders.py` llaman a estas funciones.

- before_*: valida/normaliza o rechaza con `raise APIError(...)`.
- after_*: efectos secundarios; lo pesado, encólalo con `await ctx.enqueue(...)`
  para que lo ejecute el worker sin ralentizar la API.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from sqlalchemy import update
from sqlmodel import col, select

from app.core.exceptions import APIError  # noqa: F401
from app.hooks import HookContext
from app.models.order import Order, OrderStatus
from app.models.product import Product
from app.schemas.order import OrderCreate, OrderRead, OrderUpdate  # noqa: F401


async def _product(ctx: HookContext, product_id) -> Product:
    product = (
        await ctx.session.exec(
            select(Product).where(
                col(Product.id) == product_id,
                col(Product.deleted_at).is_(None),
                col(Product.active).is_(True),
            )
        )
    ).first()
    if product is None:
        raise APIError(422, "Product not available", code="product_not_available")
    return product


async def _restock(ctx: HookContext, obj: Order) -> None:
    await ctx.session.execute(
        update(Product)
        .where(col(Product.id) == obj.product_id)
        .values(stock=Product.stock + obj.quantity)
    )


async def before_create(ctx: HookContext, data: OrderCreate) -> OrderCreate:
    """El servidor fija el estado y calcula el total; comprueba que hay stock."""
    product = await _product(ctx, data.product_id)
    if product.stock < data.quantity:
        raise APIError(409, "Not enough stock for this product", code="insufficient_stock")
    total = (Decimal(product.price) * data.quantity).quantize(Decimal("0.01"))
    return data.model_copy(update={"status": OrderStatus.pending, "total": total})


async def after_create(ctx: HookContext, obj: Order) -> None:
    """Descuenta el stock (UPDATE condicional: nunca baja de cero)."""
    await ctx.session.execute(
        update(Product)
        .where(col(Product.id) == obj.product_id, col(Product.stock) >= obj.quantity)
        .values(stock=Product.stock - obj.quantity)
    )
    await ctx.session.commit()


async def before_update(ctx: HookContext, obj: Order, data: OrderUpdate) -> OrderUpdate:
    """Reglas del pedido:
    - producto, cantidad y total no se pueden cambiar;
    - el cliente solo puede cambiar la dirección o cancelar mientras está `pending`;
    - un admin puede mover el estado (paid, shipped, cancelled).
    Cancelar devuelve el stock."""
    sent = data.model_fields_set
    locked = sent & {"product_id", "quantity", "total"}
    if locked:
        raise APIError(
            422, f"These fields cannot be changed: {', '.join(sorted(locked))}", code="order_locked"
        )
    new_status = data.status if "status" in sent else obj.status
    if not ctx.principal.is_admin:
        if obj.status != OrderStatus.pending:
            raise APIError(409, "Only pending orders can be modified", code="order_not_pending")
        if new_status not in (OrderStatus.pending, OrderStatus.cancelled):
            raise APIError(403, "Only an admin can change the order status", code="forbidden")
    if new_status == OrderStatus.cancelled and obj.status != OrderStatus.cancelled:
        await _restock(ctx, obj)
    return data


async def after_update(ctx: HookContext, obj: Order) -> None:
    return None


async def before_delete(ctx: HookContext, obj: Order) -> None:
    """No se borran pedidos pagados o enviados; borrar uno pendiente devuelve el stock."""
    if obj.status in (OrderStatus.paid, OrderStatus.shipped):
        raise APIError(409, "Paid or shipped orders cannot be deleted", code="order_not_deletable")
    if obj.status == OrderStatus.pending:
        await _restock(ctx, obj)


async def after_delete(ctx: HookContext, obj: Order) -> None:
    return None


async def summary(ctx: HookContext, obj: Order, data: dict[str, Any]) -> dict[str, Any]:
    """Resumen legible del pedido."""
    product = await ctx.session.get(Product, obj.product_id)
    return {
        "order_id": str(obj.id),
        "product": product.name if product else None,
        "quantity": obj.quantity,
        "total": str(obj.total),
        "status": obj.status,
    }

"""Tareas en segundo plano de `order`. ESTE FICHERO ES TUYO.

Se ejecutan en `apigen worker` (un proceso aparte), nunca dentro de la API.
apigen lo crea una vez y solo añade al final las tareas que falten.

- `raise TaskError("mensaje")`: fallo que el cliente puede ver (no se reintenta).
- Cualquier otra excepción se reintenta con espera creciente y el cliente solo
  ve "Task failed" (la traza queda en el log con el job_id).
"""

from __future__ import annotations

import uuid  # noqa: F401
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from app.models.order import Order  # noqa: F401
from app.models.product import Product
from app.tasks.registry import TaskContext, TaskError, task  # noqa: F401


@task("order.invoice", executor="async", timeout=300, max_attempts=3)
async def invoice(ctx: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Genera la factura del pedido en segundo plano

    payload: {"item_id": "<uuid>"}.
    Quién lo pidió: `ctx.owner_id` (también `ctx.job_id`, `ctx.attempt`).
    Sesión de BD propia: `async with ctx.session() as session`.
    """
    item_id = uuid.UUID(payload["item_id"])
    async with ctx.session() as session:
        obj = await session.get(Order, item_id)
        if obj is None:
            raise TaskError("Order no longer exists")
        product = await session.get(Product, obj.product_id)
    # En un proyecto real aquí se generaría el PDF y se subiría a un almacenamiento;
    # en la demo devolvemos los datos de la factura como resultado del trabajo.
    unit = Decimal(product.price) if product else Decimal("0")
    return {
        "invoice_number": f"INV-{obj.created_at:%Y%m%d}-{str(obj.id)[-6:].upper()}",
        "issued_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "order_id": str(obj.id),
        "product": product.name if product else None,
        "quantity": obj.quantity,
        "unit_price": str(unit),
        "total": str(obj.total),
        "status": obj.status,
    }

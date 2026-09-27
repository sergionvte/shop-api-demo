"""Endpoints de `orders` (v1), generados por apigen: edítalos libremente.

Permisos: list=owner, read=owner, create=user, update=owner, delete=owner
Recurso con propietario: con nivel `owner` cada usuario solo ve/modifica sus
filas (las ajenas devuelven 404, sin revelar que existen); un admin ve todas.
"""

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status

import app.hooks.order as hooks
from app.api.deps import (
    PaginationDep,
    Principal,
    SessionDep,
    error_responses,
    query_guard,
    require,
)
from app.core.config import settings
from app.core.permissions import Access, Scope
from app.core.rate_limit import limiter
from app.crud.base import Repository, ensure_reference
from app.hooks import HookContext
from app.models.order import Order, OrderStatus
from app.models.product import Product
from app.schemas.common import Page
from app.schemas.order import (
    OrderCreate,
    OrderInvoiceInput,
    OrderRead,
    OrderSummaryInput,
    OrderUpdate,
)
from app.tasks.queue import JobAccepted, enqueue

router = APIRouter(prefix="/orders", tags=["orders"], responses=error_responses(401, 403, 429))

repo = Repository(
    Order,
    owner_field="owner_id",
    soft_delete=False,
    search_fields=(),
    ordering_fields=(
        "created_at",
        "quantity",
    ),
)

CanList = Annotated[Principal, Depends(require(Access.owner, Scope.read))]
CanRead = Annotated[Principal, Depends(require(Access.owner, Scope.read))]
CanCreate = Annotated[Principal, Depends(require(Access.user, Scope.write))]
CanUpdate = Annotated[Principal, Depends(require(Access.owner, Scope.write))]
CanDelete = Annotated[Principal, Depends(require(Access.owner, Scope.write))]
# Permisos de las acciones (prefijo propio: no pueden pisar los del CRUD).
CanAction_invoice = Annotated[Principal, Depends(require(Access.owner, Scope.write))]
CanAction_summary = Annotated[Principal, Depends(require(Access.owner, Scope.write))]

OrderBy = Literal["created_at", "-created_at", "quantity", "-quantity"]


async def _get_or_404(
    session: SessionDep, item_id: uuid.UUID, principal: Principal, *, scoped: bool
) -> Order:
    owner_id = principal.owner_filter() if scoped else None
    obj = await repo.get(session, item_id, owner_id=owner_id)
    if obj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Order not found")
    return obj


async def _check_references(
    session: SessionDep, principal: Principal, data: OrderCreate | OrderUpdate
) -> None:
    """Impide referenciar filas que el usuario no puede ver (IDOR vía clave foránea)."""
    sent = data.model_fields_set
    if "product_id" in sent and data.product_id is not None:
        await ensure_reference(
            session,
            Product,
            data.product_id,
            owner_id=None,
            soft_delete=True,
            field="product_id",
        )


@router.get(
    "",
    response_model=Page[OrderRead],
    description=(
        "Pedidos; cada cliente solo ve los suyos\n\n"
        "Filters: status, product_id.\n\n"
        "Ordering (`order_by`, prefix `-` for descending): created_at, "
        "quantity."
    ),
    dependencies=[
        Depends(
            query_guard(
                frozenset({"limit", "offset", "order_by", "product_id", "status"}),
                frozenset({"product_id", "quantity", "shipping_address", "status", "total"}),
            )
        )
    ],
)
async def list_orders(
    principal: CanList,
    session: SessionDep,
    page: PaginationDep,
    order_by: OrderBy = "-created_at",
    status: OrderStatus | None = None,
    product_id: uuid.UUID | None = None,
) -> Page[OrderRead]:
    items, total = await repo.list(
        session,
        offset=page.offset,
        limit=page.limit,
        filters={"status": status, "product_id": product_id},
        search=None,
        order_by=order_by,
        owner_id=principal.owner_filter(),
    )
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)  # type: ignore[arg-type]


@router.post(
    "",
    response_model=OrderRead,
    status_code=status.HTTP_201_CREATED,
    description=("Pedidos; cada cliente solo ve los suyos"),
    responses=error_responses(409),
)
async def create_order(
    payload: OrderCreate,
    principal: CanCreate,
    session: SessionDep,
) -> Order:
    # Lógica propia: app/hooks/order.py (apigen nunca sobrescribe ese fichero).
    ctx = HookContext(session=session, principal=principal)
    payload = await hooks.before_create(ctx, payload)
    await _check_references(session, principal, payload)
    obj = await repo.create(session, payload, owner_id=principal.user_id)
    await hooks.after_create(ctx, obj)
    return obj


@router.get("/{item_id}", response_model=OrderRead, responses=error_responses(404))
async def get_order(
    item_id: uuid.UUID,
    principal: CanRead,
    session: SessionDep,
) -> Order:
    return await _get_or_404(session, item_id, principal, scoped=True)


@router.patch("/{item_id}", response_model=OrderRead, responses=error_responses(404, 409))
async def update_order(
    item_id: uuid.UUID,
    payload: OrderUpdate,
    principal: CanUpdate,
    session: SessionDep,
) -> Order:
    obj = await _get_or_404(session, item_id, principal, scoped=True)
    ctx = HookContext(session=session, principal=principal)
    payload = await hooks.before_update(ctx, obj, payload)
    await _check_references(session, principal, payload)
    obj = await repo.update(session, obj, payload)
    await hooks.after_update(ctx, obj)
    return obj


@router.delete(
    "/{item_id}", status_code=status.HTTP_204_NO_CONTENT, responses=error_responses(404, 409)
)
async def delete_order(
    item_id: uuid.UUID,
    principal: CanDelete,
    session: SessionDep,
) -> None:
    obj = await _get_or_404(session, item_id, principal, scoped=True)
    ctx = HookContext(session=session, principal=principal)
    await hooks.before_delete(ctx, obj)
    await repo.delete(session, obj)
    await hooks.after_delete(ctx, obj)


@router.post(
    "/{item_id}/invoice",
    response_model=JobAccepted,
    status_code=status.HTTP_202_ACCEPTED,
    description=("Genera la factura del pedido en segundo plano"),
    responses=error_responses(404),
)
@limiter.limit("10/minute")
async def invoice_order(
    request: Request,
    response: Response,
    item_id: uuid.UUID,
    principal: CanAction_invoice,
    session: SessionDep,
    # Sin campos obligatorios: el cuerpo se puede omitir (equivale a `{}`).
    payload: Annotated[OrderInvoiceInput, Body(default_factory=OrderInvoiceInput)],
) -> JobAccepted:
    obj = await _get_or_404(session, item_id, principal, scoped=True)
    # Solo se encola (una inserción): el trabajo lo ejecuta `apigen worker` aparte.
    job = await enqueue(
        session,
        "order.invoice",
        {
            "item_id": str(obj.id),
            **payload.model_dump(mode="json"),
        },
        owner_id=principal.user_id,
    )
    status_url = f"{settings.API_PREFIX}/v1/jobs/{job.id}"
    response.headers["Location"] = status_url
    return JobAccepted(job_id=job.id, status=job.status, status_url=status_url)


@router.post(
    "/{item_id}/summary",
    description=("Resumen rápido del pedido"),
    responses=error_responses(404),
)
async def summary_order(
    item_id: uuid.UUID,
    principal: CanAction_summary,
    session: SessionDep,
    # Sin campos obligatorios: el cuerpo se puede omitir (equivale a `{}`).
    payload: Annotated[OrderSummaryInput, Body(default_factory=OrderSummaryInput)],
) -> dict[str, Any]:
    obj = await _get_or_404(session, item_id, principal, scoped=True)
    ctx = HookContext(session=session, principal=principal)
    result = await hooks.summary(
        ctx,
        obj,
        payload.model_dump(mode="json"),
    )
    if session.new or session.dirty or session.deleted:
        await session.commit()  # guarda lo que la acción haya cambiado
    return result

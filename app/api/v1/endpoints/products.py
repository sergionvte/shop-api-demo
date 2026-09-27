"""Endpoints de `products` (v1), generados por apigen: edítalos libremente.

Permisos: list=public, read=public, create=admin, update=admin, delete=admin
"""

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status

import app.hooks.product as hooks
from app.api.deps import (
    PaginationDep,
    Principal,
    SessionDep,
    error_responses,
    query_guard,
    require,
)
from app.core.permissions import Access, Scope
from app.crud.base import Repository, ensure_reference
from app.hooks import HookContext
from app.models.category import Category
from app.models.product import Product
from app.schemas.common import Page
from app.schemas.product import ProductCreate, ProductRead, ProductUpdate

router = APIRouter(prefix="/products", tags=["products"], responses=error_responses(401, 403, 429))

repo = Repository(
    Product,
    owner_field=None,
    soft_delete=True,
    search_fields=("name",),
    ordering_fields=(
        "created_at",
        "name",
        "price",
        "stock",
    ),
)

CanList = Annotated[Principal, Depends(require(Access.public, Scope.read))]
CanRead = Annotated[Principal, Depends(require(Access.public, Scope.read))]
CanCreate = Annotated[Principal, Depends(require(Access.admin, Scope.write))]
CanUpdate = Annotated[Principal, Depends(require(Access.admin, Scope.write))]
CanDelete = Annotated[Principal, Depends(require(Access.admin, Scope.write))]

OrderBy = Literal[
    "created_at", "-created_at", "name", "-name", "price", "-price", "stock", "-stock"
]


async def _get_or_404(
    session: SessionDep, item_id: uuid.UUID, principal: Principal, *, scoped: bool
) -> Product:
    owner_id = principal.owner_filter() if scoped else None
    obj = await repo.get(session, item_id, owner_id=owner_id)
    if obj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Product not found")
    return obj


async def _check_references(
    session: SessionDep, principal: Principal, data: ProductCreate | ProductUpdate
) -> None:
    """Impide referenciar filas que el usuario no puede ver (IDOR vía clave foránea)."""
    sent = data.model_fields_set
    if "category_id" in sent and data.category_id is not None:
        await ensure_reference(
            session,
            Category,
            data.category_id,
            owner_id=None,
            soft_delete=False,
            field="category_id",
        )


@router.get(
    "",
    response_model=Page[ProductRead],
    description=(
        "Productos a la venta\n\n"
        "Filters: active, category_id.\n\n"
        "Text search (`q`) in: name.\n\n"
        "Ordering (`order_by`, prefix `-` for descending): created_at, name, "
        "price, stock."
    ),
    dependencies=[
        Depends(
            query_guard(
                frozenset({"active", "category_id", "limit", "offset", "order_by", "q"}),
                frozenset(
                    {"active", "category_id", "description", "image_url", "name", "price", "stock"}
                ),
            )
        )
    ],
)
async def list_products(
    principal: CanList,
    session: SessionDep,
    page: PaginationDep,
    q: Annotated[str | None, Query(max_length=100, description="Búsqueda de texto")] = None,
    order_by: OrderBy = "-created_at",
    active: bool | None = None,
    category_id: uuid.UUID | None = None,
) -> Page[ProductRead]:
    items, total = await repo.list(
        session,
        offset=page.offset,
        limit=page.limit,
        filters={"active": active, "category_id": category_id},
        search=q,
        order_by=order_by,
        owner_id=None,
    )
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)  # type: ignore[arg-type]


@router.post(
    "",
    response_model=ProductRead,
    status_code=status.HTTP_201_CREATED,
    description=("Productos a la venta"),
    responses=error_responses(409),
)
async def create_product(
    payload: ProductCreate,
    principal: CanCreate,
    session: SessionDep,
) -> Product:
    # Lógica propia: app/hooks/product.py (apigen nunca sobrescribe ese fichero).
    ctx = HookContext(session=session, principal=principal)
    payload = await hooks.before_create(ctx, payload)
    await _check_references(session, principal, payload)
    obj = await repo.create(session, payload)
    await hooks.after_create(ctx, obj)
    return obj


@router.get("/{item_id}", response_model=ProductRead, responses=error_responses(404))
async def get_product(
    item_id: uuid.UUID,
    principal: CanRead,
    session: SessionDep,
) -> Product:
    return await _get_or_404(session, item_id, principal, scoped=False)


@router.patch("/{item_id}", response_model=ProductRead, responses=error_responses(404, 409))
async def update_product(
    item_id: uuid.UUID,
    payload: ProductUpdate,
    principal: CanUpdate,
    session: SessionDep,
) -> Product:
    obj = await _get_or_404(session, item_id, principal, scoped=False)
    ctx = HookContext(session=session, principal=principal)
    payload = await hooks.before_update(ctx, obj, payload)
    await _check_references(session, principal, payload)
    obj = await repo.update(session, obj, payload)
    await hooks.after_update(ctx, obj)
    return obj


@router.delete(
    "/{item_id}", status_code=status.HTTP_204_NO_CONTENT, responses=error_responses(404, 409)
)
async def delete_product(
    item_id: uuid.UUID,
    principal: CanDelete,
    session: SessionDep,
) -> None:
    obj = await _get_or_404(session, item_id, principal, scoped=False)
    ctx = HookContext(session=session, principal=principal)
    await hooks.before_delete(ctx, obj)
    await repo.delete(session, obj)
    await hooks.after_delete(ctx, obj)

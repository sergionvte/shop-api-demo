"""Endpoints de `categories` (v1), generados por apigen: edítalos libremente.

Permisos: list=public, read=public, create=admin, update=admin, delete=admin
"""

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status

import app.hooks.category as hooks
from app.api.deps import (
    PaginationDep,
    Principal,
    SessionDep,
    error_responses,
    query_guard,
    require,
)
from app.core.permissions import Access, Scope
from app.crud.base import Repository
from app.hooks import HookContext
from app.models.category import Category
from app.schemas.category import CategoryCreate, CategoryRead, CategoryUpdate
from app.schemas.common import Page

router = APIRouter(
    prefix="/categories", tags=["categories"], responses=error_responses(401, 403, 429)
)

repo = Repository(
    Category,
    owner_field=None,
    soft_delete=False,
    search_fields=("name",),
    ordering_fields=(
        "created_at",
        "name",
    ),
)

CanList = Annotated[Principal, Depends(require(Access.public, Scope.read))]
CanRead = Annotated[Principal, Depends(require(Access.public, Scope.read))]
CanCreate = Annotated[Principal, Depends(require(Access.admin, Scope.write))]
CanUpdate = Annotated[Principal, Depends(require(Access.admin, Scope.write))]
CanDelete = Annotated[Principal, Depends(require(Access.admin, Scope.write))]

OrderBy = Literal["created_at", "-created_at", "name", "-name"]


async def _get_or_404(
    session: SessionDep, item_id: uuid.UUID, principal: Principal, *, scoped: bool
) -> Category:
    owner_id = principal.owner_filter() if scoped else None
    obj = await repo.get(session, item_id, owner_id=owner_id)
    if obj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Category not found")
    return obj


@router.get(
    "",
    response_model=Page[CategoryRead],
    description=(
        "Categorías del catálogo\n\n"
        "Text search (`q`) in: name.\n\n"
        "Ordering (`order_by`, prefix `-` for descending): created_at, name."
    ),
    dependencies=[
        Depends(
            query_guard(
                frozenset({"limit", "offset", "order_by", "q"}),
                frozenset({"description", "name", "slug"}),
            )
        )
    ],
)
async def list_categories(
    principal: CanList,
    session: SessionDep,
    page: PaginationDep,
    q: Annotated[str | None, Query(max_length=100, description="Búsqueda de texto")] = None,
    order_by: OrderBy = "-created_at",
) -> Page[CategoryRead]:
    items, total = await repo.list(
        session,
        offset=page.offset,
        limit=page.limit,
        filters={},
        search=q,
        order_by=order_by,
        owner_id=None,
    )
    return Page(items=items, total=total, limit=page.limit, offset=page.offset)  # type: ignore[arg-type]


@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    description=("Categorías del catálogo"),
    responses=error_responses(409),
)
async def create_category(
    payload: CategoryCreate,
    principal: CanCreate,
    session: SessionDep,
) -> Category:
    # Lógica propia: app/hooks/category.py (apigen nunca sobrescribe ese fichero).
    ctx = HookContext(session=session, principal=principal)
    payload = await hooks.before_create(ctx, payload)
    obj = await repo.create(session, payload)
    await hooks.after_create(ctx, obj)
    return obj


@router.get("/{item_id}", response_model=CategoryRead, responses=error_responses(404))
async def get_category(
    item_id: uuid.UUID,
    principal: CanRead,
    session: SessionDep,
) -> Category:
    return await _get_or_404(session, item_id, principal, scoped=False)


@router.patch("/{item_id}", response_model=CategoryRead, responses=error_responses(404, 409))
async def update_category(
    item_id: uuid.UUID,
    payload: CategoryUpdate,
    principal: CanUpdate,
    session: SessionDep,
) -> Category:
    obj = await _get_or_404(session, item_id, principal, scoped=False)
    ctx = HookContext(session=session, principal=principal)
    payload = await hooks.before_update(ctx, obj, payload)
    obj = await repo.update(session, obj, payload)
    await hooks.after_update(ctx, obj)
    return obj


@router.delete(
    "/{item_id}", status_code=status.HTTP_204_NO_CONTENT, responses=error_responses(404, 409)
)
async def delete_category(
    item_id: uuid.UUID,
    principal: CanDelete,
    session: SessionDep,
) -> None:
    obj = await _get_or_404(session, item_id, principal, scoped=False)
    ctx = HookContext(session=session, principal=principal)
    await hooks.before_delete(ctx, obj)
    await repo.delete(session, obj)
    await hooks.after_delete(ctx, obj)

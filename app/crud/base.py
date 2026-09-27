"""Repositorio CRUD genérico y asíncrono.

Los endpoints generados lo usan, pero puedes heredar de él para añadir
consultas propias. Toda la entrada que llega aquí ya viene validada, y los
nombres de columna para filtrar/ordenar salen de listas blancas del recurso.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any

from fastapi import HTTPException, status
from pydantic import BaseModel
from sqlalchemy import Table, and_, func, or_
from sqlalchemy import delete as sa_delete
from sqlalchemy import update as sa_update
from sqlmodel import SQLModel, col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.exceptions import APIError, DatabaseValueError
from app.db.types import utcnow


async def _commit(session: AsyncSession) -> None:
    try:
        await session.commit()
    except OverflowError as exc:  # sqlite3 no envuelve este error del driver
        await session.rollback()
        raise DatabaseValueError(str(exc)) from exc


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class Repository[ModelT: SQLModel]:
    def __init__(
        self,
        model: type[ModelT],
        *,
        owner_field: str | None = None,
        soft_delete: bool = False,
        search_fields: Iterable[str] = (),
        ordering_fields: Iterable[str] = ("created_at",),
        default_ordering: str = "-created_at",
    ) -> None:
        self.model = model
        self.owner_field = owner_field
        self.soft_delete = soft_delete
        self.search_fields = tuple(search_fields)
        self.ordering_fields = frozenset(ordering_fields)
        self.default_ordering = default_ordering

    # -- consultas -----------------------------------------------------------
    def _base_query(self, owner_id: uuid.UUID | None):
        query = select(self.model)
        if self.soft_delete:
            query = query.where(col(self.model.deleted_at).is_(None))  # type: ignore[attr-defined]
        if owner_id is not None and self.owner_field:
            query = query.where(getattr(self.model, self.owner_field) == owner_id)
        return query

    async def get(
        self, session: AsyncSession, id: uuid.UUID, *, owner_id: uuid.UUID | None = None
    ) -> ModelT | None:
        query = self._base_query(owner_id).where(self.model.id == id)  # type: ignore[attr-defined]
        return (await session.exec(query)).first()

    async def list(
        self,
        session: AsyncSession,
        *,
        offset: int = 0,
        limit: int = 20,
        filters: Mapping[str, Any] | None = None,
        search: str | None = None,
        order_by: str | None = None,
        owner_id: uuid.UUID | None = None,
        with_total: bool = True,
    ) -> tuple[list[ModelT], int]:
        query = self._base_query(owner_id)
        for field, value in (filters or {}).items():
            if value is not None:
                query = query.where(getattr(self.model, field) == value)
        if search and self.search_fields:
            pattern = f"%{escape_like(search)}%"
            query = query.where(
                or_(
                    *(
                        col(getattr(self.model, f)).ilike(pattern, escape="\\")
                        for f in self.search_fields
                    )
                )
            )

        total = -1
        if with_total:
            count_query = select(func.count()).select_from(query.order_by(None).subquery())
            total = (await session.exec(count_query)).one()

        ordering = order_by or self.default_ordering
        field = ordering.lstrip("-")
        if field not in self.ordering_fields and field != "created_at":
            field, ordering = "created_at", "-created_at"
        column = col(getattr(self.model, field))
        primary = column.desc() if ordering.startswith("-") else column.asc()
        # Desempate por id para que la paginación sea estable.
        tiebreak = col(self.model.id)  # type: ignore[attr-defined]
        query = query.order_by(primary, tiebreak.desc() if ordering.startswith("-") else tiebreak)

        items = (await session.exec(query.offset(offset).limit(limit))).all()
        return list(items), total

    # -- escritura ------------------------------------------------------------
    async def create(
        self, session: AsyncSession, data: BaseModel | Mapping[str, Any], **extra: Any
    ) -> ModelT:
        values = data.model_dump() if isinstance(data, BaseModel) else dict(data)
        values.update(extra)
        obj = self.model.model_validate(values)
        session.add(obj)
        await _commit(session)
        await session.refresh(obj)
        return obj

    async def update(
        self, session: AsyncSession, obj: ModelT, data: BaseModel | Mapping[str, Any]
    ) -> ModelT:
        values = data.model_dump(exclude_unset=True) if isinstance(data, BaseModel) else data
        for key, value in values.items():
            setattr(obj, key, value)
        if hasattr(obj, "updated_at"):
            obj.updated_at = utcnow()  # type: ignore[attr-defined]
        session.add(obj)
        await _commit(session)
        await session.refresh(obj)
        return obj

    async def delete(self, session: AsyncSession, obj: ModelT) -> None:
        if self.soft_delete:
            now = utcnow()
            try:
                # El borrado lógico no dispara los ON DELETE de la BD: se aplican aquí.
                await apply_on_delete(
                    session,
                    self.model.__table__,  # type: ignore[attr-defined]
                    [obj.id],  # type: ignore[attr-defined]
                    now,
                )
            except Exception:
                await session.rollback()
                raise
            obj.deleted_at = now  # type: ignore[attr-defined]
            session.add(obj)
        else:
            await session.delete(obj)
        await session.commit()


HAS_DEPENDENTS = APIError(
    status.HTTP_409_CONFLICT,
    "Cannot delete this record: other records reference it",
    code="has_dependents",
)


async def apply_on_delete(
    session: AsyncSession, table: Table, ids: Sequence[Any], when: datetime
) -> None:
    """Aplica el `on_delete` de las FK que apuntan a `table` al borrar lógicamente `ids`.

    Con soft delete la fila sigue existiendo, así que la BD no ejecuta sus acciones
    ON DELETE. Para que `on_delete` signifique lo mismo en los dos modos (UX-40),
    se reproducen sobre los hijos *vivos* (los ya borrados lógicamente se ignoran):
    - CASCADE: el hijo se borra lógicamente si tiene soft delete (y se repite con
      sus propios hijos); si no lo tiene, se borra de verdad y la BD aplica sus FK.
    - SET NULL: se vacía la columna.
    - RESTRICT / NO ACTION: 409 `has_dependents` si queda algún hijo vivo.
    Las FK se leen de los metadatos, así que también cubre recursos añadidos
    después del padre. Quien llama debe hacer rollback si esto lanza.
    """
    for child in list(table.metadata.tables.values()):
        for fk in child.foreign_keys:
            if fk.column.table is not table:
                continue
            column = fk.parent
            soft = "deleted_at" in child.c
            live = column.in_(ids)
            if soft:
                live = and_(live, child.c.deleted_at.is_(None))
            action = (fk.ondelete or "NO ACTION").upper()
            touched = {"updated_at": when} if "updated_at" in child.c else {}
            if action == "CASCADE" and soft:
                result = await session.execute(select(child.c.id).where(live))
                child_ids = list(result.scalars())
                if child_ids:
                    await session.execute(
                        sa_update(child)
                        .where(child.c.id.in_(child_ids))
                        .values(deleted_at=when, **touched)
                    )
                    await apply_on_delete(session, child, child_ids, when)
            elif action == "CASCADE":
                await session.execute(sa_delete(child).where(live))
            elif action == "SET NULL":
                await session.execute(
                    sa_update(child).where(live).values({column.name: None, **touched})
                )
            elif (await session.execute(select(column).where(live).limit(1))).first():
                raise HAS_DEPENDENTS


async def ensure_reference(
    session: AsyncSession,
    model: type[SQLModel],
    ref_id: uuid.UUID,
    *,
    owner_id: uuid.UUID | None = None,
    soft_delete: bool = False,
    field: str = "id",
    allowed: bool = True,
) -> None:
    """Comprueba que la fila referenciada existe y es visible para quien la usa.

    NO es código muerto: la llaman los routers generados (`_check_references` en
    `apigen/templates/router.py.j2`), que el grafo de graphify no indexa (SEC-28).

    Sin esto, un usuario podría enlazar su registro a una fila ajena conociendo
    (o adivinando) su ID, y deducir su existencia por el error devuelto.
    `allowed=False` (p. ej. destino que solo lee un admin) responde igual que si
    no existiera, sin consultar la BD.
    """
    if not allowed:
        raise _reference_not_found(field)
    query = select(model.id).where(model.id == ref_id)  # type: ignore[attr-defined]
    if owner_id is not None:
        query = query.where(model.owner_id == owner_id)  # type: ignore[attr-defined]
    if soft_delete:
        query = query.where(col(model.deleted_at).is_(None))  # type: ignore[attr-defined]
    if (await session.exec(query)).first() is None:
        raise _reference_not_found(field)


def _reference_not_found(field: str) -> HTTPException:
    return HTTPException(
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail=[
            {
                "loc": ["body", field],
                "msg": "Referenced resource not found",
                "type": "reference_not_found",
            }
        ],
    )

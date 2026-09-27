"""UX-40: `on_delete` también se respeta cuando el padre se borra lógicamente.

Se usan tablas Core en unos metadatos propios (no en los de la app) y una BD en
memoria, para no añadir tablas de prueba al esquema real ni a sus migraciones.
"""

import uuid
from datetime import datetime

import pytest
from sqlalchemy import Column, DateTime, ForeignKey, MetaData, String, Table, Uuid, select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.exceptions import APIError
from app.crud.base import apply_on_delete

meta = MetaData()


def _table(name: str, *extra, soft: bool = True) -> Table:
    cols = [Column("id", Uuid, primary_key=True), Column("name", String(20)), *extra]
    if soft:
        cols.append(Column("deleted_at", DateTime, nullable=True))
        cols.append(Column("updated_at", DateTime, nullable=True))
    return Table(name, meta, *cols)


def _fk(target: str, on_delete: str | None, nullable: bool = False) -> Column:
    return Column(
        f"{target}_id", Uuid, ForeignKey(f"{target}.id", ondelete=on_delete), nullable=nullable
    )


posts = _table("posts")
comments = _table("comments", _fk("posts", "CASCADE"))
replies = _table("replies", _fk("comments", "CASCADE"))
likes = _table("likes", _fk("posts", "CASCADE"), soft=False)
pins = _table("pins", _fk("posts", "SET NULL", nullable=True))
reports = _table("reports", _fk("posts", "RESTRICT"))
# Autorreferencia en cascada (hilos): no debe entrar en bucle.
threads = _table("threads")
threads.append_column(_fk("threads", "CASCADE", nullable=True))


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(meta.create_all)
    async with AsyncSession(engine) as s:
        yield s
    await engine.dispose()


async def _insert(session, table: Table, **values) -> uuid.UUID:
    row_id = uuid.uuid4()
    await session.execute(table.insert().values(id=row_id, name="x", **values))
    return row_id


async def _deleted_at(session, table: Table, row_id: uuid.UUID):
    return (await session.execute(select(table.c.deleted_at).where(table.c.id == row_id))).one()[0]


async def test_cascade_set_null_and_already_deleted_children(session):
    when = datetime(2026, 1, 1)
    earlier = datetime(2025, 1, 1)
    post = await _insert(session, posts)
    comment = await _insert(session, comments, posts_id=post)
    reply = await _insert(session, replies, comments_id=comment)
    old_comment = await _insert(session, comments, posts_id=post, deleted_at=earlier)
    await _insert(session, likes, posts_id=post)
    pin = await _insert(session, pins, posts_id=post)
    other_post = await _insert(session, posts)
    other_comment = await _insert(session, comments, posts_id=other_post)

    await apply_on_delete(session, posts, [post], when)

    assert await _deleted_at(session, comments, comment) == when  # CASCADE lógico
    assert await _deleted_at(session, replies, reply) == when  # ... y recursivo
    assert await _deleted_at(session, comments, old_comment) == earlier  # no se toca
    assert (await session.execute(select(likes))).all() == []  # hijo sin soft delete
    pinned = (await session.execute(select(pins.c.posts_id).where(pins.c.id == pin))).one()
    assert pinned[0] is None  # SET NULL
    assert await _deleted_at(session, comments, other_comment) is None  # otro padre


async def test_restrict_blocks_only_with_live_children(session):
    when = datetime(2026, 1, 1)
    post = await _insert(session, posts)
    await _insert(session, reports, posts_id=post, deleted_at=datetime(2025, 1, 1))
    await apply_on_delete(session, posts, [post], when)  # solo hijos borrados: vale

    blocked = await _insert(session, posts)
    await _insert(session, reports, posts_id=blocked)
    with pytest.raises(APIError) as exc:
        await apply_on_delete(session, posts, [blocked], when)
    assert exc.value.status_code == 409 and exc.value.code == "has_dependents"


async def test_self_referencing_cascade_terminates(session):
    when = datetime(2026, 1, 1)
    root = await _insert(session, threads)
    child = await _insert(session, threads, threads_id=root)
    await _insert(session, threads, threads_id=child)
    await session.execute(threads.update().where(threads.c.id == root).values(threads_id=child))
    await apply_on_delete(session, threads, [root], when)
    alive = (await session.execute(select(threads).where(threads.c.deleted_at.is_(None)))).all()
    assert alive == []

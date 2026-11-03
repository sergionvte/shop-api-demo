"""Derechos del interesado y retención (ISO 27701 7.3.6/7.3.8/7.4.7, SOC 2 P4-P5, C1.2).

Los recursos generados se simulan con una tabla propia en los metadatos de la app
(con FK a users y soft delete): la exportación y la retención descubren las tablas
en los metadatos, igual que harán con las de `apigen generate`.
"""

import logging
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import Column, DateTime, ForeignKey, String, Table, Uuid, select
from sqlmodel import SQLModel

from app.core.config import settings
from app.core.permissions import Role
from app.db.session import SessionFactory, engine
from app.db.types import utcnow
from app.models.user import User
from app.services import privacy
from tests.conftest import TEST_PASSWORD, create_user, headers_for

notes = Table(
    "privacy_test_notes",
    SQLModel.metadata,
    Column("id", Uuid, primary_key=True),
    Column("owner_id", Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True),
    Column("body", String(100), info={"pii": True}),
    Column("api_secret", String(100), info={"write_only": True}),
    Column("created_at", DateTime(timezone=True)),
    Column("deleted_at", DateTime(timezone=True), nullable=True),
)


@pytest.fixture(scope="module", autouse=True)
async def _notes_table():
    async with engine.begin() as conn:
        await conn.run_sync(notes.create, checkfirst=True)
    yield


async def _add_note(owner_id: uuid.UUID, deleted_days_ago: int | None = None) -> uuid.UUID:
    note_id = uuid.uuid4()
    deleted = utcnow() - timedelta(days=deleted_days_ago) if deleted_days_ago is not None else None
    async with SessionFactory() as session:
        await session.execute(
            notes.insert().values(
                id=note_id,
                owner_id=owner_id,
                body="mi nota",
                api_secret="no-exportar",
                created_at=utcnow(),
                deleted_at=deleted,
            )
        )
        await session.commit()
    return note_id


async def _note_exists(note_id: uuid.UUID) -> bool:
    async with SessionFactory() as session:
        return (
            await session.execute(select(notes.c.id).where(notes.c.id == note_id))
        ).first() is not None


# --- Exportación ----------------------------------------------------------------
async def test_export_contains_account_sessions_and_owned_rows(client, user, other_user, caplog):
    await _add_note(user.id)
    await _add_note(other_user.id)
    login = await client.post(
        "/api/v1/auth/login", data={"username": user.email, "password": TEST_PASSWORD}
    )
    assert login.status_code == 200
    with caplog.at_level(logging.INFO, logger="app.audit"):
        response = await client.get("/api/v1/users/me/export", headers=headers_for(user))
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    data = response.json()
    assert data["format"] == privacy.EXPORT_FORMAT
    assert data["account"]["email"] == user.email
    assert "hashed_password" not in data["account"]
    assert data["sessions"] and "token_hash" not in data["sessions"][0]
    rows = data["resources"]["privacy_test_notes"]["rows"]
    # Solo sus filas, y nunca las columnas write_only.
    assert {row["owner_id"] for row in rows} == {str(user.id)}
    assert all("api_secret" not in row for row in rows)
    assert any(r.getMessage() == "privacy.export" for r in caplog.records)


async def test_export_requires_auth_and_is_rate_limited(client, user):
    assert (await client.get("/api/v1/users/me/export")).status_code == 401
    codes = [
        (await client.get("/api/v1/users/me/export", headers=headers_for(user))).status_code
        for _ in range(6)
    ]
    assert codes[:5] == [200] * 5 and codes[5] == 429


async def test_export_marks_truncation(monkeypatch, user):
    monkeypatch.setattr(settings, "PRIVACY_EXPORT_MAX_ROWS", 1)
    await _add_note(user.id)
    await _add_note(user.id)
    async with SessionFactory() as session:
        data = await privacy.export_user_data(session, user)
    notes_export = data["resources"]["privacy_test_notes"]
    assert len(notes_export["rows"]) == 1 and notes_export["truncated"] is True


# --- Supresión ------------------------------------------------------------------
async def test_delete_me_erases_account_and_cascades(client, user, caplog):
    note_id = await _add_note(user.id)
    headers = headers_for(user)
    with caplog.at_level(logging.INFO, logger="app.audit"):
        response = await client.request(
            "DELETE", "/api/v1/users/me", json={"current_password": TEST_PASSWORD}, headers=headers
        )
    assert response.status_code == 204
    async with SessionFactory() as session:
        assert await session.get(User, user.id) is None
    assert not await _note_exists(note_id)
    # El token del usuario borrado deja de valer y el log no guarda su email.
    assert (await client.get("/api/v1/users/me", headers=headers)).status_code == 401
    erasure = [r for r in caplog.records if r.getMessage() == "privacy.erasure"]
    assert erasure and user.email not in caplog.text


async def test_delete_me_requires_password(client, user, caplog):
    with caplog.at_level(logging.INFO, logger="app.audit"):
        response = await client.request(
            "DELETE",
            "/api/v1/users/me",
            json={"current_password": "wrong-password-123"},
            headers=headers_for(user),
        )
    assert response.status_code == 400 and response.json()["code"] == "wrong_password"
    assert "privacy.erasure.wrong_password" in caplog.text
    missing = await client.request("DELETE", "/api/v1/users/me", headers=headers_for(user))
    assert missing.status_code == 422


async def test_delete_me_can_be_disabled(client, user, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_SELF_DELETION", False)
    response = await client.request(
        "DELETE",
        "/api/v1/users/me",
        json={"current_password": TEST_PASSWORD},
        headers=headers_for(user),
    )
    assert response.status_code == 403 and response.json()["code"] == "self_deletion_disabled"


async def test_last_admin_cannot_delete_itself(client, monkeypatch):
    admin = await create_user(Role.admin)

    async def one_admin(_session):
        return 1

    from app.api.v1.endpoints import users as users_endpoints

    monkeypatch.setattr(users_endpoints, "_admin_count", one_admin)
    response = await client.request(
        "DELETE",
        "/api/v1/users/me",
        json={"current_password": TEST_PASSWORD},
        headers=headers_for(admin),
    )
    assert response.status_code == 409 and response.json()["code"] == "last_admin"


async def test_read_only_token_cannot_delete_account(client, user):
    response = await client.request(
        "DELETE",
        "/api/v1/users/me",
        json={"current_password": TEST_PASSWORD},
        headers=headers_for(user, scopes=["read"]),
    )
    assert response.status_code == 403


# --- Retención ------------------------------------------------------------------
async def test_prune_soft_deleted_respects_retention(user):
    old = await _add_note(user.id, deleted_days_ago=settings.SOFT_DELETE_RETENTION_DAYS + 1)
    recent = await _add_note(user.id, deleted_days_ago=1)
    alive = await _add_note(user.id)
    async with SessionFactory() as session:
        removed = await privacy.prune_soft_deleted(session)
    assert removed >= 1
    assert not await _note_exists(old)
    assert await _note_exists(recent) and await _note_exists(alive)


async def test_prune_soft_deleted_disabled_with_zero(user, monkeypatch):
    monkeypatch.setattr(settings, "SOFT_DELETE_RETENTION_DAYS", 0)
    old = await _add_note(user.id, deleted_days_ago=400)
    async with SessionFactory() as session:
        assert await privacy.prune_soft_deleted(session) == 0
    assert await _note_exists(old)


async def test_prune_unverified_only_with_required_verification(monkeypatch):
    old = utcnow() - timedelta(days=settings.UNVERIFIED_ACCOUNT_RETENTION_DAYS + 1)
    stale = await create_user(created_at=old)
    stale_admin = await create_user(Role.admin, created_at=old)
    verified = await create_user(created_at=old, email_verified_at=old)
    fresh = await create_user()
    async with SessionFactory() as session:
        # Con verificación `off` (la de los tests) una cuenta sin verificar es normal.
        assert await privacy.prune_unverified_users(session) == 0
    monkeypatch.setattr(settings, "EMAIL_VERIFICATION", "required")
    async with SessionFactory() as session:
        assert await privacy.prune_unverified_users(session) >= 1
        remaining = {
            row
            for row in (
                await session.execute(
                    select(User.id).where(
                        User.id.in_([stale.id, stale_admin.id, verified.id, fresh.id])  # type: ignore[attr-defined]
                    )
                )
            ).scalars()
        }
    assert remaining == {stale_admin.id, verified.id, fresh.id}

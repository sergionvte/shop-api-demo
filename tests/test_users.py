"""Gestión de usuarios y control de acceso de administración."""

import uuid

from app.core.config import settings
from tests.conftest import TEST_PASSWORD, create_user, headers_for

LOGIN = "/api/v1/auth/login"


async def test_me_requires_auth(client):
    assert (await client.get("/api/v1/users/me")).status_code == 401


async def test_update_me_cannot_change_role(client, user_headers):
    r = await client.patch("/api/v1/users/me", json={"role": "admin"}, headers=user_headers)
    assert r.status_code == 422


async def test_regular_user_cannot_list_users(client, user_headers):
    assert (await client.get("/api/v1/users", headers=user_headers)).status_code == 403


async def test_admin_lists_and_searches_users(client, admin_headers, user):
    r = await client.get("/api/v1/users", params={"q": user.email}, headers=admin_headers)
    assert r.status_code == 200
    assert [u["id"] for u in r.json()["items"]] == [str(user.id)]


async def test_role_change_revokes_old_tokens(client, admin_headers, user):
    old = headers_for(user)
    r = await client.patch(
        f"/api/v1/users/{user.id}", json={"role": "admin"}, headers=admin_headers
    )
    assert r.status_code == 200
    assert (await client.get("/api/v1/users/me", headers=old)).status_code == 401


async def test_deactivated_user_loses_access(client, admin_headers, user):
    headers = headers_for(user)
    r = await client.patch(
        f"/api/v1/users/{user.id}", json={"is_active": False}, headers=admin_headers
    )
    assert r.status_code == 200
    assert (await client.get("/api/v1/users/me", headers=headers)).status_code == 401


async def test_null_role_rejected(client, admin_headers, user):
    r = await client.patch(f"/api/v1/users/{user.id}", json={"role": None}, headers=admin_headers)
    assert r.status_code == 422


async def test_admin_cannot_delete_self(client, admin, admin_headers, caplog):
    import logging

    with caplog.at_level(logging.WARNING, logger="app.audit"):
        r = await client.delete(f"/api/v1/users/{admin.id}", headers=admin_headers)
    assert r.status_code == 409 and r.json()["code"] == "self_delete"
    assert any(getattr(rec, "reason", None) == "self_delete" for rec in caplog.records)


async def test_pagination_bounds(client, admin_headers):
    assert (await client.get("/api/v1/users?limit=1000", headers=admin_headers)).status_code == 422
    assert (await client.get("/api/v1/users?offset=-1", headers=admin_headers)).status_code == 422
    r = await client.get("/api/v1/users?order_by=hashed_password", headers=admin_headers)
    assert r.status_code == 422


async def test_me_works_with_special_use_email_domain(client):
    """SEC-12: la salida no revalida el email; un dominio .test (alta por script)
    no debe romper /users/me con un 500."""
    user = await create_user(email=f"alice-{uuid.uuid4().hex[:6]}@lab.test")
    r = await client.get("/api/v1/users/me", headers=headers_for(user))
    assert r.status_code == 200
    assert r.json()["email"].endswith("@lab.test")


async def test_admin_can_create_users(client, admin_headers, user_headers):
    """UX-27: alta de usuarios por un admin (sirve con ALLOW_REGISTRATION=false)."""
    payload = {
        "email": f"staff-{uuid.uuid4().hex[:6]}@example.com",
        "password": "a long staff passphrase",
        "role": "admin",
    }
    assert (
        await client.post("/api/v1/users", json=payload, headers=user_headers)
    ).status_code == 403
    r = await client.post("/api/v1/users", json=payload, headers=admin_headers)
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "admin"
    again = await client.post("/api/v1/users", json=payload, headers=admin_headers)
    assert again.status_code == 409 and again.json()["code"] == "email_taken"


async def test_admin_unlock_resets_lockout(client, admin_headers):
    victim = await create_user()
    for _ in range(settings.LOGIN_MAX_ATTEMPTS):
        await client.post(LOGIN, data={"username": victim.email, "password": "wrong password!"})
    ok = {"username": victim.email, "password": TEST_PASSWORD}
    assert (await client.post(LOGIN, data=ok)).status_code == 401
    r = await client.post(f"/api/v1/users/{victim.id}/unlock", headers=admin_headers)
    assert r.status_code == 200 and r.json()["failed_login_attempts"] == 0
    assert (await client.post(LOGIN, data=ok)).status_code == 200


async def _only_one_active_admin(session) -> int:
    return 1


async def test_inactive_admin_can_be_demoted_and_deleted(client, admin_headers, monkeypatch):
    """SEC-30: un admin desactivado no cuenta para el mínimo; se puede degradar y borrar."""
    from app.api.v1.endpoints import users as users_endpoints
    from app.core.permissions import Role

    monkeypatch.setattr(users_endpoints, "_admin_count", _only_one_active_admin)
    other = await create_user(Role.admin, is_active=False)
    r = await client.patch(
        f"/api/v1/users/{other.id}", json={"role": "user"}, headers=admin_headers
    )
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "user"
    other = await create_user(Role.admin, is_active=False)
    r = await client.delete(f"/api/v1/users/{other.id}", headers=admin_headers)
    assert r.status_code == 204


async def test_last_active_admin_protected_and_audited(client, admin_headers, monkeypatch, caplog):
    """El último admin activo sigue protegido; el intento queda en app.audit."""
    import logging

    from app.api.v1.endpoints import users as users_endpoints
    from app.core.permissions import Role

    monkeypatch.setattr(users_endpoints, "_admin_count", _only_one_active_admin)
    other = await create_user(Role.admin)
    with caplog.at_level(logging.WARNING, logger="app.audit"):
        for method, kwargs in (
            ("patch", {"json": {"role": "user"}}),
            ("patch", {"json": {"is_active": False}}),
            ("delete", {}),
        ):
            r = await client.request(
                method.upper(), f"/api/v1/users/{other.id}", headers=admin_headers, **kwargs
            )
            assert r.status_code == 409 and r.json()["code"] == "last_admin"
    events = [rec for rec in caplog.records if rec.getMessage() == "admin.user.rejected"]
    assert len(events) == 3
    assert {e.reason for e in events} == {"last_admin"}
    assert {e.action for e in events} == {"update", "delete"}

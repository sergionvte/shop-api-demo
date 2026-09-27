"""Registro, login, bloqueo de cuenta, rotación y revocación de tokens."""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlmodel import col, select

from app.core.config import settings
from app.core.security import hash_token
from app.db.session import SessionFactory
from app.models.refresh_token import RefreshToken
from app.services import auth as auth_service
from tests.conftest import TEST_PASSWORD, client_from, create_user, headers_for

LOGIN = "/api/v1/auth/login"


async def _login(client, email, password=TEST_PASSWORD, **extra):
    return await client.post(LOGIN, data={"username": email, "password": password, **extra})


async def test_register_and_login(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": "New.User@Example.com", "password": "a very long passphrase"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["email"] == "new.user@example.com"
    assert "hashed_password" not in r.json()

    r = await _login(client, "new.user@example.com", "a very long passphrase")
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["refresh_token"].startswith("rt_")
    me = await client.get(
        "/api/v1/users/me", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert me.status_code == 200


async def test_register_rejects_role_escalation(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": "evil@example.com", "password": "a very long passphrase", "role": "admin"},
    )
    assert r.status_code == 422


async def test_register_weak_password(client):
    r = await client.post(
        "/api/v1/auth/register", json={"email": "weak@example.com", "password": "short"}
    )
    assert r.status_code == 422
    r = await client.post(
        "/api/v1/auth/register", json={"email": "weak2@example.com", "password": "password1234"}
    )
    assert r.status_code == 422


async def test_duplicate_email(client, user):
    r = await client.post(
        "/api/v1/auth/register", json={"email": user.email, "password": "a very long passphrase"}
    )
    assert r.status_code == 409
    assert r.json()["code"] == "email_taken"


async def test_weak_passwords_do_not_consume_register_quota(client):
    """S-1/UX: la política se valida en el esquema, antes del límite de registro."""
    quota = int(settings.RATE_LIMIT_REGISTER.split("/")[0])
    for _ in range(quota + 2):
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": f"w-{uuid.uuid4().hex[:8]}@example.com", "password": "short"},
        )
        assert r.status_code == 422
        assert r.json()["detail"][0]["type"] == "password_policy"
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": f"ok-{uuid.uuid4().hex[:8]}@example.com", "password": "a long passphrase!"},
    )
    assert r.status_code == 201, r.text


async def test_password_policy_message_names_email_part(client):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": "alice@example.com", "password": "Alice-Clave-Larga-1"},
    )
    assert r.status_code == 422
    assert "first part of your email ('alice')" in r.json()["detail"][0]["msg"]


async def test_login_with_json_gets_explicit_error(client, user):
    r = await client.post(LOGIN, json={"username": user.email, "password": TEST_PASSWORD})
    assert r.status_code == 415
    assert r.json()["code"] == "login_expects_form"


async def test_login_errors_are_indistinguishable(client, user):
    wrong_password = await _login(client, user.email, "not the password")
    unknown_user = await _login(client, "nobody@example.com", "not the password")
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


async def test_account_lockout(client):
    victim = await create_user()
    for _ in range(settings.LOGIN_MAX_ATTEMPTS):
        assert (await _login(client, victim.email, "wrong password!")).status_code == 401
    # Aun con la contraseña correcta, la cuenta está bloqueada (origen desconocido).
    assert (await _login(client, victim.email)).status_code == 401


async def test_lockout_by_third_party_does_not_lock_out_owner(client):
    """SEC-02: un anónimo que conoce el email ya no deja fuera al titular desde
    una IP donde ya inició sesión; para orígenes desconocidos sigue bloqueada."""
    victim = await create_user()
    assert (await _login(client, victim.email)).status_code == 200  # IP conocida
    async with client_from("198.51.100.7") as attacker:
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            assert (await _login(attacker, victim.email, "wrong password!")).status_code == 401
        # El atacante (o cualquier IP nueva) no puede seguir probando: bloqueada.
        assert (await _login(attacker, victim.email)).status_code == 401
    async with client_from("192.0.2.44") as new_place:
        assert (await _login(new_place, victim.email)).status_code == 401
    # El titular, desde su IP habitual, entra con normalidad y se reinicia el contador.
    assert (await _login(client, victim.email)).status_code == 200


def test_lockout_duration_escalates(monkeypatch):
    monkeypatch.setattr(settings, "LOGIN_MAX_ATTEMPTS", 5)
    monkeypatch.setattr(settings, "LOGIN_LOCKOUT_MINUTES", 15)
    monkeypatch.setattr(settings, "LOGIN_LOCKOUT_MAX_MINUTES", 240)
    assert [auth_service.lockout_minutes(n) for n in (5, 10, 15, 20, 25, 500)] == [
        15,
        30,
        60,
        120,
        240,
        240,
    ]


async def test_inactive_user_cannot_login(client):
    inactive = await create_user(is_active=False)
    assert (await _login(client, inactive.email)).status_code == 401


async def test_login_rate_limited(client, user, caplog):
    import logging

    with caplog.at_level(logging.WARNING, logger="app.audit"):
        statuses = [(await _login(client, user.email, "x" * 12)).status_code for _ in range(12)]
    assert 429 in statuses
    # El 429 de login queda auditado (con IP y ruta, sin email).
    events = [r for r in caplog.records if r.getMessage() == "auth.rate_limited"]
    assert events and events[0].path == "/api/v1/auth/login"
    assert not hasattr(events[0], "email")


async def test_refresh_rotation_and_reuse_detection(client, user):
    tokens = (await _login(client, user.email)).json()
    first = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert first.status_code == 200
    rotated = first.json()["refresh_token"]
    assert rotated != tokens["refresh_token"]

    # Reutilizar el token viejo desde otro origen (robo) revoca toda la sesión,
    # incluido el nuevo, y también los access tokens ya emitidos (SEC-16).
    async with client_from("203.0.113.9") as attacker:
        reuse = await attacker.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
    assert reuse.status_code == 401
    after = await client.post("/api/v1/auth/refresh", json={"refresh_token": rotated})
    assert after.status_code == 401
    access = {"Authorization": f"Bearer {first.json()['access_token']}"}
    assert (await client.get("/api/v1/users/me", headers=access)).status_code == 401


async def _stale_race(client, user) -> tuple[object, HTTPException, str]:
    """Reproduce de forma determinista la carrera de SEC-01: el "perdedor" leyó la
    fila cuando aún no estaba revocada y el ganador la rota antes de su UPDATE."""
    old = (await _login(client, user.email)).json()["refresh_token"]
    async with SessionFactory() as loser:
        row = (
            await loser.exec(select(RefreshToken).where(RefreshToken.token_hash == hash_token(old)))
        ).first()
        assert row is not None and row.revoked_at is None
        await loser.commit()  # la instancia queda en el identity map con datos viejos
        winner = await client.post("/api/v1/auth/refresh", json={"refresh_token": old})
        assert winner.status_code == 200
        with pytest.raises(HTTPException) as caught:
            await auth_service.rotate_refresh_token(loser, old, "pytest", "127.0.0.1")
    return winner, caught.value, old


async def test_refresh_race_loser_revokes_family_without_grace(client, user, monkeypatch):
    """SEC-01: el perdedor de la carrera recibe 401 (no 500) y la familia se revoca."""
    monkeypatch.setattr(settings, "REFRESH_REUSE_GRACE_SECONDS", 0)
    winner, error, _ = await _stale_race(client, user)
    assert error.status_code == 401
    after = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": winner.json()["refresh_token"]}
    )
    assert after.status_code == 401


async def test_refresh_race_same_client_within_grace_keeps_session(client, user):
    """UX-19: dos pestañas del mismo cliente -> 409 sin revocar; el token del
    ganador sigue valiendo."""
    winner, error, _ = await _stale_race(client, user)
    assert error.status_code == 409
    assert getattr(error, "code", None) == "refresh_token_rotated"
    after = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": winner.json()["refresh_token"]}
    )
    assert after.status_code == 200


async def test_concurrent_refresh_never_returns_500(client, user):
    for _ in range(3):
        old = (await _login(client, user.email)).json()["refresh_token"]
        responses = await asyncio.gather(
            *(client.post("/api/v1/auth/refresh", json={"refresh_token": old}) for _ in range(3))
        )
        codes = sorted(r.status_code for r in responses)
        assert codes.count(200) == 1, codes
        assert set(codes) <= {200, 401, 409}, codes


async def test_reuse_after_grace_period_revokes(client, user):
    tokens = (await _login(client, user.email)).json()
    first = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    rotated = first.json()["refresh_token"]
    # Simulamos que el sucesor se emitió hace más que el periodo de gracia.
    async with SessionFactory() as db:
        row = (
            await db.exec(
                select(RefreshToken).where(RefreshToken.token_hash == hash_token(rotated))
            )
        ).one()
        row.created_at = datetime.now(UTC) - timedelta(
            seconds=settings.REFRESH_REUSE_GRACE_SECONDS + 5
        )
        db.add(row)
        await db.commit()
    reuse = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert reuse.status_code == 401
    assert (
        await client.post("/api/v1/auth/refresh", json={"refresh_token": rotated})
    ).status_code == 401


async def test_logged_out_token_reuse_has_no_side_effects(client, user):
    """Un refresh revocado por logout no es "reutilización": 401 sin tocar las
    demás sesiones ni los access tokens."""
    one = (await _login(client, user.email)).json()
    two = (await _login(client, user.email)).json()
    await client.post("/api/v1/auth/logout", json={"refresh_token": one["refresh_token"]})
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": one["refresh_token"]})
    assert r.status_code == 401
    headers = {"Authorization": f"Bearer {two['access_token']}"}
    assert (await client.get("/api/v1/users/me", headers=headers)).status_code == 200


async def test_expired_token_is_distinguishable(client, user, monkeypatch):
    """UX-12: token caducado -> code token_expired (RFC 6750 error_description)."""
    from app.core import security

    past = datetime.now(UTC) - timedelta(hours=1)

    class Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return past

    monkeypatch.setattr(security, "datetime", Frozen)
    expired = headers_for(user)
    monkeypatch.undo()
    r = await client.get("/api/v1/users/me", headers=expired)
    assert r.status_code == 401
    assert r.json()["code"] == "token_expired"
    assert 'error="invalid_token"' in r.headers["www-authenticate"]
    r = await client.get("/api/v1/users/me", headers={"Authorization": "Bearer garbage"})
    assert r.json()["code"] == "invalid_token"
    assert (await client.get("/api/v1/users/me")).json()["code"] == "not_authenticated"


async def test_logout_revokes_refresh(client, user):
    tokens = (await _login(client, user.email)).json()
    r = await client.post("/api/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 204
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401


async def test_logout_all_invalidates_access_tokens(client, user):
    tokens = (await _login(client, user.email)).json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert (await client.post("/api/v1/auth/logout-all", headers=headers)).status_code == 204
    assert (await client.get("/api/v1/users/me", headers=headers)).status_code == 401


async def test_scoped_read_only_token(client, user):
    tokens = (await _login(client, user.email, scope="read")).json()
    assert tokens["scope"] == "read"
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert (await client.get("/api/v1/users/me", headers=headers)).status_code == 200
    r = await client.patch("/api/v1/users/me", json={"full_name": "X"}, headers=headers)
    assert r.status_code == 403


async def test_cannot_request_scopes_beyond_role(client, user):
    tokens = (await _login(client, user.email, scope="read admin")).json()
    assert tokens["scope"] == "read"


async def test_change_password_revokes_sessions(client, user):
    headers = headers_for(user)
    r = await client.post(
        "/api/v1/users/me/password",
        json={"current_password": TEST_PASSWORD, "new_password": "another long passphrase"},
        headers=headers,
    )
    assert r.status_code == 204
    assert (await client.get("/api/v1/users/me", headers=headers)).status_code == 401
    assert (await _login(client, user.email, "another long passphrase")).status_code == 200


async def test_owner_login_during_lockout_keeps_lock_for_others(client):
    """SEC-20: el login del titular desde su IP no levanta el bloqueo ni reinicia
    el escalado para el resto de orígenes."""
    from app.models.user import User

    victim = await create_user()
    assert (await _login(client, victim.email)).status_code == 200  # IP conocida
    async with client_from("198.51.100.20") as attacker:
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            await _login(attacker, victim.email, "wrong password!")
        assert (await _login(client, victim.email)).status_code == 200
        # Ni siquiera con la contraseña correcta: sigue bloqueada para el atacante.
        assert (await _login(attacker, victim.email)).status_code == 401
    async with SessionFactory() as db:
        fresh = await db.get(User, victim.id)
        assert fresh.failed_login_attempts == settings.LOGIN_MAX_ATTEMPTS
        assert fresh.locked_until is not None


async def test_password_change_forgets_familiar_ips(client):
    """Condición T1: tras cambiar la contraseña, las IPs de logins anteriores dejan
    de estar exentas del bloqueo."""
    victim = await create_user()
    tokens = (await _login(client, victim.email)).json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    new = "another long passphrase"
    r = await client.post(
        "/api/v1/users/me/password",
        json={"current_password": TEST_PASSWORD, "new_password": new},
        headers=headers,
    )
    assert r.status_code == 204
    async with client_from("198.51.100.21") as attacker:
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            await _login(attacker, victim.email, "wrong password!")
    assert (await _login(client, victim.email, new)).status_code == 401


async def test_logout_after_409_revokes_the_whole_family(client, user):
    """Condición T2: tras un 409 refresh_token_rotated, si el cliente no tiene un
    refresh más nuevo, llama a /auth/logout con el viejo: se revoca toda la familia,
    incluido el token que se llevó quien ganó la carrera (quizá un atacante)."""
    winner, error, old = await _stale_race(client, user)
    assert error.status_code == 409
    assert (
        await client.post("/api/v1/auth/logout", json={"refresh_token": old})
    ).status_code == 204
    after = await client.post(
        "/api/v1/auth/refresh", json={"refresh_token": winner.json()["refresh_token"]}
    )
    assert after.status_code == 401


async def test_prune_removes_only_dead_old_sessions(user):
    """SEC-23: retención de refresh tokens (y de su IP)."""
    now = datetime.now(UTC)
    old = now - timedelta(days=settings.LOGIN_FAMILIAR_DAYS + 5)
    dead_family, live_family = uuid.uuid4(), uuid.uuid4()
    async with SessionFactory() as db:
        rows = [
            # Sesión muerta y antigua -> se borra.
            RefreshToken(user_id=user.id, family_id=dead_family, token_hash=uuid.uuid4().hex,
                         client_ip="192.0.2.1", created_at=old, expires_at=old,
                         revoked_at=old),
            # Token rotado antiguo de una sesión VIVA -> se conserva (detección de robo).
            RefreshToken(user_id=user.id, family_id=live_family, token_hash=uuid.uuid4().hex,
                         created_at=old, expires_at=now + timedelta(days=1), revoked_at=old),
            RefreshToken(user_id=user.id, family_id=live_family, token_hash=uuid.uuid4().hex,
                         created_at=now, expires_at=now + timedelta(days=1)),
        ]  # fmt: skip
        db.add_all(rows)
        await db.commit()
        ids = [r.id for r in rows]
        removed = await auth_service.prune_refresh_tokens(db, user_id=user.id)
        assert removed == 1
        left = (await db.exec(select(RefreshToken.id).where(col(RefreshToken.id).in_(ids)))).all()
        assert set(left) == set(ids[1:])

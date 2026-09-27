"""Flujos de cuenta: recuperación de contraseña, verificación y cambio de email.

Sin correos reales: backend `memory` (fixture `mail`) y `process_pending()` para que
el "worker" ejecute los trabajos encolados.
"""

import asyncio
import logging
import re
from datetime import timedelta
from urllib.parse import unquote

import pytest
from sqlalchemy import update
from sqlmodel import col, select

from app.core.config import settings
from app.db.session import SessionFactory
from app.db.types import utcnow
from app.models.account_token import AccountToken
from app.models.email_log import EmailLog
from app.models.job import Job
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.tasks.worker import process_pending
from tests.conftest import TEST_PASSWORD, client_from, create_user, headers_for
from tests.helpers import _uid

API = "/api/v1"
FORGOT = f"{API}/auth/password/forgot"
RESET = f"{API}/auth/password/reset"
VALIDATE = f"{API}/auth/password/reset/validate"
VERIFY = f"{API}/auth/email/verify"
RESEND = f"{API}/auth/email/verify/resend"
REGISTER = f"{API}/auth/register"
LOGIN = f"{API}/auth/login"
NEW_PASSWORD = "a brand new passphrase"
TOKEN = re.compile(r"#token=([A-Za-z0-9_\-%]+)")


def token_from(message) -> str:
    return unquote(TOKEN.search(message.text).group(1))


def sent_to(outbox, address):
    return [m for m in outbox if address in m.to]


async def _login(client, email, password=TEST_PASSWORD):
    return await client.post(LOGIN, data={"username": email, "password": password})


async def _user(user_id) -> User:
    async with SessionFactory() as session:
        return await session.get(User, user_id)


async def _reset_token(client, outbox, user) -> str:
    r = await client.post(FORGOT, json={"email": user.email})
    assert r.status_code == 202
    await process_pending()
    return token_from(sent_to(outbox, user.email)[-1])


# --- Desactivado por defecto ------------------------------------------------------
async def test_everything_is_off_by_default(client, user, user_headers, outbox):
    assert (await client.post(FORGOT, json={"email": user.email})).json()["code"] == (
        "password_reset_disabled"
    )
    assert (await client.post(RESET, json={"token": "x", "new_password": "y"})).status_code == 403
    r = await client.post(RESEND, headers=user_headers)
    assert r.json()["code"] == "email_verification_disabled"
    r = await client.post(
        f"{API}/users/me/email",
        headers=user_headers,
        json={"new_email": "x@example.com", "current_password": TEST_PASSWORD},
    )
    assert r.json()["code"] == "email_change_disabled"
    # El registro sigue como antes: 201 con UserRead (y 409 si ya existe).
    email = f"legacy-{_uid()}@example.com"
    r = await client.post(REGISTER, json={"email": email, "password": NEW_PASSWORD})
    assert r.status_code == 201 and r.json()["email_verified"] is False
    r = await client.post(REGISTER, json={"email": email, "password": NEW_PASSWORD})
    assert r.status_code == 409
    features = (await client.get(f"{API}/auth/features")).json()
    assert features == {
        "registration": True,
        "email_verification": "off",
        "password_reset": False,
        "email_change": False,
    }
    await process_pending()
    assert outbox == []


# --- Recuperación de contraseña ----------------------------------------------------
async def test_password_reset_full_flow(client, mail, user):
    login = (await _login(client, user.email)).json()
    old_access = {"Authorization": f"Bearer {login['access_token']}"}

    token = await _reset_token(client, mail, user)
    message = sent_to(mail, user.email)[-1]
    assert token.startswith("pr_") and len(token) >= 46
    assert "https://app.example.com/reset-password#token=" in message.text
    assert (await client.post(VALIDATE, json={"token": token})).status_code == 204

    r = await client.post(RESET, json={"token": token, "new_password": NEW_PASSWORD})
    assert r.status_code == 204, r.text
    assert "access_token" not in r.text  # no inicia sesión (REQ-F05)
    assert r.headers["cache-control"] == "no-store"
    # ST-18: sesiones anteriores revocadas al instante.
    assert (await client.get(f"{API}/users/me", headers=old_access)).status_code == 401
    r = await client.post(f"{API}/auth/refresh", json={"refresh_token": login["refresh_token"]})
    assert r.status_code == 401
    assert (await _login(client, user.email)).status_code == 401
    assert (await _login(client, user.email, NEW_PASSWORD)).status_code == 200
    # ST-11: un solo uso.
    r = await client.post(RESET, json={"token": token, "new_password": "another passphrase ok"})
    assert r.status_code == 400 and r.json()["code"] == "invalid_or_expired_token"
    # ST-44: aviso "tu contraseña ha cambiado", sin tokens.
    await process_pending()
    notice = sent_to(mail, user.email)[-1]
    assert "changed" in notice.subject and "token" not in notice.text
    refreshed = await _user(user.id)
    assert refreshed.email_verified_at is not None and refreshed.password_changed_at


async def test_forgot_is_uniform_and_sends_only_to_existing_accounts(client, mail, user):
    """ST-05/27/07: misma respuesta siempre; solo se envía a cuentas activas, a la
    dirección de la BD."""
    inactive = await create_user(is_active=False)
    bodies = set()
    for email in (user.email.upper(), "nobody-" + _uid() + "@example.com", inactive.email):
        r = await client.post(FORGOT, json={"email": email})
        assert r.status_code == 202
        bodies.add(r.text)
    assert len(bodies) == 1
    await process_pending()
    assert [m.to for m in mail] == [(user.email,)]


async def test_forgot_payload_is_strict(client, mail):
    """ST-06: listas, objetos o campos extra → 422 y ningún trabajo."""
    for body in (
        {"email": ["a@example.com", "b@example.com"]},
        {"email": {"a": 1}},
        {"email": "a@example.com", "extra": 1},
    ):
        assert (await client.post(FORGOT, json=body)).status_code == 422


@pytest.mark.parametrize(
    "token",
    [
        "pr_" + "a" * 10_000,
        "pr_" + "a" * 40 + "\x00",
        "pr_" + "a" * 40 + "!$",
        "ev_" + "a" * 43,
        "rt_" + "a" * 43,
        12345,
    ],
)
async def test_bad_tokens_get_the_same_400(client, mail, token):
    """ST-13/16: forma inválida, otro propósito o tamaño enorme → mismo 400, sin 500."""
    r = await client.post(RESET, json={"token": token, "new_password": NEW_PASSWORD})
    if isinstance(token, int):
        assert r.status_code == 422  # tipo JSON distinto: error de forma, no de cuenta
    else:
        assert r.status_code == 400 and r.json()["code"] == "invalid_or_expired_token"


async def test_token_of_one_purpose_never_serves_another(client, mail, user):
    token = await _reset_token(client, mail, user)
    r = await client.post(VERIFY, json={"token": token})
    assert r.status_code == 400
    forged = "ev_" + token[3:]  # cambiar el prefijo no cambia el propósito (REQ-T06)
    assert (await client.post(VERIFY, json={"token": forged})).status_code == 400


async def test_weak_password_keeps_the_token_valid(client, mail, user):
    """ST-17: el 422 de política no consume el enlace."""
    token = await _reset_token(client, mail, user)
    r = await client.post(RESET, json={"token": token, "new_password": "short"})
    assert r.status_code == 422 and r.json()["detail"][0]["type"] == "password_policy"
    r = await client.post(RESET, json={"token": token, "new_password": NEW_PASSWORD})
    assert r.status_code == 204


async def test_expired_token_is_rejected(client, mail, user):
    """ST-12: caducado → mismo 400 que inexistente."""
    token = await _reset_token(client, mail, user)
    async with SessionFactory() as session:
        await session.execute(
            update(AccountToken)
            .where(col(AccountToken.user_id) == user.id)
            .values(expires_at=utcnow() - timedelta(seconds=1))
        )
        await session.commit()
    r = await client.post(RESET, json={"token": token, "new_password": NEW_PASSWORD})
    assert r.status_code == 400 and r.json()["code"] == "invalid_or_expired_token"


async def test_concurrent_resets_only_one_wins(client, mail, user):
    """ST-11: dos consumos a la vez → exactamente un 204."""
    token = await _reset_token(client, mail, user)
    results = await asyncio.gather(
        *(client.post(RESET, json={"token": token, "new_password": NEW_PASSWORD}) for _ in range(2))
    )
    assert sorted(r.status_code for r in results) == [204, 400]


async def test_using_one_reset_invalidates_the_others(client, mail, user, user_headers):
    """ST-14: dos resets pedidos, uno usado → el otro no vale; cambiar la contraseña
    por /users/me/password invalida los pendientes."""
    first = await _reset_token(client, mail, user)
    second = await _reset_token(client, mail, user)
    assert first != second
    assert (
        await client.post(RESET, json={"token": second, "new_password": NEW_PASSWORD})
    ).status_code == 204
    assert (
        await client.post(RESET, json={"token": first, "new_password": NEW_PASSWORD})
    ).status_code == 400

    other = await create_user()
    pending = await _reset_token(client, mail, other)
    r = await client.post(
        f"{API}/users/me/password",
        headers=headers_for(other),
        json={"current_password": TEST_PASSWORD, "new_password": NEW_PASSWORD},
    )
    assert r.status_code == 204
    r = await client.post(RESET, json={"token": pending, "new_password": "yet another passphrase"})
    assert r.status_code == 400
    await process_pending()
    assert "changed" in sent_to(mail, other.email)[-1].subject  # aviso también aquí (F04)


async def test_reset_unlocks_account_and_known_ip_loses_exemption(client, mail, user):
    """ST-21/19 y D2: una cuenta bloqueada completa el reset y entra; la IP conocida
    de antes del reset deja de estar exenta del bloqueo."""
    known = client_from("198.51.100.7")
    async with known:
        assert (await _login(known, user.email)).status_code == 200
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            await _login(client, user.email, "wrong password!!")
        assert (await _user(user.id)).locked_until is not None
        token = await _reset_token(client, mail, user)
        r = await client.post(RESET, json={"token": token, "new_password": NEW_PASSWORD})
        assert r.status_code == 204
        fresh = await _user(user.id)
        assert fresh.locked_until is None and fresh.failed_login_attempts == 0
        # Nuevo bloqueo tras el reset: la IP conocida ya no está exenta.
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            await _login(client, user.email, "wrong password!!")
        assert (await _login(known, user.email, NEW_PASSWORD)).status_code == 401


async def test_invalid_requests_do_not_touch_lockout(client, mail, user):
    """ST-20: forgot y reset inválidos no alteran el contador de ninguna cuenta."""
    for _ in range(10):
        await client.post(FORGOT, json={"email": user.email})
        await client.post(RESET, json={"token": "pr_" + "b" * 43, "new_password": NEW_PASSWORD})
    fresh = await _user(user.id)
    assert fresh.failed_login_attempts == 0 and fresh.locked_until is None


async def test_account_takeover_by_preregistration_is_undone(client, mail):
    """ST-23: el atacante registra el email de la víctima (optional: puede entrar); la
    víctima hace reset → la contraseña del atacante y sus sesiones dejan de valer."""
    email = f"victim-{_uid()}@example.com"
    r = await client.post(REGISTER, json={"email": email, "password": "attacker passphrase"})
    assert r.status_code == 202
    attacker = (await _login(client, email, "attacker passphrase")).json()
    victim = await _user_by_email(email)
    token = await _reset_token(client, mail, victim)
    assert (
        await client.post(RESET, json={"token": token, "new_password": NEW_PASSWORD})
    ).status_code == 204
    r = await client.get(
        f"{API}/users/me", headers={"Authorization": f"Bearer {attacker['access_token']}"}
    )
    assert r.status_code == 401
    assert (await _login(client, email, "attacker passphrase")).status_code == 401


async def _user_by_email(email) -> User:
    async with SessionFactory() as session:
        return (await session.exec(select(User).where(User.email == email))).first()


# --- Enlaces, cabeceras y cola ------------------------------------------------------
async def test_links_ignore_request_host(client, mail, user):
    """ST-28/29: Host, X-Forwarded-Host, Origin o Referer maliciosos no cambian el enlace."""
    await client.post(
        FORGOT,
        json={"email": user.email},
        headers={
            "Host": "evil.test",
            "X-Forwarded-Host": "evil.test",
            "Origin": "https://evil.test",
            "Referer": "https://evil.test/",
        },
    )
    await process_pending()
    text = sent_to(mail, user.email)[-1].text
    assert "evil" not in text and "https://app.example.com/reset-password#token=pr_" in text
    assert (await client.get(f"{RESET}?token=x")).status_code == 405  # no hay GET


async def test_tokens_never_stored_in_clear(client, mail, user):
    """ST-10: en BD solo hashes; nada del token en jobs.payload/result/error; los jobs de
    correo son de sistema y su payload se vacía al terminar."""
    token = await _reset_token(client, mail, user)
    async with SessionFactory() as session:
        rows = (
            await session.exec(select(AccountToken).where(col(AccountToken.user_id) == user.id))
        ).all()
        jobs = (await session.exec(select(Job).where(col(Job.name).like("auth.%")))).all()
    assert rows and all(re.fullmatch(r"[0-9a-f]{64}", r.token_hash) for r in rows)
    for job in jobs:
        dump = f"{job.payload}{job.result}{job.error}"
        assert token not in dump and token[3:20] not in dump
        assert job.owner_id is None
    done = [j for j in jobs if j.status == "succeeded"]
    assert done and all(j.payload == {} for j in done)


async def test_user_cannot_see_email_jobs(client, mail, user, user_headers):
    """ST-40: los trabajos de correo no aparecen en /jobs del usuario."""
    await client.post(FORGOT, json={"email": user.email})
    r = await client.get(f"{API}/jobs", headers=user_headers)
    assert r.status_code == 200 and r.json()["total"] == 0


async def test_per_account_quota_across_ips(client, mail, user, monkeypatch):
    """ST-25 (D3): 3 correos/hora por cuenta sumando forgot, resend y registro duplicado,
    aunque cada petición llegue desde otra IP."""
    monkeypatch.setattr(settings, "EMAIL_PER_ACCOUNT_PER_HOUR", 3)
    for index in range(6):
        async with client_from(f"203.0.113.{index + 1}") as other_ip:
            if index % 3 == 0:
                await other_ip.post(FORGOT, json={"email": user.email})
            elif index % 3 == 1:
                await other_ip.post(RESEND, json={"email": user.email})
            else:
                await other_ip.post(REGISTER, json={"email": user.email, "password": NEW_PASSWORD})
        await process_pending()
    # El usuario de la fixture ya está verificado: el reenvío se descarta por eso.
    assert len(sent_to(mail, user.email)) == 3
    async with SessionFactory() as session:
        jobs = (await session.exec(select(Job).where(col(Job.name).like("auth.%")))).all()
    reasons = {
        j.result.get("reason") for j in jobs if j.result and j.result.get("status") == "suppressed"
    }
    assert "quota" in reasons


async def test_cooldown_between_emails(client, mail, user, monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_PER_ACCOUNT_COOLDOWN_SECONDS", 60)
    await client.post(FORGOT, json={"email": user.email})
    await client.post(FORGOT, json={"email": user.email})
    await process_pending()
    assert len(sent_to(mail, user.email)) == 1


async def test_stale_or_revalidated_jobs_are_not_sent(client, mail, user):
    """ST-43: un reset más viejo que la vida del token, o de un usuario desactivado
    entre el encolado y el envío, no se envía."""
    await client.post(FORGOT, json={"email": user.email})
    async with SessionFactory() as session:
        job = (await session.exec(select(Job).where(col(Job.name) == "auth.password_reset"))).all()[
            -1
        ]
        payload = dict(job.payload)
        payload["requested_at"] = (utcnow() - timedelta(hours=2)).isoformat()
        await session.execute(update(Job).where(col(Job.id) == job.id).values(payload=payload))
        await session.commit()
    await process_pending()
    assert sent_to(mail, user.email) == []

    other = await create_user()
    await client.post(FORGOT, json={"email": other.email})
    async with SessionFactory() as session:
        await session.execute(update(User).where(col(User.id) == other.id).values(is_active=False))
        await session.commit()
    await process_pending()
    assert sent_to(mail, other.email) == []


async def test_retry_after_send_does_not_resend(client, mail, user):
    """ST-41: con `sent_at` ya escrito, reintentar el trabajo no reenvía."""
    await client.post(FORGOT, json={"email": user.email})
    await process_pending()
    assert len(sent_to(mail, user.email)) == 1
    async with SessionFactory() as session:
        log = (await session.exec(select(EmailLog).where(col(EmailLog.user_id) == user.id))).first()
        assert log.sent_at is not None
        await session.execute(
            update(Job).where(col(Job.id) == log.job_id).values(status="queued", run_after=utcnow())
        )
        await session.commit()
    await process_pending()
    assert len(sent_to(mail, user.email)) == 1


async def test_transient_failure_retries_and_permanent_does_not(client, mail, user, monkeypatch):
    """ST-42: un fallo pasajero se reintenta; uno definitivo falla sin reintento, con un
    mensaje genérico en job.error."""
    from app.email.backends import PermanentEmailError, TransientEmailError, get_backend

    backend = get_backend()
    errors = [TransientEmailError("smtp_421", "x"), PermanentEmailError("smtp_550", "y")]

    async def failing(message):
        raise errors.pop(0)

    monkeypatch.setattr(backend, "send", failing)
    await client.post(FORGOT, json={"email": user.email})
    await process_pending()
    async with SessionFactory() as session:
        job = (await session.exec(select(Job).where(col(Job.name) == "auth.password_reset"))).all()[
            -1
        ]
        assert job.status == "queued" and job.error == "Email delivery failed (transient)"
        await session.execute(update(Job).where(col(Job.id) == job.id).values(run_after=utcnow()))
        await session.commit()
    await process_pending()
    async with SessionFactory() as session:
        job = await session.get(Job, job.id)
    assert job.status == "failed" and job.error == "Email delivery failed (permanent)"
    assert job.payload == {}


async def test_circuit_breaker_pauses_sending(client, mail, user, monkeypatch, caplog):
    """ST-26 y SEC-40: el presupuesto general agotado pausa los correos masivos (y se
    audita a nivel ERROR), pero NO el reset, que tiene su propio presupuesto; agotado el
    de seguridad, también se pausa."""
    monkeypatch.setattr(settings, "EMAIL_MAX_PER_HOUR", 1)
    async with SessionFactory() as session:
        session.add(EmailLog(kind="custom:test", sent_at=utcnow()))
        await session.commit()
    unverified = await create_user()
    await client.post(RESEND, json={"email": unverified.email})
    await client.post(FORGOT, json={"email": user.email})
    with caplog.at_level("ERROR", logger="app.audit"):
        await process_pending()
    assert sent_to(mail, unverified.email) == []  # verificación: presupuesto general
    assert len(sent_to(mail, user.email)) == 1  # reset: presupuesto de seguridad
    assert any(
        getattr(r, "reason", None) == "circuit_open" and r.levelname == "ERROR"
        for r in caplog.records
    )
    monkeypatch.setattr(settings, "EMAIL_MAX_SECURITY_PER_HOUR", 1)
    other = await create_user()
    await client.post(FORGOT, json={"email": other.email})
    await process_pending()
    assert sent_to(mail, other.email) == []


async def test_notices_have_per_account_quota(client, mail, monkeypatch):
    """SEC-40: pedir cambios de email en bucle no bombardea la dirección antigua."""
    monkeypatch.setattr(settings, "EMAIL_NOTICES_PER_ACCOUNT_PER_HOUR", 2)
    victim = await create_user(email_verified_at=utcnow())
    for index in range(6):
        r = await client.post(
            f"{API}/users/me/email",
            headers=headers_for(victim),
            json={"new_email": f"t{index}-{_uid()}@example.com", "current_password": TEST_PASSWORD},
        )
        assert r.status_code == 202
    await process_pending()
    notices = [m for m in sent_to(mail, victim.email) if "#token=" not in m.text]
    assert len(notices) == 2


async def test_email_change_links_have_per_address_quota(client, mail, monkeypatch):
    """SEC-40: varias cuentas no pueden enviar enlaces sin límite a la misma dirección."""
    monkeypatch.setattr(settings, "EMAIL_PER_ADDRESS_PER_HOUR", 2)
    target = f"third-party-{_uid()}@example.com"
    for _ in range(4):
        owner = await create_user(email_verified_at=utcnow())
        await client.post(
            f"{API}/users/me/email",
            headers=headers_for(owner),
            json={"new_email": target, "current_password": TEST_PASSWORD},
        )
    await process_pending()
    assert len(sent_to(mail, target)) == 2


async def test_concurrent_jobs_respect_per_account_quota(client, mail, monkeypatch):
    """SEC-41: con varios trabajos a la vez de la misma cuenta, el cupo se serializa."""
    from app.tasks import queue
    from app.tasks.worker import run_job

    monkeypatch.setattr(settings, "EMAIL_PER_ACCOUNT_COOLDOWN_SECONDS", 60)
    for round_ in range(3):
        victim = await create_user()
        for index in range(6):
            async with client_from(f"10.7.{round_}.{index + 1}") as other_ip:
                await other_ip.post(FORGOT, json={"email": victim.email})
        claimed = await queue.claim("race", 10)
        await asyncio.gather(*(run_job(job_id, "race") for job_id in claimed))
        assert len(sent_to(mail, victim.email)) == 1


async def test_reclaimed_and_cancelled_email_jobs_are_scrubbed(client, mail, admin_headers):
    """SEC-43: los trabajos de correo recuperados tras caer el worker o cancelados
    también vacían el payload."""
    from app.models.job import JobStatus
    from app.tasks import queue

    await client.post(FORGOT, json={"email": f"a-{_uid()}@example.com"})
    await client.post(FORGOT, json={"email": f"b-{_uid()}@example.com"})
    async with SessionFactory() as session:
        jobs = (
            await session.exec(
                select(Job).where(
                    col(Job.name) == "auth.password_reset", col(Job.status) == JobStatus.queued
                )
            )
        ).all()
        stale, cancelled = jobs[-2], jobs[-1]
        await session.execute(
            update(Job)
            .where(col(Job.id) == stale.id)
            .values(
                status=JobStatus.running,
                attempts=stale.max_attempts,
                locked_until=utcnow() - timedelta(minutes=1),
            )
        )
        await session.commit()
    await queue.reclaim_stale()
    assert (
        await client.post(f"{API}/jobs/{cancelled.id}/cancel", headers=admin_headers)
    ).status_code == 200
    async with SessionFactory() as session:
        lost, gone = await session.get(Job, stale.id), await session.get(Job, cancelled.id)
    assert lost.status == JobStatus.failed and lost.payload == {}
    assert gone.status == JobStatus.cancelled and gone.payload == {}


# --- Verificación de email ----------------------------------------------------------
async def test_register_is_uniform_with_verification(client, mail):
    """ST-01/02 (D1): nuevo, existente verificado y existente sin verificar → mismo 202;
    el existente no cambia y recibe "ya tienes cuenta", no un enlace de verificación."""
    verified = await create_user(email_verified_at=utcnow(), full_name="Real Owner")
    unverified = await create_user()
    fresh = f"fresh-{_uid()}@example.com"
    responses = []
    for email in (fresh, verified.email, unverified.email):
        r = await client.post(
            REGISTER, json={"email": email, "password": NEW_PASSWORD, "full_name": "Mallory"}
        )
        responses.append((r.status_code, r.text, "location" in r.headers))
    assert len(set(responses)) == 1 and responses[0][0] == 202
    await process_pending()
    assert "Confirm your email" in sent_to(mail, fresh)[-1].subject
    for existing in (verified, unverified):
        message = sent_to(mail, existing.email)[-1]
        assert "already have" in message.subject and "#token=" not in message.text
        assert "Mallory" not in message.text  # sin texto libre del registrante (M06)
        row = await _user(existing.id)
        assert (
            row.hashed_password == existing.hashed_password and row.full_name == existing.full_name
        )


async def test_concurrent_registrations_same_email(client, mail):
    """ST-04: dos registros a la vez → ambos 202 y una sola fila."""
    email = f"race-{_uid()}@example.com"
    results = await asyncio.gather(
        *(client.post(REGISTER, json={"email": email, "password": NEW_PASSWORD}) for _ in range(2))
    )
    assert [r.status_code for r in results] == [202, 202]
    async with SessionFactory() as session:
        rows = (await session.exec(select(User).where(User.email == email))).all()
    assert len(rows) == 1


async def test_verification_flow_and_required_mode(client, mail, monkeypatch):
    """ST-08/22: con `required`, contraseña mala → 401 de siempre; buena → 403 sin
    tokens; tras verificar (idempotente, sin tokens) el login funciona."""
    monkeypatch.setattr(settings, "EMAIL_VERIFICATION", "required")
    email = f"verify-{_uid()}@example.com"
    await client.post(REGISTER, json={"email": email, "password": NEW_PASSWORD})
    await process_pending()
    token = token_from(sent_to(mail, email)[-1])
    assert token.startswith("ev_")

    r = await _login(client, email, "wrong password!!")
    assert r.status_code == 401 and r.json()["code"] == "invalid_credentials"
    assert (await _user_by_email(email)).failed_login_attempts == 1  # cuenta para el bloqueo
    r = await _login(client, email, NEW_PASSWORD)
    assert r.status_code == 403 and r.json()["code"] == "email_not_verified"
    assert "access_token" not in r.text

    r = await client.post(VERIFY, json={"token": token})
    assert r.status_code == 204 and r.content == b""
    assert (await client.post(VERIFY, json={"token": token})).status_code == 204  # idempotente
    r = await _login(client, email, NEW_PASSWORD)
    assert r.status_code == 200
    me = await client.get(
        f"{API}/users/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"}
    )
    assert me.json()["email_verified"] is True


async def test_refresh_refused_for_unverified_in_required_mode(client, mail, monkeypatch):
    email = f"optional-{_uid()}@example.com"
    await client.post(REGISTER, json={"email": email, "password": NEW_PASSWORD})
    login = (await _login(client, email, NEW_PASSWORD)).json()  # optional: entra
    monkeypatch.setattr(settings, "EMAIL_VERIFICATION", "required")
    r = await client.post(f"{API}/auth/refresh", json={"refresh_token": login["refresh_token"]})
    assert r.status_code == 401


async def test_existing_users_can_log_in_in_required_mode(client, mail, monkeypatch):
    """ST-45: los usuarios creados por un admin (o migrados) nacen verificados."""
    monkeypatch.setattr(settings, "EMAIL_VERIFICATION", "required")
    admin = await create_user(role="admin", email_verified_at=utcnow())
    email = f"byadmin-{_uid()}@example.com"
    r = await client.post(
        f"{API}/users",
        headers=headers_for(admin),
        json={"email": email, "password": NEW_PASSWORD},
    )
    assert r.status_code == 201 and r.json()["email_verified"] is True
    assert (await _login(client, email, NEW_PASSWORD)).status_code == 200


async def test_resend_with_session_and_anonymous(client, mail):
    email = f"resend-{_uid()}@example.com"
    await client.post(REGISTER, json={"email": email, "password": NEW_PASSWORD})
    await process_pending()
    first = token_from(sent_to(mail, email)[-1])
    login = (await _login(client, email, NEW_PASSWORD)).json()
    auth = {"Authorization": f"Bearer {login['access_token']}"}
    assert (await client.post(RESEND, headers=auth)).status_code == 202
    anonymous = await client.post(RESEND, json={"email": email})
    unknown = await client.post(RESEND, json={"email": f"nobody-{_uid()}@example.com"})
    assert anonymous.status_code == unknown.status_code == 202 and anonymous.text == unknown.text
    assert (await client.post(RESEND)).status_code == 422
    await process_pending()
    tokens = [token_from(m) for m in sent_to(mail, email)]
    assert len(tokens) == 3 and len(set(tokens)) == 3
    # Hasta 3 enlaces vigentes: el primero sigue valiendo (REQ-T12).
    assert (await client.post(VERIFY, json={"token": first})).status_code == 204


async def test_verification_token_bound_to_email(client, mail, user):
    """ST-15: un token emitido para A no verifica si la cuenta pasa a B."""
    email = f"bound-{_uid()}@example.com"
    await client.post(REGISTER, json={"email": email, "password": NEW_PASSWORD})
    await process_pending()
    token = token_from(sent_to(mail, email)[-1])
    async with SessionFactory() as session:
        await session.execute(
            update(User).where(col(User.email) == email).values(email=f"other-{_uid()}@example.com")
        )
        await session.commit()
    assert (await client.post(VERIFY, json={"token": token})).status_code == 400


async def test_verified_user_dependency(mail, monkeypatch):
    from fastapi import HTTPException

    from app.api.deps import Principal, verified_user

    unverified = await create_user()
    with pytest.raises(HTTPException) as info:
        await verified_user(Principal(user=unverified, scopes=frozenset()))
    assert info.value.status_code == 403
    monkeypatch.setattr(settings, "EMAIL_VERIFICATION", "off")
    assert await verified_user(Principal(user=unverified, scopes=frozenset()))


# --- Cambio de email --------------------------------------------------------------
async def test_email_change_flow(client, mail):
    user = await create_user(email_verified_at=utcnow(), full_name="Ada")
    headers = headers_for(user)
    login = (await _login(client, user.email)).json()
    new = f"new-{_uid()}@example.com"

    r = await client.post(
        f"{API}/users/me/email",
        headers=headers,
        json={"new_email": new.upper(), "current_password": "wrong password!!"},
    )
    assert r.status_code == 400 and r.json()["code"] == "wrong_password"
    r = await client.post(
        f"{API}/users/me/email",
        headers=headers,
        json={"new_email": new.upper(), "current_password": TEST_PASSWORD},
    )
    assert r.status_code == 202
    assert (await _user(user.id)).email == user.email  # nada cambia aún (REQ-F21)
    await process_pending()
    confirm = sent_to(mail, new)[-1]
    notice = sent_to(mail, user.email)[-1]
    assert "Confirm your new email" in confirm.subject and "Ada" not in confirm.text
    assert "n***@example.com" in notice.text and "#token=" not in notice.text
    pending_reset = await _reset_token(client, mail, await _user(user.id))

    token = token_from(confirm)
    assert token.startswith("ec_")
    assert (await client.post(VERIFY, json={"token": token})).status_code == 204
    fresh = await _user(user.id)
    assert fresh.email == new and fresh.email_verified_at is not None
    # Sesiones cerradas y tokens pendientes invalidados (REQ-F24).
    r = await client.post(f"{API}/auth/refresh", json={"refresh_token": login["refresh_token"]})
    assert r.status_code == 401
    r = await client.post(RESET, json={"token": pending_reset, "new_password": NEW_PASSWORD})
    assert r.status_code == 400
    await process_pending()
    changed = sent_to(mail, user.email)[-1]  # aviso final a la dirección ANTIGUA (F23)
    assert "was changed" in changed.subject


async def test_email_change_to_taken_address_is_uniform(client, mail):
    """ST-09: 202 idéntico aunque la dirección nueva sea de otra cuenta; no se envía
    enlace a esa dirección."""
    user = await create_user(email_verified_at=utcnow())
    taken = await create_user()
    free = f"free-{_uid()}@example.com"
    bodies = []
    for target in (taken.email, free):
        r = await client.post(
            f"{API}/users/me/email",
            headers=headers_for(user),
            json={"new_email": target, "current_password": TEST_PASSWORD},
        )
        bodies.append((r.status_code, r.text))
    assert bodies[0] == bodies[1] and bodies[0][0] == 202
    await process_pending()
    assert not any("#token=" in m.text for m in sent_to(mail, taken.email))


async def test_profile_updates_cannot_touch_email_fields(
    client, mail, user_headers, admin_headers, user
):
    """REQ-F25: ningún esquema de actualización acepta email ni email_verified_at."""
    for body in ({"email": "x@example.com"}, {"email_verified_at": "2020-01-01T00:00:00Z"}):
        assert (
            await client.patch(f"{API}/users/me", headers=user_headers, json=body)
        ).status_code == 422
        r = await client.patch(f"{API}/users/{user.id}", headers=admin_headers, json=body)
        assert r.status_code == 422


async def test_rate_limit_on_forgot_is_audited(client, mail, user, caplog, monkeypatch):
    """ST-24: superar el límite por IP → 429 y evento auth.rate_limited."""
    with caplog.at_level("WARNING", logger="app.audit"):
        codes = [
            (await client.post(FORGOT, json={"email": user.email})).status_code for _ in range(40)
        ]
    assert 429 in codes and "auth.rate_limited" in caplog.text


async def test_inline_delivery_runs_the_job_after_the_response(client, mail, user, monkeypatch):
    """EMAIL_DELIVERY=inline (desarrollo): el correo sale sin worker."""
    monkeypatch.setattr(settings, "EMAIL_DELIVERY", "inline")
    r = await client.post(FORGOT, json={"email": user.email})
    assert r.status_code == 202
    assert len(sent_to(mail, user.email)) == 1
    # También los avisos que encola el propio trabajo (cambio de email).
    new = f"inline-{_uid()}@example.com"
    r = await client.post(
        f"{API}/users/me/email",
        headers=headers_for(user),
        json={"new_email": new, "current_password": TEST_PASSWORD},
    )
    assert r.status_code == 202
    assert len(sent_to(mail, new)) == 1 and len(sent_to(mail, user.email)) == 2


async def test_refresh_tokens_untouched_by_forgot(client, mail, user):
    await _login(client, user.email)
    await client.post(FORGOT, json={"email": user.email})
    await process_pending()
    async with SessionFactory() as session:
        alive = (
            await session.exec(
                select(RefreshToken).where(
                    col(RefreshToken.user_id) == user.id, col(RefreshToken.revoked_at).is_(None)
                )
            )
        ).all()
    assert alive  # pedir un reset no cierra sesiones (solo completarlo)


async def test_logs_never_contain_tokens_or_addresses(client, mail, user, caplog):
    """ST-37: con DEBUG, ni tokens ni enlaces ni direcciones completas en los logs."""
    with caplog.at_level(logging.DEBUG):
        await client.post(FORGOT, json={"email": user.email})
        await process_pending()
        token = token_from(sent_to(mail, user.email)[-1])
        await client.post(RESET, json={"token": token, "new_password": NEW_PASSWORD})
        await client.post(RESET, json={"token": token, "new_password": NEW_PASSWORD})
        await process_pending()
    text = caplog.text + " ".join(str(r.__dict__) for r in caplog.records)
    assert token not in text and token[3:15] not in text
    assert user.email not in text and "#token=" not in text


# --- Correcciones de la validación (SEC-42, UX-76, UX-77, UX-68) -----------------------
async def test_email_changed_notice_has_no_free_text_for_unproven_address(client, mail):
    """SEC-42: quien registra la dirección de otro con un `full_name` señuelo y cambia
    después el email no consigue que el aviso final a esa dirección lleve el señuelo."""
    victim = f"victim-{_uid()}@example.com"
    lure = "URGENTE visita http://evil.example/claim"
    await client.post(REGISTER, json={"email": victim, "password": NEW_PASSWORD, "full_name": lure})
    await process_pending()
    access = (await _login(client, victim, NEW_PASSWORD)).json()["access_token"]
    mine = f"attacker-{_uid()}@example.com"
    await client.post(
        f"{API}/users/me/email",
        headers={"Authorization": f"Bearer {access}"},
        json={"new_email": mine, "current_password": NEW_PASSWORD},
    )
    await process_pending()
    assert (
        await client.post(VERIFY, json={"token": token_from(sent_to(mail, mine)[-1])})
    ).status_code == 204
    await process_pending()
    assert "was changed" in sent_to(mail, victim)[-1].subject
    assert all(lure not in m.text for m in sent_to(mail, victim))


async def test_unverified_login_does_not_touch_last_login(client, mail, monkeypatch):
    """UX-76: un 403 email_not_verified no cuenta como inicio de sesión."""
    monkeypatch.setattr(settings, "EMAIL_VERIFICATION", "required")
    unverified = await create_user()
    r = await _login(client, unverified.email)
    assert r.status_code == 403
    assert (await _user(unverified.id)).last_login_at is None


async def test_email_language_follows_user_locale(client, mail):
    """UX-77: el idioma del registro se guarda; los correos posteriores sin
    Accept-Language (p. ej. el aviso tras el reset) salen en ese idioma."""
    email = f"locale-{_uid()}@example.com"
    await client.post(
        REGISTER,
        json={"email": email, "password": NEW_PASSWORD},
        headers={"Accept-Language": "es-ES,es;q=0.9"},
    )
    await process_pending()
    assert "Confirma tu email" in sent_to(mail, email)[-1].subject
    assert (await _user_by_email(email)).locale == "es"
    await client.post(FORGOT, json={"email": email})  # sin cabecera
    await process_pending()
    token = token_from(sent_to(mail, email)[-1])
    assert "Restablece" in sent_to(mail, email)[-1].subject
    await client.post(RESET, json={"token": token, "new_password": "yet another passphrase"})
    await process_pending()
    assert "Se ha cambiado tu contraseña" in sent_to(mail, email)[-1].subject


async def test_quota_suppression_is_visible_outside_production(
    client, mail, user, monkeypatch, caplog
):
    """UX-70: fuera de producción, un correo descartado por cupo se avisa en el log."""
    monkeypatch.setattr(settings, "EMAIL_PER_ACCOUNT_PER_HOUR", 1)
    await client.post(FORGOT, json={"email": user.email})
    await client.post(FORGOT, json={"email": user.email})
    with caplog.at_level(logging.WARNING, logger="app.email"):
        await process_pending()
    assert len(sent_to(mail, user.email)) == 1
    assert "correo NO enviado" in caplog.text and "EMAIL_PER_ACCOUNT_PER_HOUR" in caplog.text

"""Defensas transversales: tokens, cabeceras, tamaño de body, errores y rate limit."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt

from app.core.config import settings
from app.core.rate_limit import client_ip
from tests.conftest import headers_for


def _forge(payload: dict, key: str, alg: str = "HS256", headers: dict | None = None) -> dict:
    token = jwt.encode(payload, key, algorithm=alg, headers=headers)
    return {"Authorization": f"Bearer {token}"}


def _claims(user, **overrides) -> dict:
    now = datetime.now(UTC)
    claims = {
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "sub": str(user.id),
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=5),
        "jti": uuid.uuid4().hex,
        "typ": "access",
        "ver": 0,
        "role": "admin",
        "scope": "read write admin",
    }
    claims.update(overrides)
    return claims


async def test_forged_token_with_wrong_key(client, user):
    headers = _forge(_claims(user), "not-the-real-secret-key-0123456789abcdef")
    assert (await client.get("/api/v1/users/me", headers=headers)).status_code == 401


async def test_alg_none_rejected(client, user):
    token = jwt.encode(_claims(user), None, algorithm="none")
    r = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


async def test_role_claim_is_not_trusted(client, user):
    """Aunque el token (válido) diga role=admin, manda el rol en la base de datos."""
    from app.core.security import _keys

    headers = _forge(_claims(user), _keys.signing_key, headers={"kid": _keys.kid})
    assert (await client.get("/api/v1/users/me", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/users", headers=headers)).status_code == 403


async def test_expired_and_wrong_audience_rejected(client, user):
    from app.core.security import _keys

    past = datetime.now(UTC) - timedelta(hours=1)
    expired = _forge(
        _claims(user, exp=past, iat=past, nbf=past), _keys.signing_key, headers={"kid": _keys.kid}
    )
    wrong_aud = _forge(_claims(user, aud="other"), _keys.signing_key, headers={"kid": _keys.kid})
    for headers in (expired, wrong_aud):
        assert (await client.get("/api/v1/users/me", headers=headers)).status_code == 401


async def test_meta_endpoint_ignores_auth_header(client):
    r = await client.get("/api/versions", headers={"Authorization": "Bearer garbage"})
    # /api/versions no depende del usuario: sigue funcionando.
    assert r.status_code == 200


async def test_security_headers(client):
    r = await client.get("/health/live")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"
    assert "server" not in r.headers
    assert len(r.headers["x-request-id"]) >= 8


async def test_request_id_is_sanitized(client):
    r = await client.get("/health/live", headers={"X-Request-ID": "bad\nvalue<script>"})
    assert "\n" not in r.headers["x-request-id"] and "<" not in r.headers["x-request-id"]


async def test_body_size_limit(client, user_headers):
    big = "x" * (settings.MAX_BODY_SIZE + 10)
    r = await client.patch(
        "/api/v1/users/me",
        content=big,
        headers={**user_headers, "Content-Type": "application/json"},
    )
    assert r.status_code == 413
    assert r.json()["code"] == "body_too_large"  # UX-30


async def test_body_size_limit_chunked(client, user_headers):
    async def gen():
        for _ in range(settings.MAX_BODY_SIZE // 65536 + 2):
            yield b"x" * 65536

    r = await client.patch(
        "/api/v1/users/me",
        content=gen(),
        headers={**user_headers, "Content-Type": "application/json"},
    )
    assert r.status_code == 413


async def test_validation_errors_do_not_echo_input(client):
    secret = "super-secret-password-value"
    r = await client.post(
        "/api/v1/auth/register", json={"email": "not-an-email", "password": secret}
    )
    assert r.status_code == 422
    assert secret not in r.text and "not-an-email" not in r.text


async def test_json_without_content_type_is_rejected(client, user_headers):
    r = await client.patch(
        "/api/v1/users/me",
        content=b'{"full_name": "csrf"}',
        headers={**user_headers, "Content-Type": ""},
    )
    assert r.status_code == 422


async def test_default_rate_limit_applies_to_included_routers(client, user):
    """Regresión: SlowAPIMiddleware no ve los routers incluidos en FastAPI >= 0.140."""
    from app.core.rate_limit import limiter

    headers = headers_for(user)
    limit = int(settings.RATE_LIMIT_DEFAULT.split("/")[0])
    statuses = [
        (await client.get("/api/v1/users/me", headers=headers)).status_code
        for _ in range(limit + 5)
    ]
    assert statuses[:limit] == [200] * limit
    # La ventana deslizante es aproximada: si la prueba cruza el cambio de minuto,
    # puede dejar pasar alguna petición de más. El 429 debe llegar enseguida.
    assert 429 in statuses[limit:]
    limiter.reset()


async def test_rate_limit_headers(client, user_headers):
    r = await client.get("/api/v1/users/me", headers=user_headers)
    assert r.headers["x-ratelimit-limit"] == settings.RATE_LIMIT_DEFAULT.split("/")[0]


def test_ipv6_grouped_by_prefix():
    class Req:
        def __init__(self, host):
            self.client = type("C", (), {"host": host})

    a = client_ip(Req("2001:db8:1:2::1"))  # type: ignore[arg-type]
    b = client_ip(Req("2001:db8:1:2:ffff::9"))  # type: ignore[arg-type]
    assert a == b == "2001:db8:1:2::/64"
    assert client_ip(Req("::ffff:10.0.0.1")) == "10.0.0.1"  # type: ignore[arg-type]


async def test_versions_endpoint(client):
    r = await client.get("/api/versions")
    assert r.status_code == 200
    assert r.json()[0]["name"] == "v1"


async def test_500_keeps_security_headers_and_request_id(client, caplog):
    """SEC-06: el 500 se genera dentro de la pila de middlewares."""
    from app.main import app as fastapi_app

    async def boom() -> None:
        raise RuntimeError("secret internal detail")

    fastapi_app.add_api_route("/__boom", boom)
    try:
        r = await client.get("/__boom", headers={"X-Request-ID": "req-12345678"})
    finally:
        fastapi_app.router.routes = [
            route for route in fastapi_app.router.routes if getattr(route, "path", "") != "/__boom"
        ]
    assert r.status_code == 500
    assert r.json() == {
        "detail": "Internal server error",
        "code": "internal_error",
        "request_id": "req-12345678",
    }
    assert "secret internal detail" not in r.text
    assert r.headers["x-request-id"] == "req-12345678"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


async def test_nul_character_is_422_not_500(client):
    """SEC-07: PostgreSQL rechaza \\x00 en texto; se corta en la validación."""
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": "nul@example.com", "password": "a long passphrase", "full_name": "a\x00b"},
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "null_character"
    r = await client.post(
        "/api/v1/auth/login", data={"username": "x\x00@example.com", "password": "whatever-long"}
    )
    assert r.status_code == 401


async def test_integrity_errors_are_described_without_leaking(db):
    """UX-10 / SEC-09: 409 con code y campo, sin SQL ni valores."""
    from sqlalchemy.exc import IntegrityError

    from app.core.errors import describe_integrity_error
    from app.models.user import User

    email = f"dup-{uuid.uuid4().hex[:6]}@example.com"
    db.add(User(email=email, hashed_password="x"))
    await db.commit()
    db.add(User(email=email, hashed_password="x"))
    try:
        await db.commit()
        raise AssertionError("se esperaba IntegrityError")
    except IntegrityError as exc:
        code, detail, fields = describe_integrity_error(exc, "POST")
        await db.rollback()
    assert (code, fields) == ("unique_violation", ["email"])
    assert email not in detail


async def test_unrouted_requests_are_rate_limited(client):
    """SEC-11: escanear rutas inexistentes también consume cupo."""
    limit = int(settings.RATE_LIMIT_DEFAULT.split("/")[0])
    statuses = [(await client.get("/no-such-path")).status_code for _ in range(limit + 5)]
    assert statuses[0] == 404
    assert statuses[-1] == 429
    body = (await client.get("/no-such-path")).json()
    assert body["code"] == "rate_limited"


async def test_error_bodies_have_stable_codes(client, user_headers):
    r = await client.get(f"/api/v1/users/{uuid.uuid4()}", headers=user_headers)
    assert r.status_code == 403 and r.json()["code"] == "forbidden"
    r = await client.get("/api/v1/users?limit=0", headers=user_headers)
    assert r.json()["code"] in {"validation_error", "forbidden"}


def test_text_logs_escape_control_characters():
    """SEC-13: una ruta con %0a no puede falsificar líneas en el log de texto."""
    import logging

    from app.core.logging import TextFormatter

    record = logging.makeLogRecord(
        {"name": "app.audit", "levelname": "INFO", "msg": "GET /x\nFAKE admin login ok"}
    )
    record.request_id = "-"
    record.user_id = "u1\r\nforged"
    line = TextFormatter().format(record)
    assert "\n" not in line and "\r" not in line
    assert "\\x0a" in line and "user_id=u1" in line


def test_deprecation_headers_follow_rfcs():
    """UX-18: Deprecation con @epoch (RFC 9745) y Sunset como HTTP-date (RFC 8594)."""
    from app.api.versions import APIVersion

    headers = APIVersion(
        name="v1", module="x", deprecated=True, deprecated_since="2026-01-01", sunset="2027-01-01"
    ).deprecation_headers()
    assert headers == {"Deprecation": "@1767225600", "Sunset": "Fri, 01 Jan 2027 00:00:00 GMT"}


async def test_rate_limit_header_cleanup(client, user_headers):
    """UX-26: Retry-After solo en 429 y X-RateLimit-Reset entero."""
    r = await client.get("/api/v1/users/me", headers=user_headers)
    assert r.status_code == 200
    assert "retry-after" not in r.headers
    assert r.headers["x-ratelimit-reset"].isdigit()


async def test_dev_cors_allows_localhost_frontends(monkeypatch):
    """UX-17: en desarrollo, sin CORS_ORIGINS, se admite cualquier localhost."""
    import httpx

    from app.core.config import Environment
    from app.main import create_app

    monkeypatch.setattr(settings, "ENVIRONMENT", Environment.development)
    dev_app = create_app()
    transport = httpx.ASGITransport(app=dev_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        preflight = {"Access-Control-Request-Method": "GET"}
        ok = await c.options(
            "/api/versions", headers={"Origin": "http://localhost:3000", **preflight}
        )
        bad = await c.options(
            "/api/versions", headers={"Origin": "https://evil.example", **preflight}
        )
    assert ok.status_code == 200
    assert ok.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "access-control-allow-origin" not in bad.headers


def test_partial_update_messages():
    """UX-15: campo inmutable en PATCH -> error explícito, no "Extra inputs"."""
    from typing import ClassVar

    import pytest
    from pydantic import ValidationError

    from app.schemas.common import PartialUpdate

    class ThingUpdate(PartialUpdate):
        __non_nullable__: ClassVar[frozenset[str]] = frozenset({"name"})
        __immutable__: ClassVar[frozenset[str]] = frozenset({"slug"})
        name: str | None = None

    with pytest.raises(ValidationError) as exc:
        ThingUpdate.model_validate({"slug": "x"})
    assert [(e["loc"], e["type"]) for e in exc.value.errors()] == [(("slug",), "immutable_field")]
    with pytest.raises(ValidationError) as exc:
        ThingUpdate.model_validate({"name": None})
    assert [(e["loc"], e["type"]) for e in exc.value.errors()] == [(("name",), "null_not_allowed")]


def test_json_size_and_depth_limits():
    import pytest
    from pydantic_core import PydanticCustomError

    from app.schemas.common import check_json_size

    assert check_json_size({"a": [1, 2]}, 100) == {"a": [1, 2]}
    with pytest.raises(PydanticCustomError):
        check_json_size({"a": "x" * 200}, 100)
    deep: dict = {}
    node = deep
    for _ in range(15):
        node["n"] = {}
        node = node["n"]
    with pytest.raises(PydanticCustomError):
        check_json_size(deep, 10_000)


async def test_response_validation_errors_are_logged_without_values(client, caplog):
    """SEC-12: un fallo al serializar la respuesta no vuelca datos personales al log."""
    import logging

    from pydantic import BaseModel

    from app.main import app as fastapi_app

    class Out(BaseModel):
        count: int

    async def broken() -> dict:
        return {"count": "private-value@example.com"}

    fastapi_app.add_api_route("/__broken", broken, response_model=Out)
    try:
        with caplog.at_level(logging.ERROR, logger="app.errors"):
            r = await client.get("/__broken")
    finally:
        fastapi_app.router.routes = [
            route
            for route in fastapi_app.router.routes
            if getattr(route, "path", "") != "/__broken"
        ]
    assert r.status_code == 500
    assert "response validation error" in caplog.text
    assert "private-value@example.com" not in caplog.text


async def test_password_policy_errors_point_to_the_field(client):
    """UX-29: un error por problema y `loc` en el campo, para marcarlo en el formulario."""
    r = await client.post(
        "/api/v1/auth/register", json={"email": "loc@example.com", "password": "aaaa"}
    )
    assert r.status_code == 422
    errors = r.json()["detail"]
    assert len(errors) == 2
    assert all(e["loc"] == ["body", "password"] and e["type"] == "password_policy" for e in errors)
    assert all(e["msg"].startswith("Password ") for e in errors)


async def test_non_json_body_gets_415(client):
    """UX-37: form o text/plain en un endpoint JSON -> 415 expects_json."""
    r = await client.post("/api/v1/auth/refresh", data={"refresh_token": "rt_x"})
    assert r.status_code == 415 and r.json()["code"] == "expects_json"
    r = await client.post(
        "/api/v1/auth/register", content=b"hola", headers={"Content-Type": "text/plain"}
    )
    assert r.status_code == 415


async def test_swagger_token_url_uses_active_version(client, monkeypatch):
    """UX-31: tokenUrl apunta a la versión activa más reciente; login documenta errores."""
    from app.api import deps, versions

    # UX-38: el valor esperado sale de las versiones reales del proyecto; con
    # `apigen version add v2` activa, tokenUrl es /api/v2/auth/login.
    names = [v.name for v in versions.VERSIONS if not v.deprecated] or [
        v.name for v in versions.VERSIONS
    ]
    latest = max(names, key=lambda name: int(name[1:]))
    expected = f"{settings.API_PREFIX}/{latest}/auth/login"
    spec = (await client.get("/openapi.json")).json()
    flows = spec["components"]["securitySchemes"]["OAuth2PasswordBearer"]["flows"]
    assert flows["password"]["tokenUrl"] == expected
    login = spec["paths"][expected]["post"]["responses"]
    assert {"401", "415", "429"} <= set(login)
    monkeypatch.setattr(
        versions,
        "VERSIONS",
        [
            versions.APIVersion(name="v1", module="x", deprecated=True),
            versions.APIVersion(name="v2", module="y"),
        ],
    )
    assert deps._login_version() == "v2"


async def test_generic_overflow_error_is_still_a_500(client):
    """SEC-24: solo el OverflowError de la capa de datos se convierte en 422."""
    from app.main import app as fastapi_app

    async def bug() -> None:
        raise OverflowError("math bug")

    fastapi_app.add_api_route("/__overflow", bug)
    try:
        r = await client.get("/__overflow")
    finally:
        fastapi_app.router.routes = [
            route
            for route in fastapi_app.router.routes
            if getattr(route, "path", "") != "/__overflow"
        ]
    assert r.status_code == 500


async def test_repository_converts_driver_overflow():
    import pytest

    from app.core.exceptions import DatabaseValueError
    from app.crud.base import _commit

    class Session:
        async def commit(self):
            raise OverflowError("Python int too large to convert to SQLite INTEGER")

        async def rollback(self):
            pass

    with pytest.raises(DatabaseValueError):
        await _commit(Session())  # type: ignore[arg-type]


async def test_backend_recovery_check_does_not_block(monkeypatch):
    """SEC-24: con Redis colgado, la comprobación de recuperación no bloquea el loop."""
    import time

    from app.core import rate_limit

    class Hanging:
        def check(self):
            time.sleep(2)
            return True

    monkeypatch.setattr(rate_limit.limiter, "_storage_dead", True)
    monkeypatch.setattr(rate_limit.limiter, "_storage", Hanging())
    monkeypatch.setattr(rate_limit, "_last_backend_check", 0.0)
    start = time.monotonic()
    await rate_limit._maybe_recover_backend()
    assert time.monotonic() - start < 1.5
    assert rate_limit.limiter._storage_dead is True


async def test_invalid_host_is_json_with_code(monkeypatch):
    """T6: el 400 de Host no permitido es JSON con `code` y lleva cabeceras de seguridad."""
    import httpx

    from app.main import create_app

    monkeypatch.setattr(settings, "ALLOWED_HOSTS", ["api.example.com", "www.example.org"])
    strict_app = create_app()
    transport = httpx.ASGITransport(app=strict_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://evil.example") as c:
        r = await c.get("/health/live")
    assert r.status_code == 400
    assert r.json() == {"detail": "Invalid host header", "code": "invalid_host"}
    assert r.headers["x-content-type-options"] == "nosniff"
    async with httpx.AsyncClient(transport=transport, base_url="http://api.example.com") as c:
        ok = await c.get("/health/live")
        # Los 4xx de la aplicación no se reescriben.
        missing = await c.get("/api/v1/users/not-a-uuid")
    assert ok.status_code == 200
    assert missing.status_code in (401, 422) and "code" in missing.json()
    # La redirección www de Starlette se conserva.
    async with httpx.AsyncClient(transport=transport, base_url="http://example.org") as c:
        redirect = await c.get("/health/live")
    assert redirect.status_code == 307


async def test_nul_in_query_or_path_is_422_not_500(client, admin_headers):
    """Validación con Docker + PostgreSQL: un %00 en la query llegaba a la BD (500)."""
    for url in ("/api/v1/users?q=a%00b", "/api/v1/users/abc%00def", "/api/v1/jobs?name=%00"):
        r = await client.get(url, headers=admin_headers)
        assert r.status_code == 422, (url, r.text)
        assert r.json()["detail"][0]["type"] == "null_character"
        assert r.headers["x-content-type-options"] == "nosniff"  # sigue pasando por seguridad


async def test_nul_422_has_cors_headers_and_right_loc(monkeypatch):
    """Ronda 7: el 422 del NUL iba por fuera de CORS (el navegador veía un error de red)
    y decía `loc: ["query"]` también con el NUL en la ruta."""
    import httpx

    from app.core.config import Environment
    from app.main import create_app

    monkeypatch.setattr(settings, "ENVIRONMENT", Environment.development)
    transport = httpx.ASGITransport(app=create_app())
    origin = {"Origin": "http://localhost:3000"}
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        in_query = await c.get("/api/v1/jobs?name=%00", headers=origin)
        in_path = await c.get("/api/v1/jobs/abc%00", headers=origin)
    for r, where in ((in_query, "query"), (in_path, "path")):
        assert r.status_code == 422
        assert r.headers["access-control-allow-origin"] == "http://localhost:3000"
        assert r.json()["detail"][0]["loc"] == [where]

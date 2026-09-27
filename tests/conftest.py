"""Fixtures compartidas. El entorno se fija ANTES de importar la aplicación."""

import os
import secrets
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="apitest-"))
os.environ.update(
    {
        "APIGEN_NO_GRAPH": "1",
        # Los tests no leen el .env local del proyecto (p. ej. el que deja `make new-api`
        # con la configuración de correo del cliente): todo lo necesario se fija aquí.
        "APP_ENV_FILE": str(_tmp / "tests-do-not-read.env"),
        "ENVIRONMENT": "testing",
        "DATABASE_URL": f"sqlite+aiosqlite:///{_tmp / 'test.db'}",
        "SECRET_KEY": secrets.token_urlsafe(48),
        "RATE_LIMIT_ENABLED": "true",
        "RATE_LIMIT_STORAGE_URI": "memory://",
        "ALLOWED_HOSTS": "*",
        "TRUSTED_PROXIES": "",
        "CORS_ORIGINS": "",
        "DOCS_ENABLED": "true",
        "LOG_LEVEL": "WARNING",
        "ALLOW_REGISTRATION": "true",
        # Correo: backend en memoria y flujos de cuenta apagados (cada test los activa
        # con la fixture `mail`); sin cortacircuitos global (lo prueba su propio test).
        "EMAIL_BACKEND": "memory",
        "EMAIL_VERIFICATION": "off",
        "PASSWORD_RESET": "false",
        "EMAIL_DELIVERY": "queue",
        "EMAIL_MAX_PER_HOUR": "0",
        "EMAIL_MAX_PER_DAY": "0",
        "EMAIL_MAX_SECURITY_PER_HOUR": "0",
        "EMAIL_MAX_SECURITY_PER_DAY": "0",
    }
)

import httpx  # noqa: E402
import pytest  # noqa: E402
from sqlmodel import SQLModel  # noqa: E402

import app.models  # noqa: E402, F401
from app.core.permissions import ROLE_SCOPES, Role  # noqa: E402
from app.core.rate_limit import limiter  # noqa: E402
from app.core.security import create_access_token, hash_password  # noqa: E402
from app.db.session import SessionFactory, engine  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402
from app.models.user import User  # noqa: E402
from tests.helpers import _uid  # noqa: E402

TEST_PASSWORD = "correct-horse-battery-staple"
_password_hash: str | None = None


@pytest.fixture(scope="session", autouse=True)
async def _database():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
        await conn.run_sync(SQLModel.metadata.create_all)
    yield
    await engine.dispose()


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    limiter.reset()
    yield


@pytest.fixture
def outbox():
    """Correos "enviados" con el backend en memoria (se vacía en cada test)."""
    from app.email.backends import memory

    memory.outbox.clear()
    yield memory.outbox
    memory.outbox.clear()


@pytest.fixture
def mail(monkeypatch, outbox):
    """Activa recuperación y verificación (`optional`) con enlaces a un frontend de
    ejemplo. Devuelve el outbox; ejecuta los trabajos con `process_pending()`."""
    from app.core.config import settings

    for key, value in {
        "FRONTEND_URL": "https://app.example.com",
        "EMAIL_FROM": "no-reply@example.com",
        "PASSWORD_RESET": True,
        "EMAIL_VERIFICATION": "optional",
        "EMAIL_PER_ACCOUNT_COOLDOWN_SECONDS": 0,
    }.items():
        monkeypatch.setattr(settings, key, value)
    return outbox


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=fastapi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def client_from(ip: str) -> httpx.AsyncClient:
    """Cliente cuyas peticiones llegan desde otra IP (para simular otro origen)."""
    transport = httpx.ASGITransport(app=fastapi_app, client=(ip, 40000))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


@pytest.fixture
async def db():
    async with SessionFactory() as session:
        yield session


async def create_user(role: Role = Role.user, email: str | None = None, **extra) -> User:
    global _password_hash
    if _password_hash is None:
        _password_hash = await hash_password(TEST_PASSWORD)
    async with SessionFactory() as session:
        user = User(
            email=email or f"{role}-{_uid()}@example.com",
            hashed_password=_password_hash,
            role=role,
            **extra,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


def headers_for(user: User, scopes: list[str] | None = None) -> dict[str, str]:
    granted = scopes if scopes is not None else sorted(ROLE_SCOPES[Role(user.role)])
    token = create_access_token(
        subject=user.id, token_version=user.token_version, role=user.role, scopes=granted
    )
    return {"Authorization": f"Bearer {token.token}"}


@pytest.fixture
async def user() -> User:
    return await create_user()


@pytest.fixture
async def other_user() -> User:
    return await create_user()


@pytest.fixture
async def admin() -> User:
    return await create_user(Role.admin)


@pytest.fixture
def user_headers(user: User) -> dict[str, str]:
    return headers_for(user)


@pytest.fixture
def other_headers(other_user: User) -> dict[str, str]:
    return headers_for(other_user)


@pytest.fixture
def admin_headers(admin: User) -> dict[str, str]:
    return headers_for(admin)

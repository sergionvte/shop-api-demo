"""Primitivas criptográficas: contraseñas (Argon2id), JWT de acceso y refresh tokens."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio
import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from app.core.config import settings

# ---------------------------------------------------------------------------
# Contraseñas
# ---------------------------------------------------------------------------
_password_hash = PasswordHash(
    (
        Argon2Hasher(
            time_cost=settings.ARGON2_TIME_COST,
            memory_cost=settings.ARGON2_MEMORY_COST_KIB,
            parallelism=settings.ARGON2_PARALLELISM,
        ),
    )
)
# Hash de una contraseña aleatoria: se verifica contra él cuando el usuario no
# existe para que el tiempo de respuesta no revele qué emails están registrados.
_DUMMY_HASH = _password_hash.hash(secrets.token_urlsafe(32))
_hash_limiter: anyio.CapacityLimiter | None = None


def _limiter() -> anyio.CapacityLimiter:
    # Argon2 consume CPU y ~64 MiB por cálculo: limitamos la concurrencia para que
    # una ráfaga de logins no agote la memoria ni bloquee el event loop.
    global _hash_limiter
    if _hash_limiter is None:
        _hash_limiter = anyio.CapacityLimiter(settings.PASSWORD_HASH_CONCURRENCY)
    return _hash_limiter


async def hash_password(password: str) -> str:
    return await anyio.to_thread.run_sync(_password_hash.hash, password, limiter=_limiter())


async def verify_password(password: str, hashed: str | None) -> tuple[bool, str | None]:
    """Devuelve (válida, nuevo_hash). `nuevo_hash` != None si hay que re-hashear
    porque cambiaron los parámetros de Argon2."""
    if not hashed:
        await anyio.to_thread.run_sync(
            _password_hash.verify, password, _DUMMY_HASH, limiter=_limiter()
        )
        return False, None
    return await anyio.to_thread.run_sync(
        _password_hash.verify_and_update, password, hashed, limiter=_limiter()
    )


_COMMON_PASSWORDS = frozenset(
    {
        "123456789012",
        "password1234",
        "passwordpassword",
        "qwertyuiop12",
        "qwertyqwerty",
        "iloveyou1234",
        "adminadmin12",
        "administrator",
        "letmeinletmein",
        "welcome12345",
        "changeme1234",
        "contraseña123",
        "contrasena123",
        "111111111111",
        "abc123abc123",
        "1q2w3e4r5t6y",
        "1q2w3e4r5t6y7u8i",
        "q1w2e3r4t5y6",
        "zaq12wsxcde3",
        "passw0rd1234",
        "p@ssw0rd1234",
        "superman1234",
        "football1234",
        "baseball1234",
        "trustno1trustno1",
        "iloveyouiloveyou",
        "monkey123456",
        "dragon123456",
        "sunshine1234",
        "princess1234",
    }
)
# Secuencias de teclado/alfabeto: una contraseña que es un tramo de ellas (p. ej.
# "qwertyuiopas", "1qaz2wsx3edc", "abcdefghijkl") se rechaza aunque no esté en la lista.
_SEQUENCES = (
    "qwertyuiopasdfghjklzxcvbnm",
    "qwertzuiopasdfghjklyxcvbnm",
    "azertyuiopqsdfghjklmwxcvbn",
    "qazwsxedcrfvtgbyhnujmikolp",
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p",
    "abcdefghijklmnopqrstuvwxyz",
    "12345678901234567890",
)

_MESSAGES = {
    "en": {
        "too_short": "must be at least {n} characters long",
        "too_long": "must be at most {n} characters long",
        "repetitive": "is too repetitive",
        "common": "is too common",
        "sequence": "is a keyboard or alphabet sequence",
        "contains_email": "must not contain the first part of your email ('{local}')",
    },
    "es": {
        "too_short": "debe tener al menos {n} caracteres",
        "too_long": "no puede superar {n} caracteres",
        "repetitive": "es demasiado repetitiva",
        "common": "es demasiado común",
        "sequence": "es una secuencia de teclado o del alfabeto",
        "contains_email": "no puede contener la primera parte de tu email ('{local}')",
    },
}


def _is_sequence(password: str) -> bool:
    lowered = password.lower()
    return any(lowered in seq or lowered in seq[::-1] for seq in _SEQUENCES)


def password_problems(password: str, email: str | None = None, lang: str = "en") -> list[str]:
    """Política de contraseñas basada en NIST 800-63B: longitud y listas negras,
    sin reglas de composición arbitrarias. La API responde en inglés (el `type`
    del error, `password_policy`, es el identificador estable); la CLI, en español."""
    msg = _MESSAGES[lang]
    problems: list[str] = []
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        problems.append(msg["too_short"].format(n=settings.PASSWORD_MIN_LENGTH))
    if len(password) > settings.PASSWORD_MAX_LENGTH:
        problems.append(msg["too_long"].format(n=settings.PASSWORD_MAX_LENGTH))
    if len(set(password)) < 5:
        problems.append(msg["repetitive"])
    if password.lower() in _COMMON_PASSWORDS:
        problems.append(msg["common"])
    elif len(password) >= 8 and _is_sequence(password):
        problems.append(msg["sequence"])
    if email:
        local = email.split("@", 1)[0].lower()
        if len(local) >= 4 and local in password.lower():
            problems.append(msg["contains_email"].format(local=local))
    return problems


# ---------------------------------------------------------------------------
# JWT de acceso
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class _KeyRing:
    kid: str
    signing_key: Any
    verification_keys: dict[str, Any]


def _kid(material: bytes) -> str:
    return hashlib.sha256(material).hexdigest()[:16]


def _build_keyring() -> _KeyRing:
    if settings.JWT_ALGORITHM.startswith("HS"):
        current = settings.SECRET_KEY.get_secret_value()
        keys = {_kid(current.encode()): current}
        for old in settings.JWT_PREVIOUS_SECRET_KEYS:
            keys.setdefault(_kid(old.encode()), old)
        return _KeyRing(_kid(current.encode()), current, keys)

    private = settings.JWT_PRIVATE_KEY_FILE.read_bytes()  # type: ignore[union-attr]
    public = settings.JWT_PUBLIC_KEY_FILE.read_bytes()  # type: ignore[union-attr]
    kid = _kid(public)
    return _KeyRing(kid, private, {kid: public})


_keys = _build_keyring()
_MAX_TOKEN_LENGTH = 4096


class TokenError(Exception):
    """Token ausente, mal formado, expirado o con firma inválida."""


class TokenExpired(TokenError):
    """Firma válida pero caducado: el cliente debe usar su refresh token."""


@dataclass(frozen=True, slots=True)
class AccessToken:
    token: str
    expires_in: int


def create_access_token(
    *, subject: uuid.UUID, token_version: int, role: str, scopes: list[str]
) -> AccessToken:
    now = datetime.now(UTC)
    expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "sub": str(subject),
        "iat": now,
        "nbf": now,
        "exp": now + expires,
        "jti": uuid.uuid4().hex,
        "typ": "access",
        "ver": token_version,
        "role": role,
        "scope": " ".join(sorted(scopes)),
    }
    token = jwt.encode(
        payload, _keys.signing_key, algorithm=settings.JWT_ALGORITHM, headers={"kid": _keys.kid}
    )
    return AccessToken(token=token, expires_in=int(expires.total_seconds()))


def decode_access_token(token: str) -> dict[str, Any]:
    if not token or len(token) > _MAX_TOKEN_LENGTH:
        raise TokenError("token inválido")
    try:
        header = jwt.get_unverified_header(token)
        key = _keys.verification_keys.get(header.get("kid", ""))
        if key is None:
            raise TokenError("clave desconocida")
        payload = jwt.decode(
            token,
            key,
            # Lista explícita: impide "alg=none" y la confusión HS/RS.
            algorithms=[settings.JWT_ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
            leeway=settings.JWT_LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "nbf", "sub", "jti", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError as exc:
        # PyJWT comprueba la firma antes que `exp`: esto solo ocurre con tokens
        # auténticos, así que distinguirlo no ayuda a un atacante (RFC 6750).
        raise TokenExpired("token caducado") from exc
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
    if payload.get("typ") != "access" or not isinstance(payload.get("ver"), int):
        raise TokenError("tipo de token inválido")
    try:
        payload["sub"] = uuid.UUID(payload["sub"])
    except (ValueError, TypeError) as exc:
        raise TokenError("sub inválido") from exc
    return payload


# ---------------------------------------------------------------------------
# Refresh tokens (opacos, se guarda solo su hash)
# ---------------------------------------------------------------------------
_REFRESH_PREFIX = "rt_"


def generate_refresh_token() -> tuple[str, str]:
    """Devuelve (token_en_claro, hash). El token solo se entrega al cliente."""
    token = _REFRESH_PREFIX + secrets.token_urlsafe(48)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    # El token tiene 384 bits de entropía: SHA-256 basta (no necesita Argon2).
    return hashlib.sha256(token.encode()).hexdigest()


def looks_like_refresh_token(token: str) -> bool:
    return token.startswith(_REFRESH_PREFIX) and 40 <= len(token) <= 128


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())

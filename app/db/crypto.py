"""Cifrado en reposo de los campos `sensitive` (ISO 27701 6.7.1 / 7.4.x, SOC 2 C1.1).

Una copia de la base de datos o de un backup no revela categorías especiales de
datos (salud, ideología...): esas columnas guardan `enc:v1:<kid>:<base64url>` con
AES-256-GCM (nonce aleatorio por valor; el tag detecta cualquier manipulación).
La API los ve en claro, así que permisos y validación funcionan igual; por eso un
campo sensitive no se puede filtrar, buscar, ordenar ni ser unique (ver spec.py).

Claves: DATA_ENCRYPTION_KEY cifra; DATA_ENCRYPTION_PREVIOUS_KEYS solo descifran
(rotación). `kid` identifica la clave con la que se cifró cada valor. Un valor sin
prefijo `enc:` se devuelve tal cual: así se puede marcar como sensitive una columna
con datos antiguos, que se cifran al volver a guardarse.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

from app.core.config import settings

logger = logging.getLogger("app.crypto")

PREFIX = "enc:v1:"
# Fuera de producción, sin clave configurada: una fija y pública (los datos de
# desarrollo siguen legibles tras reiniciar). En producción falta la clave = error.
_DEV_KEY = hashlib.sha256(b"apigen-insecure-development-data-key").digest()


class EncryptionError(RuntimeError):
    pass


def parse_key(value: str) -> bytes:
    """Clave de 32 bytes en base64 (`apigen secret --data-key`)."""
    try:
        key = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("no es base64 válido") from exc
    if len(key) != 32:
        raise ValueError("debe tener 32 bytes (base64 de 43-44 caracteres)")
    return key


def key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:8]


def _keys() -> tuple[bytes, dict[str, bytes]]:
    current = settings.DATA_ENCRYPTION_KEY.get_secret_value()
    if current:
        key = parse_key(current)
    elif settings.is_production:
        raise EncryptionError("DATA_ENCRYPTION_KEY es obligatoria para guardar campos sensitive")
    else:
        key = _DEV_KEY
    ring = {key_id(key): key}
    for old in settings.DATA_ENCRYPTION_PREVIOUS_KEYS:
        previous = parse_key(old)
        ring.setdefault(key_id(previous), previous)
    if not settings.is_production:
        ring.setdefault(key_id(_DEV_KEY), _DEV_KEY)
    return key, ring


def encrypt(plaintext: str) -> str:
    key, _ = _keys()
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return f"{PREFIX}{key_id(key)}:{base64.urlsafe_b64encode(nonce + sealed).decode()}"


def decrypt(stored: str) -> str:
    if not stored.startswith(PREFIX):
        return stored  # dato anterior a marcar la columna como sensitive
    kid, _, payload = stored[len(PREFIX) :].partition(":")
    _, ring = _keys()
    key = ring.get(kid)
    if key is None:
        raise EncryptionError(f"no hay clave para kid={kid} (¿falta en PREVIOUS_KEYS?)")
    try:
        raw = base64.urlsafe_b64decode(payload)
        return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode()
    except (InvalidTag, binascii.Error, ValueError) as exc:
        raise EncryptionError(f"valor cifrado corrupto o manipulado (kid={kid})") from exc


class EncryptedText(TypeDecorator[str]):
    """Texto cifrado con AES-256-GCM. Lo usan los campos `sensitive` de tipo
    str/text/email que genera apigen."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect) -> str | None:
        return None if value is None else encrypt(value)

    def process_result_value(self, value: str | None, dialect) -> str | None:
        return None if value is None else decrypt(value)


def check_keys(metadata) -> None:
    """Al arrancar (API y worker): en producción, si algún modelo tiene columnas
    cifradas, la clave es obligatoria. Mejor no arrancar que fallar al primer guardado."""
    encrypted = [
        f"{table.name}.{column.name}"
        for table in metadata.tables.values()
        for column in table.c
        if isinstance(column.type, EncryptedText)
    ]
    if encrypted and settings.is_production and not settings.DATA_ENCRYPTION_KEY.get_secret_value():
        raise EncryptionError(
            "DATA_ENCRYPTION_KEY es obligatoria: hay campos sensitive cifrados "
            f"({', '.join(sorted(encrypted)[:5])})"
        )

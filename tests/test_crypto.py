"""Cifrado en reposo de los campos `sensitive` (ISO 27701 6.7.1, SOC 2 C1.1)."""

import base64
import os

import pytest
from pydantic import SecretStr, ValidationError
from sqlalchemy import Column, MetaData, String, Table, Uuid, select, text
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import Settings, settings
from app.db import crypto
from app.db.crypto import EncryptedText, EncryptionError, check_keys, decrypt, encrypt


def _key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


@pytest.fixture
def key(monkeypatch):
    value = _key()
    monkeypatch.setattr(settings, "DATA_ENCRYPTION_KEY", SecretStr(value))
    return value


def test_roundtrip_and_random_nonce(key):
    first, second = encrypt("diagnóstico"), encrypt("diagnóstico")
    assert first.startswith(crypto.PREFIX) and first != second
    assert "diagnóstico" not in first
    assert decrypt(first) == decrypt(second) == "diagnóstico"


def test_tampering_is_detected(key):
    stored = encrypt("secreto")
    raw = bytearray(base64.urlsafe_b64decode(stored.rsplit(":", 1)[1]))
    raw[-1] ^= 1
    forged = stored.rsplit(":", 1)[0] + ":" + base64.urlsafe_b64encode(bytes(raw)).decode()
    with pytest.raises(EncryptionError, match="manipulado"):
        decrypt(forged)


def test_key_rotation(monkeypatch, key):
    old_value = encrypt("antiguo")
    monkeypatch.setattr(settings, "DATA_ENCRYPTION_KEY", SecretStr(_key()))
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    with pytest.raises(EncryptionError, match="no hay clave"):
        decrypt(old_value)
    monkeypatch.setattr(settings, "DATA_ENCRYPTION_PREVIOUS_KEYS", [key])
    assert decrypt(old_value) == "antiguo"
    assert crypto.key_id(base64.urlsafe_b64decode(key)) not in encrypt("nuevo")


def test_legacy_plaintext_is_readable(key):
    assert decrypt("dato anterior") == "dato anterior"


def test_production_requires_key(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "DATA_ENCRYPTION_KEY", SecretStr(""))
    with pytest.raises(EncryptionError):
        encrypt("x")
    meta = MetaData()
    Table("t", meta, Column("id", Uuid, primary_key=True), Column("d", EncryptedText))
    with pytest.raises(EncryptionError, match="t.d"):
        check_keys(meta)
    check_keys(MetaData())  # sin columnas cifradas no hace falta


def test_invalid_key_rejected_by_settings():
    with pytest.raises(ValidationError, match="DATA_ENCRYPTION_KEY"):
        Settings(DATA_ENCRYPTION_KEY="corta")
    with pytest.raises(ValidationError, match="PREVIOUS_KEYS sin"):
        Settings(DATA_ENCRYPTION_PREVIOUS_KEYS=_key())
    Settings(DATA_ENCRYPTION_KEY=_key())


async def test_database_stores_ciphertext(key):
    meta = MetaData()
    table = Table(
        "notes", meta, Column("id", String(10), primary_key=True), Column("d", EncryptedText)
    )
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(meta.create_all)
        await conn.execute(table.insert().values(id="a", d="VIH positivo"))
        raw = (await conn.execute(text("SELECT d FROM notes"))).scalar_one()
        clear = (await conn.execute(select(table.c.d))).scalar_one()
    await engine.dispose()
    assert raw.startswith(crypto.PREFIX) and "VIH" not in raw
    assert clear == "VIH positivo"

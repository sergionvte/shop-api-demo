"""Tipos de columna y generadores de IDs."""

from __future__ import annotations

import os
import time
import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    return datetime.now(UTC)


def uuid7() -> uuid.UUID:
    """UUID v7 (RFC 9562): ordenado en el tiempo, así los índices B-tree se
    mantienen compactos (inserciones rápidas) y los IDs no son enumerables."""
    ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ms & 0xFFFF_FFFF_FFFF) << 80
    value |= 0x7 << 76  # versión 7
    value |= ((rand >> 62) & 0xFFF) << 64  # rand_a (12 bits)
    value |= 0b10 << 62  # variante RFC 4122
    value |= rand & 0x3FFF_FFFF_FFFF_FFFF  # rand_b (62 bits)
    return uuid.UUID(int=value)


class UTCDateTime(TypeDecorator[datetime]):
    """DateTime siempre en UTC y con tzinfo, también en SQLite (que no guarda zona)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

"""Registro de auditoría: eventos de seguridad estructurados en el logger `app.audit`.

Cada evento lleva `event` (p. ej. `auth.login.failure`), el actor/objetivo, la IP y
el `request_id`. Nunca se registran contraseñas, tokens ni emails (solo IDs).

Integridad (SOC 2 CC7.2, ISO 27701 6.9.4.2): cada proceso numera sus eventos
(`audit_stream` + `audit_seq`) y los encadena con un HMAC-SHA256 del evento y del
hash anterior (`audit_prev` -> `audit_hash`), con la clave AUDIT_HMAC_KEY. Así, en
los logs JSON, `apigen audit verify` detecta eventos alterados, insertados o
borrados del medio. Lo que no puede detectar es el corte del final de un flujo:
para eso los logs deben salir en tiempo real a un almacén externo (SIEM).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.config import settings
from app.core.logging import request_id_ctx

audit_logger = logging.getLogger("app.audit")

# Campos que añade el formateador JSON (no forman parte del evento firmado).
_FORMATTER_FIELDS = {"ts", "level", "logger", "msg", "exc", "taskName"}


class _Chain:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        self.stream = uuid.uuid4().hex[:16]
        self.seq = 0
        self.prev = ""


_chain = _Chain()
# Un proceso hijo (fork) empieza su propio flujo: si heredara el contador, dos
# procesos emitirían el mismo `audit_seq` y la verificación fallaría.
if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_chain.reset)


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode()


def _digest(key: bytes, prev: str, data: dict[str, Any]) -> str:
    payload = prev.encode() + b"\n" + _canonical(data)
    if key:
        return hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(payload).hexdigest()


def _key() -> bytes:
    return settings.AUDIT_HMAC_KEY.get_secret_value().encode()


def audit(event: str, *, level: int = logging.INFO, **fields: Any) -> None:
    data: dict[str, Any] = {"event": event}
    for key, value in fields.items():
        if value is not None:
            data[key] = value
    data["request_id"] = request_id_ctx.get()
    data["at"] = datetime.now(UTC).isoformat()
    # Ida y vuelta por JSON: lo que se firma es exactamente lo que se escribe en el log
    # (UUID, enums y fechas como texto), y el verificador puede recalcularlo.
    data = json.loads(_canonical(data))
    key = _key()
    with _chain.lock:
        _chain.seq += 1
        data["audit_alg"] = "hmac-sha256" if key else "sha256"
        data["audit_stream"] = _chain.stream
        data["audit_seq"] = _chain.seq
        data["audit_prev"] = _chain.prev
        data["audit_hash"] = _chain.prev = _digest(key, _chain.prev, data)
        # Dentro del lock: el orden de escritura coincide con el de la cadena.
        audit_logger.log(level, event, extra=data)


# ---------------------------------------------------------------------------
# Verificación (`apigen audit verify`)
# ---------------------------------------------------------------------------
@dataclass
class VerifyReport:
    events: int = 0
    streams: int = 0
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def verify_lines(lines: Iterable[str], key: bytes | None = None) -> VerifyReport:
    """Comprueba la cadena de los eventos de auditoría de un log JSON (una línea por
    registro; las que no son eventos de auditoría se ignoran)."""
    key = _key() if key is None else key
    report = VerifyReport()
    last: dict[str, tuple[int, str]] = {}
    for number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("logger") != "app.audit" or "audit_hash" not in record:
            continue
        report.events += 1
        stream, seq = record.get("audit_stream"), record.get("audit_seq")
        prev, stored = record.get("audit_prev", ""), record["audit_hash"]
        where = f"línea {number} (flujo {stream}, evento {seq})"
        if record.get("audit_alg") == "hmac-sha256" and not key:
            report.errors.append(f"{where}: firmado con HMAC y no hay AUDIT_HMAC_KEY")
            continue
        if record.get("audit_alg") == "sha256" and key:
            report.notes.append(f"{where}: evento sin HMAC (se emitió sin AUDIT_HMAC_KEY)")
        data = {k: v for k, v in record.items() if k not in _FORMATTER_FIELDS}
        data.pop("audit_hash")
        use_key = key if record.get("audit_alg") == "hmac-sha256" else b""
        if not hmac.compare_digest(_digest(use_key, prev, data), stored):
            report.errors.append(f"{where}: el contenido no coincide con su hash (alterado)")
        if stream not in last:
            report.streams += 1
            if seq != 1:
                report.notes.append(f"{where}: el flujo empieza a mitad (¿log rotado?)")
        else:
            last_seq, last_hash = last[stream]
            if seq != last_seq + 1:
                report.errors.append(
                    f"{where}: faltan eventos ({last_seq + 1}..{seq - 1}) o están desordenados"
                )
            elif prev != last_hash:
                report.errors.append(f"{where}: no enlaza con el evento anterior")
        last[stream] = (seq, stored)
    return report

"""Logging estructurado con request-id propagado mediante contextvars."""

from __future__ import annotations

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime

from app.core.config import settings

request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")

_RESERVED = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}
_TEXT_SKIP = _RESERVED | {"request_id", "color_message"}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _escape(text: str) -> str:
    """Escapa caracteres de control (CR/LF...): impide falsificar líneas de log con
    datos del cliente, p. ej. una ruta con %0a (SEC-13)."""
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = request_id_ctx.get()
        return True


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and key not in data:
                data[key] = value
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(data, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    """Formato legible para desarrollo: una línea por evento, con los campos
    `extra` (user_id, event...) al final y sin caracteres de control."""

    def format(self, record: logging.LogRecord) -> str:
        line = (
            f"{self.formatTime(record)} {record.levelname:<7} "
            f"[{getattr(record, 'request_id', '-')}] {record.name}: "
            f"{_escape(record.getMessage())}"
        )
        if record.name != "app.access":
            extras = [
                f"{key}={_escape(str(value))}"
                for key, value in record.__dict__.items()
                if key not in _TEXT_SKIP
            ]
            if extras:
                line += " | " + " ".join(extras)
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(_RequestIdFilter())
    if settings.log_json:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(TextFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(settings.LOG_LEVEL)
    # Nuestro middleware ya registra cada petición; evitamos duplicados.
    logging.getLogger("uvicorn.access").disabled = True
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers[:] = []
        logging.getLogger(name).propagate = True
    # Con LOG_LEVEL=DEBUG estas librerías vuelcan parámetros SQL (emails) o cabeceras
    # HTTP: nunca por debajo de WARNING (REQ-G01/G02).
    for name in ("aiosqlite", "httpx", "httpcore"):
        logging.getLogger(name).setLevel(max(logging.WARNING, root.level))

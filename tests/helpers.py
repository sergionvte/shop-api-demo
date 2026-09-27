"""Utilidades para tests (también las usan los tests generados por apigen)."""

import random
import string
import uuid
from datetime import UTC, date, datetime, timedelta


def _uid() -> str:
    return uuid.uuid4().hex[:10]


def _text(prefix: str, min_length: int = 0, max_length: int = 255) -> str:
    # El identificador aleatorio va delante para sobrevivir al recorte (unicidad).
    value = f"{_uid()}-{prefix}"
    if len(value) < min_length:
        value = value.ljust(min_length, "x")
    return value[:max_length]


def _rand_int(low: int, high: int) -> int:
    return random.randint(low, max(low, high))  # noqa: S311


def _like(example: str) -> str:
    """Valor aleatorio con la misma forma que `example` (a->letra, 9->dígito)."""
    out = []
    for ch in example:
        if ch.isdigit():
            out.append(random.choice(string.digits))  # noqa: S311
        elif ch.islower():
            out.append(random.choice(string.ascii_lowercase))  # noqa: S311
        elif ch.isupper():
            out.append(random.choice(string.ascii_uppercase))  # noqa: S311
        else:
            out.append(ch)
    return "".join(out)


def _future_date(offset: int = 0) -> str:
    """Fecha ISO dentro de un año (+offset días): válida para reglas tipo "no en el pasado"."""
    return (date.today() + timedelta(days=365 + offset)).isoformat()


def _future_datetime(offset: int = 0) -> str:
    """Fecha y hora ISO con zona, dentro de un año (+offset días), a las 10:00 UTC."""
    moment = datetime.now(UTC) + timedelta(days=365 + offset)
    return moment.replace(hour=10, minute=0, second=0, microsecond=0).isoformat()

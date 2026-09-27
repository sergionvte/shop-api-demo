"""Esquemas reutilizables: paginación, base de entradas y updates parciales."""

from __future__ import annotations

import json
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator
from pydantic_core import InitErrorDetails, PydanticCustomError

# Profundidad máxima por defecto de los campos `json` generados.
JSON_MAX_DEPTH = 10


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int


class Message(BaseModel):
    detail: str


def _has_nul(value: Any, depth: int = 0) -> bool:
    if isinstance(value, str):
        return "\x00" in value
    if depth > 32:
        return False
    if isinstance(value, dict):
        return any(_has_nul(k, depth + 1) or _has_nul(v, depth + 1) for k, v in value.items())
    if isinstance(value, list | tuple):
        return any(_has_nul(v, depth + 1) for v in value)
    return False


def raise_field_errors(
    title: str, errors: list[tuple[str, str, str, dict[str, Any] | None]]
) -> None:
    """Lanza varios errores de validación, cada uno con el `loc` de su campo.

    Un validador de modelo normal solo puede producir un error con `loc` vacío
    (["body"]); así el cliente puede marcar cada campo (UX-29).
    Cada error: (campo, type, plantilla del mensaje, contexto).
    """
    raise ValidationError.from_exception_data(
        title,
        [
            InitErrorDetails(
                type=PydanticCustomError(kind, template, ctx), loc=(field,), input=None
            )
            for field, kind, template, ctx in errors
        ],
    )


class StrictInput(BaseModel):
    """Base de todo lo que llega del cliente.

    - Rechaza campos desconocidos: impide la asignación masiva (p. ej. colar
      `owner_id` o `role`).
    - Rechaza el carácter NUL en cualquier texto (también dentro de JSON):
      PostgreSQL no lo admite y daría un 500 en lugar de un 422.
    """

    model_config = ConfigDict(extra="forbid")

    @field_validator("*", mode="before")
    @classmethod
    def _reject_nul(cls, value: Any) -> Any:
        if _has_nul(value):
            raise PydanticCustomError("null_character", "NUL characters are not allowed")
        return value


class PartialUpdate(StrictInput):
    """Base para PATCH: los campos omitidos no se tocan, los no-nullables no
    aceptan un `null` explícito y los inmutables dan un error claro."""

    __non_nullable__: ClassVar[frozenset[str]] = frozenset()
    __immutable__: ClassVar[frozenset[str]] = frozenset()

    @model_validator(mode="before")
    @classmethod
    def _reject_immutable(cls, data: Any) -> Any:
        if isinstance(data, dict):
            sent = sorted(cls.__immutable__ & data.keys())
            if sent:
                raise_field_errors(
                    cls.__name__,
                    [
                        (name, "immutable_field", "Field cannot be modified after creation", None)
                        for name in sent
                    ],
                )
        return data

    @model_validator(mode="after")
    def _reject_nulls(self):
        bad = sorted(
            name
            for name in self.model_fields_set & self.__non_nullable__
            if getattr(self, name) is None
        )
        if bad:
            raise_field_errors(
                type(self).__name__,
                [(name, "null_not_allowed", "Field cannot be null", None) for name in bad],
            )
        return self


def check_json_size(value: Any, max_bytes: int, max_depth: int = JSON_MAX_DEPTH) -> Any:
    """Validador para campos `json`: limita tamaño serializado y anidamiento
    (evita filas de casi 1 MiB que se multiplican en cada listado)."""

    def depth(node: Any, level: int = 1) -> int:
        if level > max_depth:
            return level
        if isinstance(node, dict):
            return max((depth(v, level + 1) for v in node.values()), default=level)
        if isinstance(node, list):
            return max((depth(v, level + 1) for v in node), default=level)
        return level - 1

    if depth(value) > max_depth:
        raise PydanticCustomError(
            "json_too_deep", "JSON nesting deeper than {max_depth}", {"max_depth": max_depth}
        )
    size = len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode())
    if size > max_bytes:
        raise PydanticCustomError(
            "json_too_large", "JSON larger than {max_bytes} bytes", {"max_bytes": max_bytes}
        )
    return value

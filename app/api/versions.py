"""Registro de versiones de la API.

Cada versión se monta en `{API_PREFIX}/{name}`. Marcar una versión como
deprecada añade las cabeceras `Deprecation` (RFC 9745) y `Sunset` (RFC 8594)
a todas sus respuestas y la marca como `deprecated` en OpenAPI. Gestiona esto
con `apigen version ...`.

Ojo: las versiones comparten modelos (tablas) y esquemas; lo que se versiona son
los routers. Un cambio incompatible en un esquema afecta a todas las versiones
(ver README, sección Versionado).
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import format_datetime


@dataclass(frozen=True, slots=True)
class APIVersion:
    name: str
    module: str
    deprecated: bool = False
    sunset: str | None = None  # fecha ISO (YYYY-MM-DD) de retirada
    deprecated_since: str | None = None  # fecha ISO (YYYY-MM-DD) de la deprecación

    def deprecation_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.deprecated_since:
            since = datetime.fromisoformat(self.deprecated_since).replace(tzinfo=UTC)
            headers["Deprecation"] = f"@{int(since.timestamp())}"  # RFC 9745
        else:
            headers["Deprecation"] = "true"  # formato antiguo (borrador)
        if self.sunset:
            sunset = datetime.fromisoformat(self.sunset).replace(tzinfo=UTC)
            headers["Sunset"] = format_datetime(sunset, usegmt=True)  # RFC 8594: HTTP-date
        return headers


VERSIONS: list[APIVersion] = [
    APIVersion(name="v1", module="app.api.v1.router"),
    # [apigen:versions]
]

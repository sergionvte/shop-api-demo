"""Roles, scopes y niveles de acceso.

- Un **rol** se asigna a cada usuario (user / admin).
- Cada rol concede un conjunto de **scopes**; el access token lleva los scopes
  concedidos (o un subconjunto si el cliente los pidió en el login, p. ej. un
  token de solo lectura con `scope=read`).
- Cada endpoint generado declara un **nivel de acceso** por acción.
"""

from enum import StrEnum


class Role(StrEnum):
    user = "user"
    admin = "admin"


class Scope(StrEnum):
    read = "read"  # leer recursos
    write = "write"  # crear / modificar / borrar recursos
    admin = "admin"  # administración (usuarios, recursos de nivel admin)


ROLE_SCOPES: dict[Role, frozenset[Scope]] = {
    Role.user: frozenset({Scope.read, Scope.write}),
    Role.admin: frozenset({Scope.read, Scope.write, Scope.admin}),
}

SCOPE_DESCRIPTIONS: dict[str, str] = {
    Scope.read: "Leer recursos",
    Scope.write: "Crear, modificar y borrar recursos",
    Scope.admin: "Administración",
}


class Access(StrEnum):
    public = "public"  # sin autenticación
    user = "user"  # cualquier usuario autenticado
    owner = "owner"  # autenticado y solo sobre sus propias filas (admin ve todo)
    admin = "admin"  # solo administradores

"""Registro de tareas en segundo plano.

Importar este paquete registra todas las tareas (la API lo hace al arrancar para
validar los nombres al encolar, y el worker para poder ejecutarlas).
`apigen` añade automáticamente los módulos de tareas nuevos antes del marcador.
"""

from app.tasks import builtin, mail  # noqa: F401

from app.tasks.resources import order  # noqa: F401
# [apigen:tasks]

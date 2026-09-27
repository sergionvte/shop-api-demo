"""Registro de modelos: todo modelo importado aquí es visible para Alembic.

`apigen` añade automáticamente los modelos nuevos antes del marcador.
"""

from app.models.account_token import AccountToken  # noqa: F401
from app.models.email_log import EmailLog  # noqa: F401
from app.models.job import Job  # noqa: F401
from app.models.refresh_token import RefreshToken  # noqa: F401
from app.models.user import User  # noqa: F401

from app.models.category import Category  # noqa: F401
from app.models.product import Product  # noqa: F401
from app.models.order import Order  # noqa: F401
# [apigen:models]

"""Enlaces de los correos: SOLO desde FRONTEND_URL + EMAIL_LINK_* (REQ-L01/L02).

Nunca desde la petición (Host, X-Forwarded-Host, Origin...): de hecho quien construye
el enlace es el worker, que no tiene petición HTTP.
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import quote

from app.core.config import settings


def build_link(kind: Literal["reset", "verify"], token: str) -> str:
    template = settings.EMAIL_LINK_RESET if kind == "reset" else settings.EMAIL_LINK_VERIFY
    return settings.FRONTEND_URL.rstrip("/") + template.replace("{token}", quote(token, safe=""))

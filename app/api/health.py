from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import text

from app.api.deps import SessionDep
from app.core.rate_limit import limiter

router = APIRouter(prefix="/health", tags=["health"])


class HealthStatus(BaseModel):
    status: str


@router.get("/live", response_model=HealthStatus)
@limiter.exempt
async def live() -> HealthStatus:
    """El proceso está vivo (para liveness probes). No toca la base de datos."""
    return HealthStatus(status="ok")


@router.get("/ready", response_model=HealthStatus)
async def ready(request: Request, response: Response, session: SessionDep) -> HealthStatus:
    """La API puede atender tráfico: la base de datos responde."""
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database unavailable"
        ) from None
    return HealthStatus(status="ok")

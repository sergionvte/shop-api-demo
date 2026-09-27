"""Tareas incluidas en la plantilla."""

from __future__ import annotations

from typing import Any

from app.tasks.registry import TaskContext, task


@task("system.echo", timeout=30, max_attempts=1)
async def echo(ctx: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Devuelve el payload recibido. Útil para comprobar que el worker funciona."""
    return {"echo": payload, "attempt": ctx.attempt}


@task("system.prune", timeout=300, max_attempts=1)
async def prune(ctx: TaskContext, payload: dict[str, Any]) -> dict[str, Any]:
    """Limpieza periódica: trabajos terminados antiguos."""
    from app.tasks.queue import prune_jobs

    return {"jobs_deleted": await prune_jobs(payload.get("older_than_days"))}

"""Operaciones de la cola: encolar (API) y reclamar/terminar (worker).

El reclamo es seguro con varios workers a la vez:
- PostgreSQL: `SELECT ... FOR UPDATE SKIP LOCKED`.
- SQLite (y como red de seguridad en ambos): `UPDATE ... WHERE status='queued'`
  condicional; solo el worker cuyo UPDATE afecta a la fila se queda el trabajo.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, func, text, update
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core.config import settings
from app.core.exceptions import APIError
from app.db.session import SessionFactory
from app.db.types import utcnow
from app.models.job import PENDING_STATUSES, Job, JobStatus
from app.schemas.job import JobAccepted
from app.tasks.registry import get_task

__all__ = [
    "JobAccepted", "cancel", "claim", "complete", "enqueue", "fail", "prune_jobs", "touch",
]  # fmt: skip

logger = logging.getLogger("app.tasks")


def _json_size(value: Any) -> int:
    return len(json.dumps(value, default=str, separators=(",", ":")))


async def enqueue(
    session: AsyncSession,
    name: str,
    payload: dict[str, Any] | None = None,
    *,
    owner_id: uuid.UUID | None = None,
    delay: float = 0,
    priority: int = 0,
    commit: bool = True,
) -> Job:
    """Encola una tarea y devuelve el trabajo creado (estado `queued`).

    Es barato: solo inserta una fila. El trabajo lo ejecuta `apigen worker`.
    """
    task = get_task(name)
    data = dict(payload or {})
    if task.payload_model is not None:
        data = task.payload_model.model_validate(data).model_dump(mode="json")
    if _json_size(data) > settings.JOBS_MAX_PAYLOAD_BYTES:
        raise APIError(413, "Job payload too large", code="job_payload_too_large")

    if owner_id is not None and settings.JOBS_MAX_PENDING_PER_USER:
        if settings.is_postgres:
            # Serializa los encolados de un mismo usuario hasta el commit: sin esto, N
            # peticiones a la vez contaban lo mismo y todas pasaban el límite (SEC-34).
            # En SQLite (desarrollo) el exceso posible con ráfagas es pequeño.
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
                {"key": f"apigen-jobs:{owner_id}"},
            )
        pending = (
            await session.exec(
                select(func.count())
                .select_from(Job)
                .where(col(Job.owner_id) == owner_id, col(Job.status).in_(PENDING_STATUSES))
            )
        ).one()
        if pending >= settings.JOBS_MAX_PENDING_PER_USER:
            # Contrapresión: un usuario no puede llenar la cola él solo.
            raise APIError(
                429,
                "Too many pending jobs; wait for some to finish",
                code="too_many_pending_jobs",
                headers={"Retry-After": "30"},
            )

    job = Job(
        name=name,
        payload=data,
        owner_id=owner_id,
        max_attempts=task.max_attempts,
        priority=priority,
        run_after=utcnow() + timedelta(seconds=max(delay, 0)),
    )
    session.add(job)
    if commit:
        await session.commit()
        await session.refresh(job)
    else:
        await session.flush()
    return job


async def claim(worker_id: str, limit: int, *, job_id: uuid.UUID | None = None) -> list[uuid.UUID]:
    """Reclama hasta `limit` trabajos listos y los marca como `running`.

    Con `job_id`, solo ese (envío `inline` de correos en desarrollo)."""
    if limit <= 0:
        return []
    now = utcnow()
    async with SessionFactory() as session:
        query = (
            select(Job.id, Job.name)
            .where(col(Job.status) == JobStatus.queued, col(Job.run_after) <= now)
            .order_by(col(Job.priority).desc(), col(Job.created_at))
            .limit(limit)
        )
        if job_id is not None:
            query = query.where(col(Job.id) == job_id)
        if settings.is_postgres:
            query = query.with_for_update(skip_locked=True)
        candidates = (await session.exec(query)).all()
        claimed: list[uuid.UUID] = []
        for job_id, name in candidates:
            try:
                timeout = get_task(name).timeout
            except LookupError:
                timeout = settings.JOBS_DEFAULT_TIMEOUT
            result = await session.execute(
                update(Job)
                .where(col(Job.id) == job_id, col(Job.status) == JobStatus.queued)
                .values(
                    status=JobStatus.running,
                    locked_by=worker_id,
                    # El arrendamiento cubre el timeout de la tarea con margen.
                    locked_until=now + timedelta(seconds=timeout + settings.JOBS_LEASE_GRACE),
                    started_at=now,
                    attempts=Job.attempts + 1,
                )
            )
            if result.rowcount == 1:
                claimed.append(job_id)
        await session.commit()
    return claimed


def _leased(job_id: uuid.UUID, worker_id: str | None) -> list[Any]:
    """Condición del UPDATE: el trabajo sigue en marcha y es de este worker (SEC-37)."""
    conditions = [col(Job.id) == job_id]
    if worker_id is not None:
        conditions += [col(Job.status) == JobStatus.running, col(Job.locked_by) == worker_id]
    return conditions


async def touch(job_id: uuid.UUID, worker_id: str, seconds: float) -> bool:
    """Renueva el arrendamiento (p. ej. cuando la tarea empieza de verdad a ejecutarse)."""
    async with SessionFactory() as session:
        result = await session.execute(
            update(Job)
            .where(*_leased(job_id, worker_id))
            .values(locked_until=utcnow() + timedelta(seconds=seconds + settings.JOBS_LEASE_GRACE))
        )
        await session.commit()
    return result.rowcount == 1


def _scrubbed_names() -> list[str]:
    from app.tasks.registry import REGISTRY

    return [name for name, task in REGISTRY.items() if task.scrub_payload]


def _scrubs(name: str) -> bool:
    try:
        return get_task(name).scrub_payload
    except LookupError:
        return False


async def complete(
    job_id: uuid.UUID, result: Any, *, worker_id: str | None = None, scrub: bool = False
) -> bool:
    """Marca el trabajo como terminado. Con `worker_id`, solo si sigue siendo suyo:
    devuelve False si otro worker lo reclamó entretanto (arrendamiento perdido).
    `scrub` vacía el payload (tareas con datos personales)."""
    if result is not None and _json_size(result) > settings.JOBS_MAX_RESULT_BYTES:
        result = {"truncated": True, "detail": "Result too large to store"}
    values: dict[str, Any] = {
        "status": JobStatus.succeeded,
        "result": result,
        "error": None,
        "finished_at": utcnow(),
        "locked_by": None,
        "locked_until": None,
    }
    if scrub:
        values["payload"] = {}
    async with SessionFactory() as session:
        done = await session.execute(
            update(Job).where(*_leased(job_id, worker_id)).values(**values)
        )
        await session.commit()
    return done.rowcount == 1


def backoff_seconds(attempt: int) -> int:
    """Reintentos con espera exponencial: 10 s, 20 s, 40 s... hasta 10 min."""
    return min(10 * 2 ** max(attempt - 1, 0), 600)


async def fail(
    job_id: uuid.UUID, message: str, *, retry: bool, worker_id: str | None = None
) -> str:
    """Registra un fallo. Devuelve el estado final (`queued` si se reintenta).

    Con `worker_id`, un fallo tardío de un worker que ya perdió el arrendamiento no
    toca el trabajo (p. ej. no devuelve a la cola uno que otro worker ya completó)."""
    async with SessionFactory() as session:
        job = await session.get(Job, job_id)
        if job is None:
            return JobStatus.failed
        will_retry = retry and job.attempts < job.max_attempts
        values: dict[str, Any] = {"error": message[:500], "locked_by": None, "locked_until": None}
        if will_retry:
            values.update(
                status=JobStatus.queued,
                run_after=utcnow() + timedelta(seconds=backoff_seconds(job.attempts)),
            )
        else:
            values.update(status=JobStatus.failed, finished_at=utcnow())
            if _scrubs(job.name):
                values["payload"] = {}
        result = await session.execute(
            update(Job).where(*_leased(job_id, worker_id)).values(**values)
        )
        await session.commit()
        if result.rowcount != 1:
            logger.warning("job lease lost: failure not recorded", extra={"job_id": str(job_id)})
            return "lease_lost"
        return values["status"]


async def reclaim_stale() -> int:
    """Devuelve a la cola los trabajos de workers caídos (arrendamiento vencido)."""
    now = utcnow()
    async with SessionFactory() as session:
        stale = col(Job.status) == JobStatus.running
        expired = col(Job.locked_until) < now
        retried = await session.execute(
            update(Job)
            .where(stale, expired, col(Job.attempts) < col(Job.max_attempts))
            .values(status=JobStatus.queued, locked_by=None, locked_until=None, run_after=now)
        )
        lost = {
            "status": JobStatus.failed,
            "error": "Worker lost while running the job",
            "finished_at": now,
            "locked_by": None,
            "locked_until": None,
        }
        # Las tareas con datos personales también se vacían aquí (SEC-43, REQ-Q03).
        private = _scrubbed_names()
        failed = await session.execute(
            update(Job).where(stale, expired, col(Job.name).in_(private)).values(**lost, payload={})
        )
        failed_rest = await session.execute(update(Job).where(stale, expired).values(**lost))
        await session.commit()
    total = retried.rowcount + failed.rowcount + failed_rest.rowcount
    if total:
        logger.warning("reclaimed %s stale jobs", total)
    return total


async def cancel(session: AsyncSession, job: Job) -> bool:
    """Cancela un trabajo aún en cola. Devuelve False si ya empezó o terminó."""
    values: dict[str, Any] = {"status": JobStatus.cancelled, "finished_at": utcnow()}
    if _scrubs(job.name):
        values["payload"] = {}  # SEC-43
    result = await session.execute(
        update(Job)
        .where(col(Job.id) == job.id, col(Job.status) == JobStatus.queued)
        .values(**values)
    )
    await session.commit()
    return result.rowcount == 1


async def prune_jobs(older_than_days: int | None = None) -> int:
    """Borra trabajos terminados más antiguos que la retención configurada."""
    days = settings.JOBS_RETENTION_DAYS if older_than_days is None else older_than_days
    limit = utcnow() - timedelta(days=days)
    finished = (JobStatus.succeeded, JobStatus.failed, JobStatus.cancelled)
    async with SessionFactory() as session:
        result = await session.execute(
            delete(Job).where(col(Job.status).in_(finished), col(Job.finished_at) < limit)
        )
        await session.commit()
    return result.rowcount

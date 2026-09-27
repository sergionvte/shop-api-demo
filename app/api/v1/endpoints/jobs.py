"""Consulta y cancelación de trabajos en segundo plano.

Cada usuario ve solo sus trabajos (los ajenos devuelven 404); un admin ve todos.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func
from sqlmodel import col, select

from app.api.deps import PaginationDep, Principal, SessionDep, error_responses, require
from app.core.exceptions import APIError
from app.core.permissions import Access, Scope
from app.models.job import Job, JobStatus
from app.schemas.common import Page
from app.schemas.job import JobRead
from app.tasks.queue import cancel

router = APIRouter(prefix="/jobs", tags=["jobs"], responses=error_responses(401, 403, 429))

CanRead = Annotated[Principal, Depends(require(Access.user, Scope.read))]
CanWrite = Annotated[Principal, Depends(require(Access.user, Scope.write))]


async def _get_or_404(session: SessionDep, job_id: uuid.UUID, principal: Principal) -> Job:
    job = await session.get(Job, job_id)
    if job is None or (not principal.is_admin and job.owner_id != principal.user_id):
        raise APIError(status.HTTP_404_NOT_FOUND, "Job not found", code="not_found")
    return job


@router.get("", response_model=Page[JobRead])
async def list_jobs(
    principal: CanRead,
    session: SessionDep,
    page: PaginationDep,
    status_filter: Annotated[JobStatus | None, Query(alias="status")] = None,
    name: Annotated[str | None, Query(max_length=100)] = None,
) -> Page[JobRead]:
    query = select(Job)
    if not principal.is_admin:
        query = query.where(col(Job.owner_id) == principal.user_id)
    if status_filter is not None:
        query = query.where(col(Job.status) == status_filter)
    if name:
        query = query.where(col(Job.name) == name)
    total = (await session.exec(select(func.count()).select_from(query.subquery()))).one()
    rows = await session.exec(
        query.order_by(col(Job.created_at).desc(), col(Job.id).desc())
        .offset(page.offset)
        .limit(page.limit)
    )
    return Page(items=rows.all(), total=total, limit=page.limit, offset=page.offset)  # type: ignore[arg-type]


@router.get("/{job_id}", response_model=JobRead, responses=error_responses(404))
async def get_job(job_id: uuid.UUID, principal: CanRead, session: SessionDep) -> Job:
    """Estado de un trabajo: `queued` → `running` → `succeeded` / `failed`."""
    return await _get_or_404(session, job_id, principal)


@router.post("/{job_id}/cancel", response_model=JobRead, responses=error_responses(404, 409))
async def cancel_job(job_id: uuid.UUID, principal: CanWrite, session: SessionDep) -> Job:
    """Cancela un trabajo que aún no ha empezado."""
    job = await _get_or_404(session, job_id, principal)
    if not await cancel(session, job):
        raise APIError(
            status.HTTP_409_CONFLICT,
            f"Job cannot be cancelled in status '{job.status}'",
            code="job_not_cancellable",
        )
    await session.refresh(job)
    return job

"""Cola de trabajos en segundo plano: ejecución, permisos, reintentos y límites."""

from datetime import timedelta

import pytest
from sqlalchemy import update
from sqlmodel import col

import tests.tasks_for_tests  # noqa: F401  (registra las tareas de prueba)
from app.core.config import settings
from app.core.exceptions import APIError
from app.db.session import SessionFactory
from app.db.types import utcnow
from app.models.job import Job, JobStatus
from app.tasks import queue
from app.tasks.worker import process_pending


async def _enqueue(name, payload=None, owner=None, **kwargs) -> Job:
    async with SessionFactory() as session:
        return await queue.enqueue(
            session, name, payload, owner_id=owner.id if owner else None, **kwargs
        )


async def _job(job_id) -> Job:
    async with SessionFactory() as session:
        return await session.get(Job, job_id)


async def _make_ready(job_id) -> None:
    async with SessionFactory() as session:
        await session.execute(update(Job).where(col(Job.id) == job_id).values(run_after=utcnow()))
        await session.commit()


async def test_job_runs_in_worker_and_owner_sees_result(client, user, user_headers):
    job = await _enqueue("system.echo", {"hello": "world"}, owner=user)
    assert job.status == JobStatus.queued

    queued = await client.get(f"/api/v1/jobs/{job.id}", headers=user_headers)
    assert queued.json()["status"] == "queued"

    assert await process_pending() >= 1
    done = await client.get(f"/api/v1/jobs/{job.id}", headers=user_headers)
    assert done.status_code == 200
    body = done.json()
    assert body["status"] == "succeeded"
    assert body["result"]["echo"] == {"hello": "world"}
    assert body["attempts"] == 1


async def test_jobs_are_private(client, user, other_headers, admin_headers, user_headers):
    job = await _enqueue("system.echo", {}, owner=user)
    assert (await client.get(f"/api/v1/jobs/{job.id}", headers=other_headers)).status_code == 404
    assert (await client.get(f"/api/v1/jobs/{job.id}", headers=admin_headers)).status_code == 200
    mine = await client.get("/api/v1/jobs", headers=user_headers)
    assert str(job.id) in [j["id"] for j in mine.json()["items"]]
    theirs = await client.get("/api/v1/jobs", headers=other_headers)
    assert str(job.id) not in [j["id"] for j in theirs.json()["items"]]
    assert (await client.get(f"/api/v1/jobs/{job.id}")).status_code == 401


async def test_cancel_only_while_queued(client, user, user_headers):
    job = await _enqueue("system.echo", {}, owner=user, delay=3600)
    r = await client.post(f"/api/v1/jobs/{job.id}/cancel", headers=user_headers)
    assert r.status_code == 200 and r.json()["status"] == "cancelled"
    again = await client.post(f"/api/v1/jobs/{job.id}/cancel", headers=user_headers)
    assert again.status_code == 409 and again.json()["code"] == "job_not_cancellable"


async def test_process_and_thread_executors():
    squared = await _enqueue("tests.square", {"n": 12})
    blocked = await _enqueue("tests.blocking", {})
    await process_pending()
    assert (await _job(squared.id)).result == {"value": 144}
    assert (await _job(blocked.id)).status == JobStatus.succeeded


async def test_failures_retry_with_backoff_and_hide_internal_errors():
    job = await _enqueue("tests.flaky")
    await process_pending()
    first = await _job(job.id)
    assert first.status == JobStatus.queued and first.attempts == 1
    assert first.run_after > utcnow()  # espera antes del reintento
    assert first.error == "Task failed" and "hunter2" not in first.error

    await _make_ready(job.id)
    await process_pending()
    final = await _job(job.id)
    assert final.status == JobStatus.failed and final.attempts == 2


async def test_task_error_message_is_shown_and_not_retried():
    job = await _enqueue("tests.business_error")
    await process_pending()
    done = await _job(job.id)
    assert done.status == JobStatus.failed
    assert done.error == "The report has no rows"
    assert done.attempts == 1


async def test_timeout_marks_job_failed():
    job = await _enqueue("tests.slow")
    await process_pending()
    done = await _job(job.id)
    assert done.status == JobStatus.failed and "Timed out" in done.error


async def test_payload_limits_and_backpressure(user, monkeypatch):
    with pytest.raises(APIError) as too_big:
        await _enqueue("system.echo", {"x": "a" * (settings.JOBS_MAX_PAYLOAD_BYTES + 1)})
    assert too_big.value.status_code == 413

    monkeypatch.setattr(settings, "JOBS_MAX_PENDING_PER_USER", 2)
    await _enqueue("system.echo", {}, owner=user, delay=3600)
    await _enqueue("system.echo", {}, owner=user, delay=3600)
    with pytest.raises(APIError) as full:
        await _enqueue("system.echo", {}, owner=user)
    assert full.value.status_code == 429 and full.value.code == "too_many_pending_jobs"


async def test_unknown_task_cannot_be_enqueued_and_orphans_fail():
    async with SessionFactory() as session:
        with pytest.raises(LookupError):
            await queue.enqueue(session, "does.not.exist")
        orphan = Job(name="removed.task")
        session.add(orphan)
        await session.commit()
        orphan_id = orphan.id
    await process_pending()
    done = await _job(orphan_id)
    assert done.status == JobStatus.failed and done.error == "Unknown task"


async def test_stale_jobs_from_dead_workers_are_reclaimed():
    job = await _enqueue("tests.blocking", {})  # admite reintentos (max_attempts=3)
    claimed = await queue.claim("dead-worker", 50)
    assert job.id in claimed
    async with SessionFactory() as session:
        await session.execute(
            update(Job)
            .where(col(Job.id) == job.id)
            .values(locked_until=utcnow() - timedelta(seconds=1))
        )
        await session.commit()
    assert await queue.reclaim_stale() >= 1
    assert (await _job(job.id)).status == JobStatus.queued
    await process_pending()
    assert (await _job(job.id)).status == JobStatus.succeeded


async def test_a_job_is_claimed_only_once():
    job = await _enqueue("system.echo", {})
    first = await queue.claim("worker-a", 100)
    second = await queue.claim("worker-b", 100)
    assert job.id in first and job.id not in second


async def test_prune_removes_old_finished_jobs():
    job = await _enqueue("system.echo", {})
    await process_pending()
    async with SessionFactory() as session:
        await session.execute(
            update(Job)
            .where(col(Job.id) == job.id)
            .values(finished_at=utcnow() - timedelta(days=settings.JOBS_RETENTION_DAYS + 1))
        )
        await session.commit()
    assert await queue.prune_jobs() >= 1
    assert await _job(job.id) is None


async def test_process_timeout_kills_the_process_and_frees_the_slot(tmp_path):
    """SEC-33: al vencer el timeout se mata el proceso de la tarea (no sigue corriendo
    ni ocupa el pool) y una tarea rápida posterior termina bien."""
    import os

    pidfile = tmp_path / "hang.pid"
    hung = await _enqueue("tests.hang_process", {"pidfile": str(pidfile)})
    await process_pending()
    fast = await _enqueue("tests.square", {"n": 3})
    await process_pending()
    first = await _job(hung.id)
    assert first.status == JobStatus.queued and "Timed out" in first.error  # se reintentará
    assert (await _job(fast.id)).result == {"value": 9}
    with pytest.raises(ProcessLookupError):  # el proceso vencido ya no existe
        os.kill(int(pidfile.read_text()), 0)


async def test_thread_timeout_is_not_retried():
    """SEC-33: un hilo no se puede interrumpir; reintentar duplicaría la ejecución."""
    job = await _enqueue("tests.hang_thread")
    await process_pending()
    done = await _job(job.id)
    assert done.status == JobStatus.failed and done.attempts == 1
    assert "Timed out" in done.error


async def test_sync_tasks_can_receive_the_context(user):
    """UX-53: las tareas thread/process saben quién las pidió."""
    by_thread = await _enqueue("tests.whoami_thread", {}, owner=user)
    by_process = await _enqueue("tests.whoami_process", {}, owner=user)
    await process_pending()
    for job in (by_thread, by_process):
        done = await _job(job.id)
        assert done.status == JobStatus.succeeded, done.error
        assert done.result["owner"] == str(user.id) and done.result["job"] == str(job.id)


async def test_results_are_only_saved_by_the_lease_holder():
    """SEC-37: un worker que perdió el arrendamiento no pisa el estado del trabajo."""
    job = await _enqueue("system.echo", {})
    assert job.id in await queue.claim("worker-a", 100)
    assert not await queue.complete(job.id, {"late": True}, worker_id="worker-b")
    assert await queue.fail(job.id, "late", retry=True, worker_id="worker-b") == "lease_lost"
    assert (await _job(job.id)).status == JobStatus.running
    assert await queue.complete(job.id, {"ok": True}, worker_id="worker-a")
    done = await _job(job.id)
    assert done.status == JobStatus.succeeded and done.result == {"ok": True}
    # Un fallo tardío tampoco devuelve a la cola un trabajo ya terminado.
    assert await queue.fail(job.id, "late", retry=True, worker_id="worker-a") == "lease_lost"
    assert (await _job(job.id)).status == JobStatus.succeeded


def test_heartbeat_does_not_follow_symlinks(tmp_path, monkeypatch):
    """SEC-36: el latido sustituye el fichero; nunca escribe a través de un enlace."""
    from app.tasks.worker import Worker, heartbeat_path

    victim = tmp_path / "victim.txt"
    victim.write_text("ORIGINAL")
    beat = tmp_path / "beat"
    beat.symlink_to(victim)
    monkeypatch.setattr(settings, "JOBS_HEARTBEAT_FILE", str(beat))
    assert heartbeat_path() == str(beat)
    Worker._heartbeat()
    assert victim.read_text() == "ORIGINAL"
    assert not beat.is_symlink() and beat.read_text().isdigit()
    assert oct(beat.stat().st_mode & 0o777) == "0o600"


async def test_worker_heartbeat_only_while_database_answers(tmp_path, monkeypatch):
    """SEC-39: con la BD caída no hay latido (el healthcheck pasa a unhealthy) y la
    traza completa solo se escribe una vez."""
    import asyncio

    from app.tasks import worker as worker_mod

    beat = tmp_path / "beat"
    monkeypatch.setattr(settings, "JOBS_HEARTBEAT_FILE", str(beat))

    async def broken(*args, **kwargs):
        raise ConnectionError("database is down")

    monkeypatch.setattr(worker_mod.queue, "claim", broken)
    monkeypatch.setattr(worker_mod.queue, "reclaim_stale", broken)
    w = worker_mod.Worker(concurrency=1, poll_interval=0.05)
    runner = asyncio.create_task(w.run())
    await asyncio.sleep(0.4)
    w.stop()
    await runner
    assert not beat.exists() and w._errors >= 2

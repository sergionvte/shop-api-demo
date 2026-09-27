"""Worker de tareas en segundo plano: `apigen worker` (o `python -m app.tasks.worker`).

Corre en un proceso separado de la API, así que un trabajo pesado nunca
ralentiza las peticiones HTTP. Puedes arrancar tantos workers como quieras
(en la misma máquina o en otras): el reclamo de trabajos es atómico.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import multiprocessing
import os
import signal
import socket
import tempfile
import traceback
import uuid
from functools import partial
from typing import Any

import anyio

from app.core.config import settings
from app.db.session import SessionFactory, engine
from app.models.job import Job
from app.tasks import queue
from app.tasks.registry import REGISTRY, TaskContext, TaskDef, TaskError

logger = logging.getLogger("app.tasks")
# Sin fichero de latido sano durante este tiempo, el healthcheck lo da por caído.
HEALTHY_WITHIN = 60


def heartbeat_path() -> str:
    """Fichero de latido que comprueba el healthcheck (JOBS_HEARTBEAT_FILE)."""
    return settings.JOBS_HEARTBEAT_FILE or os.path.join(
        tempfile.gettempdir(), "apigen-worker.heartbeat"
    )


# --- executor=process: un proceso por trabajo -----------------------------------------
# Un ProcessPoolExecutor no puede interrumpir una tarea: al vencer el timeout el
# proceso seguía ocupando el pool y el reintento corría a la vez (SEC-33). Con un
# proceso por trabajo, al vencer se mata solo ese proceso.
_slots: tuple[asyncio.AbstractEventLoop, asyncio.Semaphore] | None = None


def _process_slots() -> asyncio.Semaphore:
    """Como mucho JOBS_PROCESS_WORKERS procesos de tareas a la vez (por worker)."""
    global _slots
    loop = asyncio.get_running_loop()
    if _slots is None or _slots[0] is not loop:
        _slots = (loop, asyncio.Semaphore(settings.JOBS_PROCESS_WORKERS))
    return _slots[1]


def _mp_context() -> Any:
    # forkserver (Linux): hijos limpios, sin heredar hilos ni conexiones del worker.
    # spawn (macOS/Windows). La función de la tarea se importa en el hijo por su nombre.
    methods = multiprocessing.get_all_start_methods()
    return multiprocessing.get_context("forkserver" if "forkserver" in methods else "spawn")


class _ChildError(Exception):
    """Excepción no controlada dentro del proceso de la tarea."""

    def __init__(self, kind: str, trace: str) -> None:
        super().__init__(kind)
        self.kind = kind
        self.trace = trace


def _child_main(func: Any, args: tuple[Any, ...], conn: Any) -> None:
    """Punto de entrada del proceso hijo: ejecuta la tarea y envía el resultado."""
    try:
        result = func(*args)
        json.dumps(result)  # el resultado debe ser serializable
        conn.send(("ok", result))
    except TaskError as exc:
        conn.send(("task_error", str(exc), exc.retry))
    except BaseException as exc:  # noqa: BLE001 (se informa al worker, que decide)
        conn.send(("error", type(exc).__name__, traceback.format_exc()))
    finally:
        conn.close()


async def _run_in_process(func: Any, args: tuple[Any, ...], limit: float) -> Any:
    ctx = _mp_context()
    receiver, sender = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_child_main, args=(func, args, sender), daemon=True)
    proc.start()
    sender.close()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + limit
    try:
        while not receiver.poll():
            if not proc.is_alive() and not receiver.poll():
                raise _ChildError(f"exit code {proc.exitcode}", "task process died")
            if loop.time() >= deadline:
                raise TimeoutError
            await asyncio.sleep(0.05)
        message = receiver.recv()
    finally:
        # Timeout, cancelación (parada del worker) o fin normal: el hijo no sobrevive.
        if proc.is_alive():
            proc.kill()
        await asyncio.to_thread(proc.join, 5)
        receiver.close()
    if message[0] == "ok":
        return message[1]
    if message[0] == "task_error":
        raise TaskError(message[1], retry=message[2])
    raise _ChildError(message[1], message[2])


async def _execute(task: TaskDef, job: Job, worker_id: str | None) -> Any:
    ctx = TaskContext(job_id=job.id, owner_id=job.owner_id, attempt=job.attempts)
    args = (ctx, dict(job.payload)) if task.takes_ctx else (dict(job.payload),)
    if task.executor == "async":
        return await asyncio.wait_for(task.func(*args), timeout=task.timeout)
    if task.executor == "thread":
        # Un hilo no se puede matar: al vencer se abandona (ver run_job: sin reintento).
        return await asyncio.wait_for(
            anyio.to_thread.run_sync(partial(task.func, *args), abandon_on_cancel=True),
            timeout=task.timeout,
        )
    async with _process_slots():
        # El timeout cuenta desde que la tarea empieza, no desde que espera turno:
        # se renueva el arrendamiento para que otro worker no la reclame mientras.
        if worker_id is not None:
            await queue.touch(job.id, worker_id, task.timeout)
        return await _run_in_process(task.func, args, task.timeout)


async def run_job(job_id: uuid.UUID, worker_id: str | None = None) -> str:
    """Ejecuta un trabajo ya reclamado y registra el resultado. Nunca lanza.

    Con `worker_id`, el resultado solo se guarda si este worker sigue siendo el
    dueño del arrendamiento (SEC-37)."""
    async with SessionFactory() as session:
        job = await session.get(Job, job_id)
    if job is None:
        return "missing"
    task = REGISTRY.get(job.name)
    if task is None:
        logger.error("unknown task %s (job %s)", job.name, job.id)
        return await queue.fail(job.id, "Unknown task", retry=False, worker_id=worker_id)

    extra = {"job_id": str(job.id), "task": job.name, "attempt": job.attempts}
    logger.info("job started", extra=extra)
    fail = partial(queue.fail, job.id, worker_id=worker_id)
    try:
        result = await _execute(task, job, worker_id)
        json.dumps(result)  # el resultado debe ser serializable
    except TimeoutError:
        logger.warning("job timed out", extra=extra)
        # Un hilo abandonado sigue corriendo: reintentar duplicaría la ejecución.
        return await fail(f"Timed out after {task.timeout:g}s", retry=task.executor != "thread")
    except TaskError as exc:
        logger.info("job failed: %s", exc, extra=extra)
        return await fail(str(exc), retry=exc.retry)
    except _ChildError as exc:
        # La traza del proceso hijo va al log (con job_id); al cliente, mensaje genérico.
        logger.error("job failed: %s\n%s", exc.kind, exc.trace, extra=extra)
        return await fail("Task failed", retry=exc.kind != "TypeError")
    except (TypeError, ValueError) as exc:
        logger.exception("job failed", extra=extra)
        return await fail("Task failed", retry=not isinstance(exc, TypeError))
    except Exception:
        # La traza va al log (con job_id); al cliente solo un mensaje genérico.
        logger.exception("job failed", extra=extra)
        return await fail("Task failed", retry=True)
    if not await queue.complete(job.id, result, worker_id=worker_id, scrub=task.scrub_payload):
        logger.warning("job lease lost: result discarded", extra=extra)
        return "lease_lost"
    logger.info("job succeeded", extra=extra)
    return "succeeded"


async def run_now(job_id: uuid.UUID, worker_id: str = "inline") -> str:
    """Reclama y ejecuta un trabajo concreto ya encolado (envío `inline` en desarrollo).
    Si un worker se lo llevó antes, no hace nada."""
    if not await queue.claim(worker_id, 1, job_id=job_id):
        return "not_claimed"
    return await run_job(job_id, worker_id)


async def process_pending(limit: int = 100, worker_id: str = "inline") -> int:
    """Procesa los trabajos listos y vuelve (útil en tests y en `apigen worker --once`)."""
    done = 0
    while done < limit:
        batch = await queue.claim(worker_id, min(10, limit - done))
        if not batch:
            break
        for job_id in batch:
            await run_job(job_id, worker_id)
            done += 1
    return done


class Worker:
    def __init__(self, concurrency: int, poll_interval: float) -> None:
        self.concurrency = concurrency
        self.poll_interval = poll_interval
        self.worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
        self._stop = asyncio.Event()
        self._running: set[asyncio.Task[str]] = set()
        self._errors = 0  # errores seguidos del bucle (BD caída...)
        self._last_ok: float | None = None  # última vez que se habló con la BD

    def stop(self) -> None:
        if not self._stop.is_set():
            logger.info("worker stopping: finishing running jobs")
            self._stop.set()

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self.stop)
        logger.info(
            "worker %s started (concurrency=%s, tasks=%s)",
            self.worker_id,
            self.concurrency,
            ", ".join(sorted(REGISTRY)) or "-",
        )
        last_reclaim = last_beat = float("-inf")
        while not self._stop.is_set():
            now = loop.time()
            if now - last_reclaim > settings.JOBS_RECLAIM_INTERVAL:
                await self._safe(queue.reclaim_stale())
                last_reclaim = now
            free = self.concurrency - len(self._running)
            claimed = await self._safe(queue.claim(self.worker_id, free))
            # Latido solo si la BD responde (SEC-39): con la BD caída el healthcheck
            # pasa a unhealthy en vez de seguir diciendo "healthy".
            if self._last_ok is not None and loop.time() - self._last_ok < HEALTHY_WITHIN / 2:
                if loop.time() - last_beat > 5:
                    self._heartbeat()
                    last_beat = loop.time()
            for job_id in claimed or []:
                job_task = asyncio.create_task(run_job(job_id, self.worker_id))
                self._running.add(job_task)
                job_task.add_done_callback(self._running.discard)
            # Si la cola está vacía o estamos al máximo, espera antes de volver a mirar.
            # Con errores seguidos, espera creciente (hasta 30 s) en vez de insistir.
            if not claimed or len(self._running) >= self.concurrency:
                wait = min(self.poll_interval * 2**self._errors, 30.0)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=wait)
                except TimeoutError:
                    pass
        if self._running:
            _, pending = await asyncio.wait(self._running, timeout=settings.JOBS_SHUTDOWN_GRACE)
            for job_task in pending:
                job_task.cancel()  # el arrendamiento vencerá y volverán a la cola
        logger.info("worker %s stopped", self.worker_id)

    @staticmethod
    def _heartbeat() -> None:
        """Escribe el latido sin seguir enlaces simbólicos (SEC-36): fichero temporal
        nuevo (0600, O_EXCL) que sustituye al anterior con un rename atómico."""
        path = heartbeat_path()
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".heartbeat-")
            with os.fdopen(fd, "w") as fh:
                fh.write(str(os.getpid()))
            os.replace(tmp, path)
            tmp = None
        except OSError:
            logger.warning("cannot write worker heartbeat %s", path)
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    async def _safe(self, coro):
        try:
            result = await coro
        except Exception as exc:
            # La BD puede estar caída un momento: el worker no muere por ello. La traza
            # completa solo la primera vez; después, una línea (SEC-39).
            self._errors += 1
            if self._errors == 1:
                logger.exception("worker loop error")
            else:
                logger.warning("worker loop error (%s in a row): %s", self._errors, exc)
            return None
        if self._errors:
            logger.info("worker loop recovered after %s errors", self._errors)
            self._errors = 0
        self._last_ok = asyncio.get_running_loop().time()
        return result


async def _main(args: argparse.Namespace) -> None:
    try:
        if args.once:
            count = await process_pending(limit=args.limit)
            logger.info("processed %s jobs", count)
        else:
            await Worker(args.concurrency, args.poll_interval).run()
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> None:
    from app.core.logging import setup_logging

    parser = argparse.ArgumentParser(description="Worker de tareas en segundo plano")
    parser.add_argument("--concurrency", type=int, default=settings.JOBS_CONCURRENCY)
    parser.add_argument("--poll-interval", type=float, default=settings.JOBS_POLL_INTERVAL)
    parser.add_argument("--once", action="store_true", help="Procesar lo pendiente y salir")
    parser.add_argument("--limit", type=int, default=1000, help="Máximo de trabajos con --once")
    args = parser.parse_args(argv)
    setup_logging()
    import app.tasks  # noqa: F401  (registra todas las tareas)

    asyncio.run(_main(args))


if __name__ == "__main__":
    main()

"""Tareas usadas solo por los tests (módulo aparte: las de executor=process deben
poder importarse desde el proceso hijo sin arrastrar la app entera)."""

from __future__ import annotations

import asyncio
import os
import time

from app.tasks.registry import TaskContext, TaskError, task


@task("tests.square", executor="process", timeout=30)
def square(payload: dict) -> dict:
    return {"value": payload["n"] * payload["n"]}


@task("tests.blocking", executor="thread", timeout=30)
def blocking(payload: dict) -> dict:
    time.sleep(0.01)
    return {"slept": True}


@task("tests.flaky", max_attempts=2)
async def flaky(ctx: TaskContext, payload: dict) -> dict:
    raise RuntimeError("database password is hunter2")  # nunca debe llegar al cliente


@task("tests.business_error", max_attempts=3)
async def business_error(ctx: TaskContext, payload: dict) -> dict:
    raise TaskError("The report has no rows")


@task("tests.slow", timeout=0.05, max_attempts=1)
async def slow(ctx: TaskContext, payload: dict) -> dict:
    await asyncio.sleep(1)
    return {}


@task("tests.hang_process", executor="process", timeout=1, max_attempts=2)
def hang_process(payload: dict) -> dict:
    with open(payload["pidfile"], "w") as fh:
        fh.write(str(os.getpid()))
    time.sleep(8)
    return {}


@task("tests.hang_thread", executor="thread", timeout=0.2, max_attempts=3)
def hang_thread(payload: dict) -> dict:
    time.sleep(0.6)
    return {}


@task("tests.whoami_thread", executor="thread", timeout=30)
def whoami_thread(ctx: TaskContext, payload: dict) -> dict:
    return {"owner": str(ctx.owner_id), "job": str(ctx.job_id), "attempt": ctx.attempt}


@task("tests.whoami_process", executor="process", timeout=30)
def whoami_process(ctx: TaskContext, payload: dict) -> dict:
    return {"owner": str(ctx.owner_id), "job": str(ctx.job_id)}

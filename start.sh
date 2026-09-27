#!/bin/sh
# Arranque de la demo en un único contenedor (Render, plan free):
# migraciones -> datos de ejemplo -> worker en segundo plano -> API.
set -e
alembic upgrade head
python -m app.demo_seed
python -m app.tasks.worker --concurrency 2 &
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --workers "${WEB_CONCURRENCY:-1}" \
  --no-server-header --no-proxy-headers --no-access-log --timeout-keep-alive 5

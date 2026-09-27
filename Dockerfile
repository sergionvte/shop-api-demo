# syntax=docker/dockerfile:1.7
# ---- build: dependencias con uv ------------------------------------------------
FROM python:3.13-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
# README.txt (plantilla) o README.md (proyectos creados con scripts/new_api.py): el que haya.
COPY pyproject.toml uv.lock README* ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev --no-install-project
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini start.sh ./
# Plantillas de correo propias del proyecto (las de serie van dentro de app/email/).
COPY email_templates ./email_templates
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev

# ---- runtime: imagen mínima, usuario sin privilegios ------------------------------
FROM python:3.13-slim
RUN groupadd --system app && useradd --system --gid app --home /app app
WORKDIR /app
COPY --from=build --chown=app:app /app /app
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    ENVIRONMENT=production
USER app
EXPOSE 8000
# Render asigna el puerto en $PORT (por defecto 10000); en local, 8000.
# Con la cabecera Host del primer dominio de ALLOWED_HOSTS: si no, TrustedHost
# respondería 400 a "127.0.0.1" en cuanto ALLOWED_HOSTS tenga solo el dominio real.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import os,sys,urllib.request as u; h=os.environ.get('ALLOWED_HOSTS','localhost').split(',')[0].strip().replace('*','x') or 'localhost'; sys.exit(0 if u.urlopen(u.Request('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/health/live',headers={'Host':h}),timeout=3).status==200 else 1)"
# Demo: migraciones + datos de ejemplo + worker en segundo plano + API (start.sh).
CMD ["sh", "start.sh"]

.PHONY: install dev worker test lint docker-build docker-run

install:        ## Dependencias
	uv sync

dev:            ## API en local con recarga (http://127.0.0.1:8000/docs)
	uv run alembic upgrade head && uv run python -m app.demo_seed && uv run uvicorn app.main:app --reload

worker:         ## Tareas en segundo plano (otra terminal)
	uv run python -m app.tasks.worker

test:           ## Tests
	uv run pytest -q

lint:           ## Lint
	uv run ruff check .

docker-build:   ## Imagen de producción
	docker build -t tienda-demo-api .

docker-run:     ## Ejecuta la imagen como en Render (SQLite temporal)
	docker run --rm -p 8000:8000 --env-file .env.demo tienda-demo-api

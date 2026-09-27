# Tienda Demo API

API REST de ejemplo para una **tienda online**: catálogo público de categorías y productos,
registro y login con JWT, y **pedidos privados por cliente** con una factura que se genera
**en segundo plano**. Construida con FastAPI, SQLModel, JWT (access + refresh rotatorio),
rate limiting y una cola de trabajos propia.

> **Demo en vivo:** https://shop-api-demo.onrender.com/docs
> Alojada en el plan gratuito de Render: si lleva un rato sin uso, la primera petición tarda
> ~1 minuto en despertar. La base de datos es **temporal** y se reinicia con datos de ejemplo
> en cada arranque, así que puedes probar sin miedo.

## Pruébala en 1 minuto

1. Abre **`/docs`** (Swagger).
2. `POST /api/v1/auth/register` con tu email y una contraseña de 12+ caracteres.
3. Pulsa **Authorize**, entra con tu email (campo *username*) y contraseña.
4. `GET /api/v1/products` → elige un producto → `POST /api/v1/orders`
   con `{"product_id": "...", "quantity": 2, "shipping_address": "Calle 1"}`.
   El **total lo calcula el servidor** y el stock se descuenta.
5. `POST /api/v1/orders/{id}/invoice` → responde **202** con `status_url`;
   consúltalo y verás la factura generada por el worker.

También puedes importar la colección de **Postman** de `docs/postman/` (guarda y renueva el token sola).

### Reglas de negocio de la demo (`app/hooks/order.py`)
- El total y el estado inicial (`pending`) los fija el servidor; si no hay stock → **409 `insufficient_stock`**.
- El cliente solo ve sus pedidos, y solo puede cambiar la dirección o **cancelar** mientras están pendientes (cancelar devuelve el stock).
- Solo un admin puede marcar un pedido como `paid` o `shipped`; los pagados o enviados no se pueden borrar.
- La *Batería externa* tiene stock 3: pide 4 para ver el 409.

## Guía de integración (frontend / móvil)

URL base: `https://shop-api-demo.onrender.com` · prefijo: `/api/v1` · JSON de entrada y salida (`Content-Type: application/json`). Documentación interactiva en `https://shop-api-demo.onrender.com/docs` con `DOCS_ENABLED=true` (desactivada por defecto en producción).

### Primeros pasos

1. **Registro** (si el registro público está activado):

   ```bash
   curl -X POST https://shop-api-demo.onrender.com/api/v1/auth/register -H 'Content-Type: application/json' \
     -d '{"email": "ana@example.com", "password": "una frase larga"}'
   ```

   `201` → `{"id": "…", "email": "ana@example.com", "full_name": null, "role": "user", "is_active": true, "email_verified": false, "created_at": "…"}`
2. **Login** (formulario, no JSON):

   ```bash
   curl -X POST https://shop-api-demo.onrender.com/api/v1/auth/login -d 'username=ana@example.com' --data-urlencode 'password=una frase larga'
   ```

   `200` → `{"access_token": "eyJ…", "refresh_token": "…", "token_type": "bearer", "expires_in": 900, "scope": "read write"}`
3. **Llama a la API** con el token de acceso:

   ```bash
   curl https://shop-api-demo.onrender.com/api/v1/users/me -H "Authorization: Bearer $ACCESS_TOKEN"
   ```
4. **Renueva** al recibir `401` con `code: token_expired`:

   ```bash
   curl -X POST https://shop-api-demo.onrender.com/api/v1/auth/refresh -H 'Content-Type: application/json' -d '{"refresh_token": "…"}'
   ```

   Misma respuesta que el login: **guarda el par nuevo** (el refresh anterior deja de valer).

### Autenticación

- El token de acceso dura 15 minutos (`expires_in`, en segundos); el refresh, 7 días.
- Con `scope=read` en el formulario de login se obtiene un token de solo lectura (las escrituras responden `403 insufficient_scope`).
- `POST /api/v1/auth/logout` (con `refresh_token`) cierra una sesión; `POST /api/v1/auth/logout-all`, todas.
- Tras varios intentos fallidos la cuenta se bloquea un tiempo; el login sigue respondiendo `401 invalid_credentials` (no revela el bloqueo). Un admin puede desbloquearla.

### Postman

Importa `docs/postman/API.postman_collection.json` en Postman. Ajusta las variables de la colección `baseUrl`, `email` y `password` (en *Current value*), ejecuta **Auth > Login** y el resto de peticiones van con `Bearer {{accessToken}}`; el token se renueva solo antes de caducar. La carpeta **Account** cubre la recuperación de contraseña y la verificación del email: pega el token del enlace del correo (lo que va tras `#token=`) en `resetToken` o `verifyToken`.

### Listados y paginación

Todo listado responde `{"items": [...], "total": 42, "limit": 20, "offset": 0}`. Pagina con `limit` (1-100, por defecto 20) y `offset` (hasta 10000); `total` cuenta todas las filas que cumplen el filtro. `order_by` admite los campos indicados en cada recurso (prefijo `-` descendente). Un parámetro desconocido responde `422` con una pista (p. ej. usa `q`, no `search`).

### Errores

Los errores devuelven JSON con `detail` (texto para humanos) y `code` (estable, para tu código). Los `422` listan cada problema con su campo en `loc`.

| HTTP | code | |
|---|---|---|
| 401 | `not_authenticated / invalid_token / token_expired` | Token ausente o inválido |
| 403 | `forbidden / insufficient_scope` | Sin permiso |
| 404 | `not_found` | No existe (o no es tuyo) |
| 409 | `unique_violation / has_dependents` | Conflicto con datos existentes |
| 413 / 415 | `body_too_large / expects_json` | Problemas con el cuerpo |
| 422 | `validation_error` | Datos no válidos (ver `detail[].loc`) |
| 429 | `rate_limited / too_many_pending_jobs` | Demasiadas peticiones (ver `Retry-After`) |

#### Errores de negocio de esta API

Los devuelven las reglas de negocio de esta API (mismo formato JSON). Se extraen de `app/hooks/` cada vez que se genera esta documentación.

| HTTP | code | detail |
|---|---|---|
| 403 | `forbidden` | Only an admin can change the order status |
| 409 | `insufficient_stock` | Not enough stock for this product |
| 409 | `order_not_deletable` | Paid or shipped orders cannot be deleted |
| 409 | `order_not_pending` | Only pending orders can be modified |
| 422 | `order_locked` | These fields cannot be changed: … |
| 422 | `product_not_available` | Product not available |

### Cuentas y roles

El registro crea usuarios con rol `user`. Los admins (rol `admin`) ven y gestionan todo; en esta demo el admin se crea al arrancar (`app/demo_seed.py`) y los demás se promueven con `PATCH /api/v1/users/{id}` (`{"role": "admin"}`).

| Método | Ruta | Quién | Descripción |
|---|---|---|---|
| GET / PATCH | `/api/v1/users/me` | Usuario autenticado | Perfil propio |
| POST | `/api/v1/users/me/password` | Usuario autenticado | Cambiar contraseña (cierra sesiones) |
| GET / POST | `/api/v1/users` | Admins | Listar / crear usuarios |
| GET / PATCH / DELETE | `/api/v1/users/{id}` | Admins | Gestionar un usuario (rol, activo) |
| POST | `/api/v1/users/{id}/unlock` | Admins | Desbloquear una cuenta |

### Recursos

#### Versión de la API `v1` — `/api/v1`

##### `categories`

Categorías del catálogo

| Método | Ruta | Quién puede | Descripción |
|---|---|---|---|
| GET | `/api/v1/categories` | Cualquiera | Listar (paginado) |
| POST | `/api/v1/categories` | Admins | Crear |
| GET | `/api/v1/categories/{id}` | Cualquiera | Ver uno |
| PATCH | `/api/v1/categories/{id}` | Admins | Modificar (parcial) |
| DELETE | `/api/v1/categories/{id}` | Admins | Borrar |

Parámetros del listado: `limit`, `offset`, `order_by` (`created_at`, `name`), `q` (búsqueda en `name`).

| Campo | Tipo | Obligatorio | Reglas |
|---|---|---|---|
| `name` | texto | sí | max 80; único |
| `slug` | texto | sí | max 80; `^[a-z0-9-]+$`; único; no modificable |
| `description` | texto (largo) | no | max 500; admite null |
| `id`, `created_at`, `updated_at` | solo lectura | — | — |

Ejemplos:

```bash
# Crear
curl -X POST https://shop-api-demo.onrender.com/api/v1/categories -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "text", "slug": "ropa-deportiva"}'
# Listar (página, orden y filtro)
curl "https://shop-api-demo.onrender.com/api/v1/categories?limit=20&offset=0&order_by=-created_at"
```

##### `orders`

Pedidos; cada cliente solo ve los suyos

Cada registro pertenece al usuario que lo crea (`owner_id`, lo fija el servidor).

| Método | Ruta | Quién puede | Descripción |
|---|---|---|---|
| GET | `/api/v1/orders` | El dueño (admins: cualquiera) | Listar (paginado) |
| POST | `/api/v1/orders` | Usuario autenticado | Crear |
| GET | `/api/v1/orders/{id}` | El dueño (admins: cualquiera) | Ver uno |
| PATCH | `/api/v1/orders/{id}` | El dueño (admins: cualquiera) | Modificar (parcial) |
| DELETE | `/api/v1/orders/{id}` | El dueño (admins: cualquiera) | Borrar |
| POST | `/api/v1/orders/{id}/invoice` | El dueño (admins: cualquiera) | Genera la factura del pedido en segundo plano — segundo plano (202) |
| POST | `/api/v1/orders/{id}/summary` | El dueño (admins: cualquiera) | Resumen rápido del pedido |

Parámetros del listado: `limit`, `offset`, `order_by` (`created_at`, `quantity`), filtros: `status`, `product_id`.

| Campo | Tipo | Obligatorio | Reglas |
|---|---|---|---|
| `product_id` | UUID → `products` | sí | — |
| `quantity` | entero | sí | ≥ 1; ≤ 20 |
| `shipping_address` | texto (largo) | sí | max 500 |
| `status` | uno de: `pending`, `paid`, `shipped`, `cancelled` | no | por defecto `pending` |
| `total` | decimal (texto) | no | ≥ 0; 12 dígitos, 2 dec.; admite null; Lo calcula el servidor |
| `id`, `created_at`, `updated_at`, `owner_id` | solo lectura | — | — |

Ejemplos:

```bash
# Crear
curl -X POST https://shop-api-demo.onrender.com/api/v1/orders -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"product_id": "<product id>", "quantity": 1, "shipping_address": "Some text"}'
# Listar (página, orden y filtro)
curl "https://shop-api-demo.onrender.com/api/v1/orders?limit=20&offset=0&order_by=-created_at&status=pending" -H "Authorization: Bearer $TOKEN"
```

Acciones:

- `POST /api/v1/orders/{id}/invoice`: en segundo plano: `202` → `{"job_id": "…", "status": "queued", "status_url": "/api/v1/jobs/…"}` (también en `Location`); el resultado queda en `result` del trabajo (ver Tareas en segundo plano); sin cuerpo (o `{}`); rate limit 10/minute.
- `POST /api/v1/orders/{id}/summary`: `200` → un objeto JSON; sin cuerpo (o `{}`).

##### `products`

Productos a la venta

| Método | Ruta | Quién puede | Descripción |
|---|---|---|---|
| GET | `/api/v1/products` | Cualquiera | Listar (paginado) |
| POST | `/api/v1/products` | Admins | Crear |
| GET | `/api/v1/products/{id}` | Cualquiera | Ver uno |
| PATCH | `/api/v1/products/{id}` | Admins | Modificar (parcial) |
| DELETE | `/api/v1/products/{id}` | Admins | Borrar (lógico: deja de listarse y leerse) |

Parámetros del listado: `limit`, `offset`, `order_by` (`created_at`, `name`, `price`, `stock`), `q` (búsqueda en `name`), filtros: `active`, `category_id`.

| Campo | Tipo | Obligatorio | Reglas |
|---|---|---|---|
| `name` | texto | sí | max 120 |
| `description` | texto (largo) | no | max 2000; admite null |
| `price` | decimal (texto) | sí | ≥ 0; 10 dígitos, 2 dec. |
| `stock` | entero | no | ≥ 0; por defecto `0` |
| `active` | booleano | no | por defecto `True` |
| `image_url` | texto | no | max 500; admite null |
| `category_id` | UUID → `categories` | no | admite null |
| `id`, `created_at`, `updated_at` | solo lectura | — | — |

Ejemplos:

```bash
# Crear
curl -X POST https://shop-api-demo.onrender.com/api/v1/products -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "text", "price": "9.00"}'
# Listar (página, orden y filtro)
curl "https://shop-api-demo.onrender.com/api/v1/products?limit=20&offset=0&order_by=-created_at&active=true"
```

### Tareas en segundo plano

Las acciones pesadas responden `202` al instante y se ejecutan en un worker aparte. Consulta `status_url` cada 1-2 s (o con un intervalo creciente) hasta un estado final:

`queued` → `running` → `succeeded` (ver `result`) · `failed` (ver `error`) · `cancelled`.

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/v1/jobs` | Tus trabajos, los más recientes primero (admins: todos). Filtros: `status`, `name`, `limit`, `offset` |
| GET | `/api/v1/jobs/{id}` | Un trabajo |
| POST | `/api/v1/jobs/{id}/cancel` | Cancela un trabajo que aún no ha empezado; si no, `409 job_not_cancellable` |

Campos del trabajo: `id`, `name`, `status`, `attempts` / `max_attempts`, `result` (JSON, si `succeeded`), `error` (texto, si `failed`), `created_at`, `run_after` (próximo intento), `started_at`, `finished_at`.

- Los fallos se reintentan solos con una espera creciente (el trabajo vuelve a `queued`).
- `error` muestra los mensajes de negocio de la API; cualquier otro fallo, `Task failed`.
- Como mucho 20 trabajos pendientes por usuario: a partir de ahí, `429 too_many_pending_jobs` con `Retry-After`.

Mensajes que puede mostrar `error`: `Order no longer exists`.

### Límites de peticiones

Por defecto: 120/minute por endpoint y 1000/minute en total por cliente (usuario o IP). Login: 10/minute;50/hour. Registro: 5/hour (producción). Al superarlo se responde `429` con la cabecera `Retry-After`.

## Ejecutar en local

Requisitos: Python 3.12+ y [uv](https://docs.astral.sh/uv/).

```bash
uv sync
cp .env.example .env              # desarrollo: SQLite y valores por defecto
DEMO_ADMIN_PASSWORD='una contraseña larga' make dev    # http://127.0.0.1:8000/docs
make worker                       # otra terminal: facturas en segundo plano
make test
```

Con Docker, igual que en Render:
```bash
make docker-build
make docker-run                   # usa .env.demo (ver abajo)
```

## Cómo está desplegada (Render, plan gratuito)

Un único servicio web Docker. `start.sh` aplica las migraciones, carga los datos de ejemplo
(`app/demo_seed.py`), arranca el worker en segundo plano y después la API. Variables:

| Variable | Valor |
|---|---|
| `ENVIRONMENT` | `production` |
| `SECRET_KEY` | aleatoria (32+ caracteres) |
| `DATABASE_URL` | `sqlite+aiosqlite:////tmp/demo.db` (disco temporal) |
| `ALLOW_SQLITE_IN_PRODUCTION` | `true` |
| `ALLOWED_HOSTS` | `shop-api-demo.onrender.com` |
| `TRUSTED_PROXIES` | `127.0.0.1` (el proxy de Render llega desde dentro del contenedor: IP real del cliente y HSTS) |
| `DOCS_ENABLED` | `true` |
| `DEMO_ADMIN_EMAIL` / `DEMO_ADMIN_PASSWORD` | admin de la demo (la contraseña no se publica) |

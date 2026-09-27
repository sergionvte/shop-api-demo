"""Tests de `orders` (v1), generados por apigen.

Cubren el CRUD completo, permisos, aislamiento entre usuarios y asignación masiva.
Si cambias los endpoints a mano, ajusta estos tests en consecuencia.
"""

import uuid
from decimal import Decimal

from app.models.product import Product
from app.tasks.worker import process_pending
from tests.helpers import _text

BASE = "/api/v1/orders"


async def _payload(db, owner_id: uuid.UUID) -> dict:
    """Payload válido. Crea antes las filas padre que exigen las claves foráneas."""
    product_1 = Product(stock=100, name=_text("name", 0, 120), price=Decimal("0.00"))
    db.add(product_1)
    await db.commit()
    return {
        "product_id": str(product_1.id),
        "quantity": 1,
        "shipping_address": _text("shipping_address", 0, 500),
        "status": "pending",
        "total": "0.00",
    }


async def test_crud_flow(client, db, user, user_headers, admin, admin_headers):
    payload = await _payload(db, user.id)
    created = await client.post(BASE, json=payload, headers=user_headers)
    assert created.status_code == 201, created.text
    body = created.json()
    item_id = body["id"]
    assert body["owner_id"] == str(user.id)

    got = await client.get(f"{BASE}/{item_id}", headers=user_headers)
    assert got.status_code == 200, got.text

    listed = await client.get(BASE, params={"limit": 100}, headers=user_headers)
    assert listed.status_code == 200, listed.text
    assert item_id in [row["id"] for row in listed.json()["items"]]

    # Regla de la tienda (app/hooks/order.py): la cantidad no se puede cambiar,
    # la dirección de envío sí (mientras el pedido está pendiente).
    new_value = "Calle Nueva 42, Madrid"
    updated = await client.patch(
        f"{BASE}/{item_id}", json={"shipping_address": new_value}, headers=user_headers
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["shipping_address"] == new_value

    deleted = await client.delete(f"{BASE}/{item_id}", headers=user_headers)
    assert deleted.status_code == 204, deleted.text
    gone = await client.get(f"{BASE}/{item_id}", headers=user_headers)
    assert gone.status_code == 404


async def test_rejects_unknown_fields(client, db, user, user_headers, admin, admin_headers):
    """Asignación masiva: no se pueden colar campos como id u owner_id."""
    payload = await _payload(db, user.id)
    payload.update({"id": str(uuid.uuid4()), "owner_id": str(uuid.uuid4()), "is_admin": True})
    response = await client.post(BASE, json=payload, headers=user_headers)
    assert response.status_code == 422


async def test_invalid_ordering_rejected(client, user_headers, admin_headers):
    response = await client.get(BASE, params={"order_by": "hashed_password"}, headers=user_headers)
    assert response.status_code == 422


async def test_create_requires_auth(client, db, user):
    payload = await _payload(db, user.id)
    response = await client.post(BASE, json=payload)
    assert response.status_code == 401


async def test_read_only_token_cannot_write(client, db, user):
    from tests.conftest import headers_for

    payload = await _payload(db, user.id)
    response = await client.post(BASE, json=payload, headers=headers_for(user, ["read"]))
    assert response.status_code == 403


async def test_owner_isolation(client, db, user, user_headers, other_headers):
    """Otro usuario no puede ver, modificar ni borrar filas ajenas (404, no 403)."""
    payload = await _payload(db, user.id)
    created = await client.post(BASE, json=payload, headers=user_headers)
    assert created.status_code == 201, created.text
    item_id = created.json()["id"]

    assert (await client.get(f"{BASE}/{item_id}", headers=other_headers)).status_code == 404
    listed = await client.get(BASE, params={"limit": 100}, headers=other_headers)
    assert item_id not in [row["id"] for row in listed.json()["items"]]
    assert (
        await client.patch(f"{BASE}/{item_id}", json={}, headers=other_headers)
    ).status_code == 404
    assert (await client.delete(f"{BASE}/{item_id}", headers=other_headers)).status_code == 404


async def test_int_out_of_range_is_422(client, db, user, user_headers, admin, admin_headers):
    """Un entero fuera de 64 bits da 422, no un 500 por desbordamiento en la BD."""
    payload = await _payload(db, user.id)
    payload["quantity"] = 2**63
    response = await client.post(BASE, json=payload, headers=user_headers)
    assert response.status_code == 422, response.text


async def test_unknown_pagination_param_is_rejected(client, user_headers, admin_headers):
    """`page`/`size` no existen (se usa limit/offset): 422 en vez de ignorarlos."""
    response = await client.get(BASE, params={"page": 2}, headers=user_headers)
    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "unknown_parameter"


async def test_action_invoice(client, db, user, user_headers, admin, admin_headers, other_headers):
    payload = await _payload(db, user.id)
    created = await client.post(BASE, json=payload, headers=user_headers)
    assert created.status_code == 201, created.text
    url = f"{BASE}/{created.json()['id']}/invoice"
    body = {}
    # Campos desconocidos en el cuerpo: 422, como en el resto de la API.
    extra = await client.post(url, json={**body, "unexpected": 1}, headers=user_headers)
    assert extra.status_code == 422, extra.text
    # Solo el dueño (o un admin): para otro usuario la fila no existe.
    other = await client.post(url, json=body, headers=other_headers)
    assert other.status_code == 404, other.text
    response = await client.post(url, json=body, headers=user_headers)
    # La API solo encola (202); el trabajo lo ejecuta el worker.
    assert response.status_code == 202, response.text
    job = response.json()
    assert response.headers["location"] == job["status_url"]
    await process_pending()
    done = await client.get(job["status_url"], headers=user_headers)
    assert done.status_code == 200, done.text
    assert done.json()["status"] == "succeeded", done.json()
    assert (await client.post(url, json=body)).status_code == 401


async def test_action_summary(client, db, user, user_headers, admin, admin_headers, other_headers):
    payload = await _payload(db, user.id)
    created = await client.post(BASE, json=payload, headers=user_headers)
    assert created.status_code == 201, created.text
    url = f"{BASE}/{created.json()['id']}/summary"
    body = {}
    # Campos desconocidos en el cuerpo: 422, como en el resto de la API.
    extra = await client.post(url, json={**body, "unexpected": 1}, headers=user_headers)
    assert extra.status_code == 422, extra.text
    # Solo el dueño (o un admin): para otro usuario la fila no existe.
    other = await client.post(url, json=body, headers=other_headers)
    assert other.status_code == 404, other.text
    response = await client.post(url, json=body, headers=user_headers)
    assert response.status_code == 200, response.text
    assert (await client.post(url, json=body)).status_code == 401

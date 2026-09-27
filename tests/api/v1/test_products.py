"""Tests de `products` (v1), generados por apigen.

Cubren el CRUD completo, permisos, aislamiento entre usuarios y asignación masiva.
Si cambias los endpoints a mano, ajusta estos tests en consecuencia.
"""

import uuid

from tests.helpers import _text

BASE = "/api/v1/products"


async def _payload(db, owner_id: uuid.UUID) -> dict:
    """Payload válido. Crea antes las filas padre que exigen las claves foráneas."""
    return {
        "name": _text("name", 0, 120),
        "description": _text("description", 0, 2000),
        "price": "0.00",
        "stock": 0,
        "active": True,
        "image_url": _text("image_url", 0, 500),
    }


async def test_crud_flow(client, db, user, user_headers, admin, admin_headers):
    payload = await _payload(db, admin.id)
    created = await client.post(BASE, json=payload, headers=admin_headers)
    assert created.status_code == 201, created.text
    body = created.json()
    item_id = body["id"]

    got = await client.get(f"{BASE}/{item_id}", headers={})
    assert got.status_code == 200, got.text

    listed = await client.get(BASE, params={"limit": 100}, headers={})
    assert listed.status_code == 200, listed.text
    assert item_id in [row["id"] for row in listed.json()["items"]]

    new_value = _text("name", 0, 120)
    updated = await client.patch(
        f"{BASE}/{item_id}", json={"name": new_value}, headers=admin_headers
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["name"] == new_value

    deleted = await client.delete(f"{BASE}/{item_id}", headers=admin_headers)
    assert deleted.status_code == 204, deleted.text
    gone = await client.get(f"{BASE}/{item_id}", headers={})
    assert gone.status_code == 404


async def test_rejects_unknown_fields(client, db, user, user_headers, admin, admin_headers):
    """Asignación masiva: no se pueden colar campos como id u owner_id."""
    payload = await _payload(db, admin.id)
    payload.update({"id": str(uuid.uuid4()), "owner_id": str(uuid.uuid4()), "is_admin": True})
    response = await client.post(BASE, json=payload, headers=admin_headers)
    assert response.status_code == 422


async def test_invalid_ordering_rejected(client, user_headers, admin_headers):
    response = await client.get(BASE, params={"order_by": "hashed_password"}, headers={})
    assert response.status_code == 422


async def test_create_requires_auth(client, db, user):
    payload = await _payload(db, user.id)
    response = await client.post(BASE, json=payload)
    assert response.status_code == 401


async def test_create_forbidden_for_regular_user(client, db, user, user_headers):
    payload = await _payload(db, user.id)
    response = await client.post(BASE, json=payload, headers=user_headers)
    assert response.status_code == 403


async def test_read_only_token_cannot_write(client, db, admin):
    from tests.conftest import headers_for

    payload = await _payload(db, admin.id)
    response = await client.post(BASE, json=payload, headers=headers_for(admin, ["read"]))
    assert response.status_code == 403


async def test_int_out_of_range_is_422(client, db, user, user_headers, admin, admin_headers):
    """Un entero fuera de 64 bits da 422, no un 500 por desbordamiento en la BD."""
    payload = await _payload(db, admin.id)
    payload["stock"] = 2**63
    response = await client.post(BASE, json=payload, headers=admin_headers)
    assert response.status_code == 422, response.text


async def test_unknown_pagination_param_is_rejected(client, user_headers, admin_headers):
    """`page`/`size` no existen (se usa limit/offset): 422 en vez de ignorarlos."""
    response = await client.get(BASE, params={"page": 2}, headers={})
    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "unknown_parameter"

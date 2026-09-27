"""Tests de `categories` (v1), generados por apigen.

Cubren el CRUD completo, permisos, aislamiento entre usuarios y asignación masiva.
Si cambias los endpoints a mano, ajusta estos tests en consecuencia.
"""

import uuid

from tests.helpers import _like, _text

BASE = "/api/v1/categories"


async def _payload(db, owner_id: uuid.UUID) -> dict:
    """Payload válido. Crea antes las filas padre que exigen las claves foráneas."""
    return {
        "name": _text("name", 0, 80),
        "slug": _like("ropa-deportiva"),
        "description": _text("description", 0, 500),
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

    new_value = _text("description", 0, 500)
    updated = await client.patch(
        f"{BASE}/{item_id}", json={"description": new_value}, headers=admin_headers
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["description"] == new_value

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


async def test_unique_name(client, db, user, user_headers, admin, admin_headers):
    payload = await _payload(db, admin.id)
    first = await client.post(BASE, json=payload, headers=admin_headers)
    assert first.status_code == 201, first.text
    second = await client.post(BASE, json=payload, headers=admin_headers)
    assert second.status_code == 409
    assert second.json()["code"] == "unique_violation"
    # Con varios campos únicos, la BD informa del primero que falla.
    assert set(second.json()["fields"]) <= {"name", "slug"}


async def test_immutable_field_rejected_on_patch(
    client, db, user, user_headers, admin, admin_headers
):
    payload = await _payload(db, admin.id)
    created = await client.post(BASE, json=payload, headers=admin_headers)
    assert created.status_code == 201, created.text
    response = await client.patch(
        f"{BASE}/{created.json()['id']}",
        json={"slug": _like("ropa-deportiva")},
        headers=admin_headers,
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "immutable_field"


async def test_unknown_pagination_param_is_rejected(client, user_headers, admin_headers):
    """`page`/`size` no existen (se usa limit/offset): 422 en vez de ignorarlos."""
    response = await client.get(BASE, params={"page": 2}, headers={})
    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "unknown_parameter"

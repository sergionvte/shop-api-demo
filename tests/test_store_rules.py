"""Reglas de negocio de la tienda (app/hooks/order.py y app/tasks/resources/order.py)."""

from decimal import Decimal

from app.models.product import Product
from app.tasks.worker import process_pending

ORDERS = "/api/v1/orders"


async def _product(db, stock=5, price="19.99"):
    product = Product(name="Camiseta", price=Decimal(price), stock=stock)
    db.add(product)
    await db.commit()
    await db.refresh(product)
    return product


async def _order(client, headers, product, quantity=2, **extra):
    body = {"product_id": str(product.id), "quantity": quantity, "shipping_address": "Calle 1"}
    return await client.post(ORDERS, json={**body, **extra}, headers=headers)


async def test_server_computes_total_and_status_and_decrements_stock(client, db, user_headers):
    product = await _product(db)
    r = await _order(client, user_headers, product, total="0.01", status="shipped")
    assert r.status_code == 201, r.text
    assert r.json()["total"] == "39.98" and r.json()["status"] == "pending"
    await db.refresh(product)
    assert product.stock == 3


async def test_insufficient_stock_is_409(client, db, user_headers):
    product = await _product(db, stock=1)
    r = await _order(client, user_headers, product, quantity=2)
    assert r.status_code == 409 and r.json()["code"] == "insufficient_stock"


async def test_customer_cannot_mark_paid_but_can_cancel_and_restock(client, db, user_headers):
    product = await _product(db, stock=5)
    order = (await _order(client, user_headers, product, quantity=3)).json()
    url = f"{ORDERS}/{order['id']}"
    r = await client.patch(url, json={"status": "paid"}, headers=user_headers)
    assert r.status_code == 403
    r = await client.patch(url, json={"status": "cancelled"}, headers=user_headers)
    assert r.status_code == 200 and r.json()["status"] == "cancelled"
    await db.refresh(product)
    assert product.stock == 5


async def test_admin_moves_status_and_paid_orders_cannot_be_deleted(
    client, db, user_headers, admin_headers
):
    product = await _product(db)
    order = (await _order(client, user_headers, product)).json()
    url = f"{ORDERS}/{order['id']}"
    r = await client.patch(url, json={"status": "paid"}, headers=admin_headers)
    assert r.status_code == 200 and r.json()["status"] == "paid"
    assert (
        await client.patch(url, json={"shipping_address": "x"}, headers=user_headers)
    ).status_code == 409
    r = await client.delete(url, headers=user_headers)
    assert r.status_code == 409 and r.json()["code"] == "order_not_deletable"


async def test_invoice_job_returns_invoice(client, db, user_headers):
    product = await _product(db)
    order = (await _order(client, user_headers, product)).json()
    job = await client.post(f"{ORDERS}/{order['id']}/invoice", headers=user_headers)
    assert job.status_code == 202, job.text
    await process_pending()
    done = (await client.get(job.json()["status_url"], headers=user_headers)).json()
    assert done["status"] == "succeeded", done
    assert done["result"]["total"] == "39.98" and done["result"]["invoice_number"].startswith(
        "INV-"
    )

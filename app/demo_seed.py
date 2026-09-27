"""Datos de la demo: se cargan al arrancar si la base de datos está vacía.

En Render (plan free) el disco es temporal: cada arranque parte de una base
nueva, así que la demo siempre empieza con este catálogo y un admin.

    python -m app.demo_seed

Variables: DEMO_ADMIN_EMAIL (por defecto admin@example.com) y DEMO_ADMIN_PASSWORD
(obligatoria para crear el admin; si falta, solo se carga el catálogo).
"""

from __future__ import annotations

import asyncio
import logging
import os
from decimal import Decimal

from sqlmodel import func, select

from app.core.permissions import Role
from app.core.security import hash_password
from app.db.session import SessionFactory, engine
from app.db.types import utcnow
from app.models.category import Category
from app.models.product import Product
from app.models.user import User

logger = logging.getLogger("app.demo_seed")

CATALOG = {
    ("Ropa", "ropa"): [
        ("Camiseta básica de algodón", "19.90", 120),
        ("Sudadera con capucha", "39.90", 60),
        ("Chaqueta impermeable", "74.50", 25),
    ],
    ("Calzado", "calzado"): [
        ("Zapatillas running", "89.00", 40),
        ("Botas de montaña", "119.00", 15),
    ],
    ("Accesorios", "accesorios"): [
        ("Mochila urbana 20 L", "45.00", 50),
        ("Gorra deportiva", "14.90", 80),
        ("Botella térmica 750 ml", "24.90", 70),
    ],
    ("Electrónica", "electronica"): [
        ("Auriculares inalámbricos", "59.90", 35),
        ("Reloj deportivo con GPS", "149.00", 10),
        ("Batería externa 10.000 mAh", "29.90", 3),  # poco stock: prueba el 409
    ],
}


async def seed() -> None:
    async with SessionFactory() as session:
        if (await session.exec(select(func.count()).select_from(Category))).one() == 0:
            for (name, slug), products in CATALOG.items():
                description = f"Productos de {name.lower()}"
                category = Category(name=name, slug=slug, description=description)
                session.add(category)
                await session.flush()
                for title, price, stock in products:
                    session.add(
                        Product(
                            name=title,
                            price=Decimal(price),
                            stock=stock,
                            category_id=category.id,
                            description=f"{title}. Producto de ejemplo de la demo.",
                        )
                    )
            logger.info("demo: catálogo cargado")

        email = os.environ.get("DEMO_ADMIN_EMAIL", "admin@example.com").strip().lower()
        password = os.environ.get("DEMO_ADMIN_PASSWORD", "")
        exists = (await session.exec(select(User.id).where(User.email == email))).first()
        if password and not exists:
            session.add(
                User(
                    email=email,
                    hashed_password=await hash_password(password),
                    full_name="Admin demo",
                    role=Role.admin,
                    email_verified_at=utcnow(),
                )
            )
            logger.info("demo: admin creado")
        elif not password:
            logger.warning("demo: DEMO_ADMIN_PASSWORD vacía, no se crea el admin")
        await session.commit()
    await engine.dispose()


if __name__ == "__main__":
    from app.core.logging import setup_logging

    setup_logging()
    asyncio.run(seed())

"""Router de la versión v1. `apigen` registra aquí los recursos nuevos."""

from fastapi import APIRouter

from app.api.v1.endpoints import account, auth, jobs, users

from app.api.v1.endpoints import categories
from app.api.v1.endpoints import products
from app.api.v1.endpoints import orders
# [apigen:imports]

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(account.router)
api_router.include_router(users.router)
api_router.include_router(jobs.router)
api_router.include_router(categories.router)
api_router.include_router(products.router)
api_router.include_router(orders.router)
# [apigen:routers]

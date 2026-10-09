from fastapi import APIRouter, Depends
from app.routes.signup import router as signup_router
from app.routes.login import router as login_router
from app.routes.account import router as account_router
from app.routes.connections import router as connections_router
from app.routes.servers import router as servers_router
from app.utils.db import get_db

api_router = APIRouter(
	prefix="/api",
	tags=["api"],
	dependencies=[Depends(get_db)],
)


# Include sub-routers
api_router.include_router(signup_router)
api_router.include_router(login_router)
api_router.include_router(account_router)
api_router.include_router(connections_router)
api_router.include_router(servers_router)



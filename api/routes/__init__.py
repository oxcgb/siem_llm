from .auth import auth_router
from .data import data_router
from .incidents import incident_router
from .system import system_router, public_router
from .telegram import telegram_router
from .audit import audit_router

__all__ = [
    "auth_router",
    "data_router",
    "incident_router",
    "system_router",
    "public_router",
    "telegram_router",
    "audit_router"
]

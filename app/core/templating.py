"""
Instance Jinja2Templates partagée, avec variables globales injectées dans
tous les templates (nom de l'application, etc.).
"""
from __future__ import annotations

from fastapi.templating import Jinja2Templates

from app.core.config import settings
from app.core.csrf import csrf_input, ensure_csrf_token
from app.db.database import SessionLocal
from app.models.user import Utilisateur
from app.services.notification_service import count_unread_notifications


def unread_notification_count(current_user: Utilisateur | None) -> int:
    if current_user is None:
        return 0
    with SessionLocal() as db:
        return count_unread_notifications(db, current_user)

templates = Jinja2Templates(directory="app/templates")
templates.env.globals["app_name"] = settings.APP_NAME
templates.env.globals["app_subtitle"] = settings.APP_SUBTITLE
templates.env.globals["csrf_input"] = csrf_input
templates.env.globals["csrf_token"] = ensure_csrf_token
templates.env.globals["unread_notification_count"] = unread_notification_count

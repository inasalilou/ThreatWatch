"""
Instance Jinja2Templates partagée, avec variables globales injectées dans
tous les templates (nom de l'application, etc.).
"""
from __future__ import annotations

from fastapi.templating import Jinja2Templates

from app.core.config import settings

templates = Jinja2Templates(directory="app/templates")
templates.env.globals["app_name"] = settings.APP_NAME
templates.env.globals["app_subtitle"] = settings.APP_SUBTITLE

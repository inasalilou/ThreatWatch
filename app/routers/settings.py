"""
Routes des parametres administratifs non sensibles.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.deps import require_admin_user
from app.core.templating import templates
from app.db.database import get_db
from app.models.app_setting import AppSettingValueType
from app.models.user import Utilisateur
from app.services.settings_service import (
    SAFE_SETTING_DEFINITIONS,
    SettingsValidationError,
    get_sensitive_configuration_status,
    grouped_settings,
    initialize_default_settings,
    list_settings,
    set_setting,
)

router = APIRouter(tags=["settings"])


@router.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    initialize_default_settings(db)
    db.commit()
    return render_settings_page(request=request, current_user=current_user, db=db)


@router.post("/settings", response_class=HTMLResponse)
async def settings_submit(
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    form = await request.form()
    try:
        for definition in SAFE_SETTING_DEFINITIONS:
            if definition.value_type == AppSettingValueType.BOOLEAN:
                raw_value = "true" if form.get(definition.key) == "on" else "false"
            else:
                raw_value = str(form.get(definition.key, ""))
            set_setting(db, definition.key, raw_value)
        db.commit()
        return render_settings_page(
            request=request,
            current_user=current_user,
            db=db,
            success="Parametres enregistres.",
        )
    except (SettingsValidationError, SQLAlchemyError) as exc:
        db.rollback()
        return render_settings_page(
            request=request,
            current_user=current_user,
            db=db,
            error=user_facing_error(exc),
            status_code=400,
        )


def render_settings_page(
    *,
    request: Request,
    current_user: Utilisateur,
    db: Session,
    success: str | None = None,
    error: str | None = None,
    status_code: int = 200,
):
    setting_views = list_settings(db)
    return templates.TemplateResponse(
        request,
        "settings/index.html",
        {
            "current_user": current_user,
            "active_page": "settings",
            "grouped_settings": grouped_settings(setting_views),
            "sensitive_status": get_sensitive_configuration_status(),
            "value_type_boolean": AppSettingValueType.BOOLEAN,
            "value_type_integer": AppSettingValueType.INTEGER,
            "value_type_float": AppSettingValueType.FLOAT,
            "success": success,
            "error": error,
        },
        status_code=status_code,
    )


def user_facing_error(exc: Exception) -> str:
    if isinstance(exc, SettingsValidationError):
        return str(exc)
    return "Impossible d'enregistrer les parametres."

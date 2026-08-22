"""Routes de la page Tableau de bord SOC."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.core.deps import require_authenticated_user
from app.core.templating import templates
from app.db.database import get_db
from app.models.user import Utilisateur
from app.services.dashboard_service import (
    action_type_label,
    alert_priority_tone,
    alert_status_label,
    alert_status_tone,
    criticality_tone,
    format_datetime,
    get_dashboard_data,
    notification_severity_tone,
    severity_tone,
    sync_status_tone,
)

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(
    request: Request,
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    return templates.TemplateResponse(
        request,
        "dashboard/index.html",
        {
            "current_user": current_user,
            "active_page": "dashboard",
            "dashboard": get_dashboard_data(db, current_user),
            "alert_priority_tone": alert_priority_tone,
            "alert_status_label": alert_status_label,
            "alert_status_tone": alert_status_tone,
            "action_type_label": action_type_label,
            "notification_severity_tone": notification_severity_tone,
            "criticality_tone": criticality_tone,
            "sync_status_tone": sync_status_tone,
            "severity_tone": severity_tone,
            "format_datetime": format_datetime,
        },
    )

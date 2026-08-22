"""
Routes de consultation des traitements analyste.
"""
from __future__ import annotations

from datetime import date
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.core.deps import require_authenticated_user
from app.core.templating import templates
from app.db.database import get_db
from app.models.user import Utilisateur
from app.services.alert_service import alert_status_label, alert_status_tone
from app.services.analyst_treatment_service import action_type_label
from app.services.treatment_query_service import (
    get_treatment_action_options,
    get_treatment_alert_status_options,
    get_treatment_analyst_options,
    get_treatment_role_options,
    get_treatment_stats,
    list_treatments,
)

router = APIRouter(tags=["treatments"])


@router.get("/treatments", response_class=HTMLResponse)
def treatments_page(
    request: Request,
    analyst_id: str = Query("", max_length=36),
    role: str = Query("", max_length=20),
    action_type: str = Query("", max_length=30),
    new_status: str = Query("", max_length=30),
    date_from: date | None = Query(None),
    date_to: date | None = Query(None),
    q: str = Query("", max_length=120),
    page: int = Query(1, ge=1),
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    result = list_treatments(
        db=db,
        analyst_id=analyst_id,
        role=role,
        action_type=action_type,
        new_status=new_status,
        date_from=date_from,
        date_to=date_to,
        search=q,
        page=page,
    )

    return templates.TemplateResponse(
        request,
        "treatments/index.html",
        {
            "current_user": current_user,
            "active_page": "treatments",
            "result": result,
            "stats": get_treatment_stats(db),
            "analyst_options": get_treatment_analyst_options(db),
            "role_options": get_treatment_role_options(),
            "action_options": get_treatment_action_options(),
            "status_options": get_treatment_alert_status_options(),
            "pagination_query": treatment_query_string(result),
            "action_type_label": action_type_label,
            "alert_status_label": alert_status_label,
            "alert_status_tone": alert_status_tone,
        },
    )


def treatment_query_string(result) -> str:
    return urlencode(
        {
            "analyst_id": result.analyst_id,
            "role": result.role,
            "action_type": result.action_type,
            "new_status": result.new_status,
            "date_from": result.date_from.isoformat() if result.date_from else "",
            "date_to": result.date_to.isoformat() if result.date_to else "",
            "q": result.search,
        }
    )

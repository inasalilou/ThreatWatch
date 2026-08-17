"""
Routes de consultation des bulletins de securite.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.core.deps import require_authenticated_user
from app.core.templating import templates
from app.db.database import get_db
from app.models.user import Utilisateur
from app.services.bulletin_service import (
    get_available_severities,
    get_bulletin_by_id,
    get_bulletin_stats,
    list_bulletins,
    severity_tone,
)

router = APIRouter(tags=["bulletins"])


@router.get("/bulletins", response_class=HTMLResponse)
def bulletins_page(
    request: Request,
    q: str = Query("", max_length=120),
    severity: str = Query("", max_length=80),
    page: int = Query(1, ge=1),
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    result = list_bulletins(db=db, query=q, severity=severity, page=page)
    stats = get_bulletin_stats(db)
    severities = get_available_severities(db)

    return templates.TemplateResponse(
        request,
        "bulletins/index.html",
        {
            "current_user": current_user,
            "active_page": "bulletins",
            "result": result,
            "stats": stats,
            "severities": severities,
            "severity_tone": severity_tone,
        },
    )


@router.get("/bulletins/{bulletin_id}", response_class=HTMLResponse)
def bulletin_detail_page(
    bulletin_id: str,
    request: Request,
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    bulletin = get_bulletin_by_id(db, bulletin_id)
    if bulletin is None:
        return templates.TemplateResponse(
            request,
            "bulletins/not_found.html",
            {
                "current_user": current_user,
                "active_page": "bulletins",
                "bulletin_id": bulletin_id,
            },
            status_code=404,
        )

    return templates.TemplateResponse(
        request,
        "bulletins/detail.html",
        {
            "current_user": current_user,
            "active_page": "bulletins",
            "bulletin": bulletin,
            "severity_tone": severity_tone,
        },
    )

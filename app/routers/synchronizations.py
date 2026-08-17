"""
Routes de consultation et de lancement des synchronisations.
"""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.core.deps import require_admin_user, require_authenticated_user
from app.core.templating import templates
from app.db.database import get_db
from app.models.user import Utilisateur
from app.services.scheduler_service import get_scheduler_state
from app.services.sync_history_service import (
    format_duration,
    get_sync_overview,
    list_sync_history,
    status_tone,
)
from app.services.synchronization_service import sync_dgssi_bulletins

router = APIRouter(tags=["synchronizations"])


@router.get("/synchronizations", response_class=HTMLResponse)
def synchronizations_page(
    request: Request,
    page: int = Query(1, ge=1),
    sync_status: str = Query("", max_length=20),
    created: int | None = Query(None, ge=0),
    known: int | None = Query(None, ge=0),
    cves: int | None = Query(None, ge=0),
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    result = list_sync_history(db=db, page=page)
    overview = get_sync_overview(db)

    return templates.TemplateResponse(
        request,
        "synchronizations/index.html",
        {
            "current_user": current_user,
            "active_page": "synchronizations",
            "result": result,
            "overview": overview,
            "scheduler": get_scheduler_state(),
            "status_tone": status_tone,
            "format_duration": format_duration,
            "manual_sync_feedback": {
                "status": sync_status,
                "created": created,
                "known": known,
                "cves": cves,
            }
            if sync_status
            else None,
        },
    )


@router.post("/synchronizations/run")
def run_synchronization(
    _current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    result = sync_dgssi_bulletins(db=db)
    query = urlencode(
        {
            "sync_status": result.status.value,
            "created": result.items_created,
            "known": result.items_known,
            "cves": result.cves_created,
        }
    )
    return RedirectResponse(url=f"/synchronizations?{query}", status_code=303)

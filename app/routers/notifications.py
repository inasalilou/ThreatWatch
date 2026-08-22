"""
Routes de consultation des notifications IN_APP.
"""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.deps import require_authenticated_user
from app.core.templating import templates
from app.db.database import get_db
from app.models.user import Utilisateur
from app.services.notification_service import (
    count_unread_notifications,
    get_notification_read_options,
    get_notification_severity_options,
    get_notification_stats,
    get_notification_type_options,
    list_notifications,
    mark_all_notifications_as_read,
    mark_notification_as_read,
    notification_read_label,
    notification_read_tone,
    notification_severity_tone,
    notification_status_label,
    notification_type_label,
)

router = APIRouter(tags=["notifications"])


@router.get("/notifications", response_class=HTMLResponse)
def notifications_page(
    request: Request,
    q: str = Query("", max_length=120),
    read: str = Query("all", max_length=20),
    severity: str = Query("", max_length=20),
    notification_type: str = Query("", max_length=40),
    page: int = Query(1, ge=1),
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    result = list_notifications(
        db=db,
        visible_to_user_id=current_user.id,
        search=q,
        read_filter=read,
        severity=severity,
        notification_type=notification_type,
        page=page,
    )

    return templates.TemplateResponse(
        request,
        "notifications/index.html",
        {
            "current_user": current_user,
            "active_page": "notifications",
            "result": result,
            "stats": get_notification_stats(db, current_user),
            "notification_unread_count": count_unread_notifications(db, current_user),
            "pagination_query": notification_query_string(result),
            "read_options": get_notification_read_options(),
            "severity_options": get_notification_severity_options(),
            "type_options": get_notification_type_options(),
            "notification_type_label": notification_type_label,
            "notification_status_label": notification_status_label,
            "notification_read_label": notification_read_label,
            "notification_read_tone": notification_read_tone,
            "notification_severity_tone": notification_severity_tone,
        },
    )


@router.post("/notifications/{notification_id}/read")
def mark_notification_read_submit(
    notification_id: str,
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    try:
        mark_notification_as_read(db, notification_id, current_user)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
    return RedirectResponse(url="/notifications", status_code=303)


@router.post("/notifications/read-all")
def mark_all_notifications_read_submit(
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    try:
        mark_all_notifications_as_read(db, current_user)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
    return RedirectResponse(url="/notifications", status_code=303)


def notification_query_string(result) -> str:
    return urlencode(
        {
            "q": result.search,
            "read": result.read_filter,
            "severity": result.severity,
            "notification_type": result.notification_type,
        }
    )

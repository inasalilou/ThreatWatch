"""
Routes web de consultation et workflow de base des alertes SOC.
"""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.deps import require_authenticated_user
from app.core.templating import templates
from app.db.database import get_db
from app.models.user import Utilisateur
from app.services.alert_service import (
    alert_activity_label,
    alert_activity_tone,
    alert_priority_tone,
    alert_status_label,
    alert_status_tone,
    get_alert_activity_options,
    get_alert_detail,
    get_alert_priority_options,
    get_alert_severity_options,
    get_alert_stats,
    get_alert_status_options,
    list_alerts,
)
from app.services.analyst_treatment_service import (
    AlertTreatmentError,
    action_type_label,
    add_alert_comment,
    close_alert_treatment,
    get_alert_treatment_history,
    resolve_alert_treatment,
    start_alert_treatment,
)
from app.services.asset_service import (
    asset_type_label,
    criticality_label,
    criticality_tone,
    environment_label,
    environment_tone,
)
from app.services.correlation_query_service import (
    correlation_status_label,
    correlation_status_tone,
)
from app.services.vulnerability_service import cvss_tone

router = APIRouter(tags=["alerts"])


@router.get("/alerts", response_class=HTMLResponse)
def alerts_page(
    request: Request,
    q: str = Query("", max_length=120),
    status: str = Query("", max_length=30),
    priority: str = Query("", max_length=20),
    severity: str = Query("", max_length=20),
    activity: str = Query("active", max_length=20),
    error: str = Query("", max_length=180),
    page: int = Query(1, ge=1),
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    result = list_alerts(
        db=db,
        search=q,
        status=status,
        priority=priority,
        severity=severity,
        is_active=activity,
        page=page,
    )

    return templates.TemplateResponse(
        request,
        "alerts/index.html",
        base_context(
            current_user,
            result=result,
            stats=get_alert_stats(db),
            pagination_query=alert_query_string(result),
            status_options=get_alert_status_options(),
            priority_options=get_alert_priority_options(),
            severity_options=get_alert_severity_options(),
            activity_options=get_alert_activity_options(),
            error=error,
        ),
    )


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail_page(
    alert_id: str,
    request: Request,
    message: str = Query("", max_length=120),
    error: str = Query("", max_length=180),
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    detail = get_alert_detail(db, alert_id)
    return templates.TemplateResponse(
        request,
        "alerts/detail.html",
        base_context(
            current_user,
            detail=detail,
            alert_id=alert_id,
            message=message,
            error=error,
            treatments=get_alert_treatment_history(db, alert_id)
            if detail is not None
            else [],
        ),
        status_code=200 if detail is not None else 404,
    )


@router.post("/alerts/{alert_id}/start")
def start_alert_submit(
    alert_id: str,
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    return change_alert_status(
        db=db,
        alert_id=alert_id,
        action=lambda: start_alert_treatment(db, alert_id, current_user),
        success_message="Alerte prise en charge.",
    )


@router.post("/alerts/{alert_id}/resolve")
def resolve_alert_submit(
    alert_id: str,
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    return change_alert_status(
        db=db,
        alert_id=alert_id,
        action=lambda: resolve_alert_treatment(db, alert_id, current_user),
        success_message="Alerte resolue.",
    )


@router.post("/alerts/{alert_id}/close")
def close_alert_submit(
    alert_id: str,
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    return change_alert_status(
        db=db,
        alert_id=alert_id,
        action=lambda: close_alert_treatment(db, alert_id, current_user),
        success_message="Alerte cloturee et retiree de la file active.",
    )


@router.post("/alerts/{alert_id}/comments")
def add_alert_comment_submit(
    alert_id: str,
    comment: str = Form(""),
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    try:
        treatment = add_alert_comment(db, alert_id, current_user, comment)
        if treatment is None:
            db.rollback()
            return RedirectResponse(
                url="/alerts?" + urlencode({"error": "Alerte introuvable"}),
                status_code=303,
            )
        db.commit()
        return RedirectResponse(
            url=f"/alerts/{alert_id}?"
            + urlencode({"message": "Observation ajoutee."}),
            status_code=303,
        )
    except AlertTreatmentError as exc:
        db.rollback()
        return RedirectResponse(
            url=f"/alerts/{alert_id}?" + urlencode({"error": str(exc)}),
            status_code=303,
        )
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=f"/alerts/{alert_id}?"
            + urlencode({"error": "Impossible d'ajouter cette observation."}),
            status_code=303,
        )


def change_alert_status(
    *,
    db: Session,
    alert_id: str,
    action,
    success_message: str,
) -> RedirectResponse:
    try:
        alert = action()
        if alert is None:
            db.rollback()
            return RedirectResponse(
                url="/alerts?" + urlencode({"error": "Alerte introuvable"}),
                status_code=303,
            )
        db.commit()
        return RedirectResponse(
            url=f"/alerts/{alert.id}?" + urlencode({"message": success_message}),
            status_code=303,
        )
    except AlertTreatmentError as exc:
        db.rollback()
        return RedirectResponse(
            url=f"/alerts/{alert_id}?" + urlencode({"error": str(exc)}),
            status_code=303,
        )
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(
            url=f"/alerts/{alert_id}?"
            + urlencode({"error": "Impossible de mettre a jour cette alerte."}),
            status_code=303,
        )


def base_context(current_user: Utilisateur, **extra):
    context = {
        "current_user": current_user,
        "active_page": "alerts",
        "alert_status_label": alert_status_label,
        "alert_status_tone": alert_status_tone,
        "alert_priority_tone": alert_priority_tone,
        "alert_activity_label": alert_activity_label,
        "alert_activity_tone": alert_activity_tone,
        "cvss_tone": cvss_tone,
        "asset_type_label": asset_type_label,
        "criticality_label": criticality_label,
        "criticality_tone": criticality_tone,
        "environment_label": environment_label,
        "environment_tone": environment_tone,
        "correlation_status_label": correlation_status_label,
        "correlation_status_tone": correlation_status_tone,
        "action_type_label": action_type_label,
    }
    context.update(extra)
    return context


def alert_query_string(result) -> str:
    return urlencode(
        {
            "q": result.search,
            "status": result.status,
            "priority": result.priority,
            "severity": result.severity,
            "activity": result.is_active,
        }
    )

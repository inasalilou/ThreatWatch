"""
Routes de consultation globale des correlations Asset <-> Vulnerability.
"""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.core.deps import require_authenticated_user
from app.core.templating import templates
from app.db.database import get_db
from app.models.user import Utilisateur
from app.services.asset_service import (
    criticality_label,
    criticality_tone,
    environment_label,
    environment_tone,
    get_criticality_options,
    get_environment_options,
)
from app.services.correlation_query_service import (
    correlation_activity_label,
    correlation_activity_tone,
    correlation_status_label,
    correlation_status_tone,
    get_activity_options,
    get_correlation_stats,
    get_correlation_status_options,
    get_cvss_severity_options,
    list_correlations,
)
from app.services.vulnerability_service import cvss_tone

router = APIRouter(tags=["correlations"])


@router.get("/correlations", response_class=HTMLResponse)
def correlations_page(
    request: Request,
    q: str = Query("", max_length=120),
    status: str = Query("", max_length=30),
    activity: str = Query("active", max_length=20),
    criticality: str = Query("", max_length=20),
    environment: str = Query("", max_length=30),
    cvss_severity: str = Query("", max_length=20),
    page: int = Query(1, ge=1),
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    result = list_correlations(
        db=db,
        query=q,
        status=status,
        activity=activity,
        criticality=criticality,
        environment=environment,
        cvss_severity=cvss_severity,
        page=page,
    )

    return templates.TemplateResponse(
        request,
        "correlations/index.html",
        {
            "current_user": current_user,
            "active_page": "correlations",
            "result": result,
            "stats": get_correlation_stats(db),
            "pagination_query": correlation_query_string(result),
            "status_options": get_correlation_status_options(),
            "activity_options": get_activity_options(),
            "criticalities": get_criticality_options(),
            "environments": get_environment_options(),
            "cvss_severities": get_cvss_severity_options(),
            "criticality_label": criticality_label,
            "criticality_tone": criticality_tone,
            "environment_label": environment_label,
            "environment_tone": environment_tone,
            "cvss_tone": cvss_tone,
            "correlation_activity_label": correlation_activity_label,
            "correlation_activity_tone": correlation_activity_tone,
            "correlation_status_label": correlation_status_label,
            "correlation_status_tone": correlation_status_tone,
        },
    )


def correlation_query_string(result) -> str:
    return urlencode(
        {
            "q": result.query,
            "status": result.status,
            "activity": result.activity,
            "criticality": result.criticality,
            "environment": result.environment,
            "cvss_severity": result.cvss_severity,
        }
    )

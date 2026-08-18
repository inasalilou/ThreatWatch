"""
Routes de consultation des vulnerabilites CVE.
"""
from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.core.deps import require_authenticated_user
from app.core.templating import templates
from app.db.database import get_db
from app.models.user import Utilisateur
from app.services.bulletin_service import severity_tone
from app.services.vulnerability_service import (
    cvss_tone,
    enrichment_status_label,
    enrichment_status_tone,
    get_cvss_severity_options,
    get_enrichment_status_options,
    get_available_vulnerability_severities,
    get_available_vulnerability_sources,
    get_vulnerability_detail,
    get_vulnerability_stats,
    list_vulnerabilities,
    normalize_cve_id,
)

router = APIRouter(tags=["vulnerabilities"])


@router.get("/vulnerabilities", response_class=HTMLResponse)
def vulnerabilities_page(
    request: Request,
    q: str = Query("", max_length=120),
    severity: str = Query("", max_length=80),
    source: str = Query("", max_length=80),
    enrichment_status: str = Query("", max_length=20),
    cvss_severity: str = Query("", max_length=20),
    date_from: str = Query("", max_length=10),
    date_to: str = Query("", max_length=10),
    page: int = Query(1, ge=1),
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    result = list_vulnerabilities(
        db=db,
        query=q,
        severity=severity,
        source=source,
        enrichment_status=enrichment_status,
        cvss_severity=cvss_severity,
        date_from=parse_date_filter(date_from),
        date_to=parse_date_filter(date_to),
        page=page,
    )
    stats = get_vulnerability_stats(db)
    severities = get_available_vulnerability_severities(db)
    sources = get_available_vulnerability_sources(db)

    return templates.TemplateResponse(
        request,
        "vulnerabilities/index.html",
        {
            "current_user": current_user,
            "active_page": "vulnerabilities",
            "result": result,
            "stats": stats,
            "severities": severities,
            "sources": sources,
            "enrichment_statuses": get_enrichment_status_options(),
            "cvss_severities": get_cvss_severity_options(),
            "severity_tone": severity_tone,
            "cvss_tone": cvss_tone,
            "enrichment_status_label": enrichment_status_label,
            "enrichment_status_tone": enrichment_status_tone,
        },
    )


def parse_date_filter(value: str) -> date | None:
    cleaned = value.strip()
    if not cleaned:
        return None
    try:
        return date.fromisoformat(cleaned)
    except ValueError:
        return None


@router.get("/vulnerabilities/{cve_id}", response_class=HTMLResponse)
def vulnerability_detail_page(
    cve_id: str,
    request: Request,
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    normalized_cve_id = normalize_cve_id(cve_id)
    vulnerability = get_vulnerability_detail(db, normalized_cve_id)
    if vulnerability is None:
        return templates.TemplateResponse(
            request,
            "vulnerabilities/not_found.html",
            {
                "current_user": current_user,
                "active_page": "vulnerabilities",
                "cve_id": normalized_cve_id or cve_id,
            },
            status_code=404,
        )

    return templates.TemplateResponse(
        request,
        "vulnerabilities/detail.html",
        {
            "current_user": current_user,
            "active_page": "vulnerabilities",
            "vulnerability": vulnerability,
            "severity_tone": severity_tone,
            "cvss_tone": cvss_tone,
            "enrichment_status_label": enrichment_status_label,
            "enrichment_status_tone": enrichment_status_tone,
        },
    )

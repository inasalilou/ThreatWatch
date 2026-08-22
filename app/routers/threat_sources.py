"""
Routes de gestion des sources de veille.
"""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.deps import require_admin_user, require_authenticated_user
from app.core.templating import templates
from app.db.database import get_db
from app.models.user import Utilisateur
from app.services.sync_history_service import format_duration
from app.services.threat_source_service import (
    ThreatSourceValidationError,
    active_label,
    active_tone,
    create_source,
    disable_source,
    enable_source,
    get_latest_sync_for_source,
    get_source_by_id,
    get_source_stats,
    get_source_status_options,
    get_source_sync_options,
    get_source_type_options,
    initialize_default_threat_sources,
    list_recent_syncs_for_source,
    list_sources,
    source_type_label,
    sync_status_tone,
    update_source,
)

router = APIRouter(tags=["sources"])


def source_form_data(
    name: str = Form(""),
    code: str = Form(""),
    source_type: str = Form("WEB"),
    base_url: str = Form(""),
    description: str = Form(""),
    sync_enabled: str | None = Form(None),
    sync_interval_minutes: str = Form("60"),
) -> dict:
    return {
        "name": name,
        "code": code,
        "source_type": source_type,
        "base_url": base_url,
        "description": description,
        "sync_enabled": sync_enabled == "on",
        "sync_interval_minutes": sync_interval_minutes,
    }


@router.get("/sources", response_class=HTMLResponse)
def sources_page(
    request: Request,
    q: str = Query("", max_length=120),
    source_type: str = Query("", max_length=20),
    status: str = Query("", max_length=20),
    sync: str = Query("", max_length=20),
    page: int = Query(1, ge=1),
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    result = list_sources(
        db=db,
        search=q,
        source_type=source_type,
        status=status,
        sync_enabled=sync,
        page=page,
    )
    return templates.TemplateResponse(
        request,
        "sources/index.html",
        base_context(
            current_user,
            result=result,
            stats=get_source_stats(db),
            pagination_query=source_query_string(result),
        ),
    )


@router.get("/sources/new", response_class=HTMLResponse)
def new_source_page(
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
):
    return render_source_form(
        request=request,
        current_user=current_user,
        mode="create",
        form_data=default_source_form_data(),
    )


@router.post("/sources", response_class=HTMLResponse)
def create_source_submit(
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
    form_data: dict = Depends(source_form_data),
):
    try:
        source = create_source(db=db, **form_data)
        db.commit()
        return RedirectResponse(url=f"/sources/{source.id}", status_code=303)
    except (ThreatSourceValidationError, SQLAlchemyError) as exc:
        db.rollback()
        return render_source_form(
            request=request,
            current_user=current_user,
            mode="create",
            form_data=form_data,
            error=user_facing_error(exc),
            status_code=400,
        )


@router.get("/sources/{source_id}", response_class=HTMLResponse)
def source_detail_page(
    source_id: str,
    request: Request,
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    source = get_source_by_id(db, source_id)
    if source is None:
        return source_not_found_response(request, current_user, source_id)

    return templates.TemplateResponse(
        request,
        "sources/detail.html",
        base_context(
            current_user,
            source=source,
            latest_sync=get_latest_sync_for_source(db, source.code),
            recent_syncs=list_recent_syncs_for_source(db, source.code),
            format_duration=format_duration,
        ),
    )


@router.get("/sources/{source_id}/edit", response_class=HTMLResponse)
def edit_source_page(
    source_id: str,
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    source = get_source_by_id(db, source_id)
    if source is None:
        return source_not_found_response(request, current_user, source_id)
    return render_source_form(
        request=request,
        current_user=current_user,
        mode="edit",
        source=source,
        form_data=form_data_from_source(source),
    )


@router.post("/sources/{source_id}/edit", response_class=HTMLResponse)
def edit_source_submit(
    source_id: str,
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
    form_data: dict = Depends(source_form_data),
):
    try:
        source = update_source(db=db, source_id=source_id, **form_data)
        if source is None:
            db.rollback()
            return source_not_found_response(request, current_user, source_id)
        db.commit()
        return RedirectResponse(url=f"/sources/{source.id}", status_code=303)
    except (ThreatSourceValidationError, SQLAlchemyError) as exc:
        db.rollback()
        source = get_source_by_id(db, source_id)
        if source is None:
            return source_not_found_response(request, current_user, source_id)
        return render_source_form(
            request=request,
            current_user=current_user,
            mode="edit",
            source=source,
            form_data=form_data,
            error=user_facing_error(exc),
            status_code=400,
        )


@router.post("/sources/{source_id}/disable")
def disable_source_submit(
    source_id: str,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    try:
        source = disable_source(db=db, source_id=source_id)
        if source is None:
            db.rollback()
            return RedirectResponse(url="/sources", status_code=303)
        db.commit()
        return RedirectResponse(url=f"/sources/{source.id}", status_code=303)
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url=f"/sources/{source_id}", status_code=303)


@router.post("/sources/{source_id}/enable")
def enable_source_submit(
    source_id: str,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    try:
        source = enable_source(db=db, source_id=source_id)
        if source is None:
            db.rollback()
            return RedirectResponse(url="/sources", status_code=303)
        db.commit()
        return RedirectResponse(url=f"/sources/{source.id}", status_code=303)
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url=f"/sources/{source_id}", status_code=303)


def base_context(current_user: Utilisateur, **extra):
    context = {
        "current_user": current_user,
        "active_page": "sources",
        "source_types": get_source_type_options(),
        "status_options": get_source_status_options(),
        "sync_options": get_source_sync_options(),
        "source_type_label": source_type_label,
        "active_label": active_label,
        "active_tone": active_tone,
        "sync_status_tone": sync_status_tone,
    }
    context.update(extra)
    return context


def render_source_form(
    *,
    request: Request,
    current_user: Utilisateur,
    mode: str,
    form_data: dict,
    source=None,
    error: str | None = None,
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request,
        "sources/form.html",
        base_context(
            current_user,
            mode=mode,
            source=source,
            form_data=form_data,
            error=error,
        ),
        status_code=status_code,
    )


def source_not_found_response(
    request: Request,
    current_user: Utilisateur,
    source_id: str,
):
    return templates.TemplateResponse(
        request,
        "sources/detail.html",
        base_context(current_user, source=None, source_id=source_id, recent_syncs=[]),
        status_code=404,
    )


def default_source_form_data() -> dict:
    return {
        "name": "",
        "code": "",
        "source_type": "WEB",
        "base_url": "",
        "description": "",
        "sync_enabled": True,
        "sync_interval_minutes": "60",
    }


def form_data_from_source(source) -> dict:
    return {
        "name": source.name,
        "code": source.code,
        "source_type": source.source_type.value,
        "base_url": source.base_url,
        "description": source.description or "",
        "sync_enabled": source.sync_enabled,
        "sync_interval_minutes": str(source.sync_interval_minutes),
    }


def user_facing_error(exc: Exception) -> str:
    if isinstance(exc, ThreatSourceValidationError):
        return str(exc)
    return "Impossible d'enregistrer cette source de veille."


def source_query_string(result) -> str:
    return urlencode(
        {
            "q": result.search,
            "source_type": result.source_type,
            "status": result.status,
            "sync": result.sync_enabled,
        }
    )

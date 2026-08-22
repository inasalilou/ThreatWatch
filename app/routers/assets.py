"""
Routes web de gestion de l'inventaire des actifs.
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
from app.models.asset import AssetCriticality, AssetEnvironment
from app.models.user import Utilisateur
from app.services.asset_service import (
    AssetValidationError,
    asset_status_label,
    asset_type_label,
    criticality_label,
    criticality_tone,
    disable_asset,
    enable_asset,
    environment_label,
    environment_tone,
    get_asset_by_id,
    get_asset_stats,
    get_asset_type_options,
    get_criticality_options,
    get_environment_options,
    list_assets,
    create_asset,
    status_tone,
    update_asset,
)
from app.services.correlation_query_service import (
    correlation_activity_label,
    correlation_activity_tone,
    correlation_status_label,
    correlation_status_tone,
    get_correlations_for_asset,
)
from app.services.vulnerability_service import cvss_tone

router = APIRouter(tags=["assets"])


def asset_form_data(
    name: str = Form(""),
    asset_type: str = Form(""),
    hostname: str = Form(""),
    ip_address: str = Form(""),
    vendor: str = Form(""),
    product: str = Form(""),
    product_version: str = Form(""),
    operating_system: str = Form(""),
    os_version: str = Form(""),
    criticality: str = Form(AssetCriticality.MEDIUM.value),
    environment: str = Form(AssetEnvironment.PRODUCTION.value),
    owner: str = Form(""),
    location: str = Form(""),
    cpe: str = Form(""),
    description: str = Form(""),
) -> dict[str, str]:
    return {
        "name": name,
        "asset_type": asset_type,
        "hostname": hostname,
        "ip_address": ip_address,
        "vendor": vendor,
        "product": product,
        "product_version": product_version,
        "operating_system": operating_system,
        "os_version": os_version,
        "criticality": criticality,
        "environment": environment,
        "owner": owner,
        "location": location,
        "cpe": cpe,
        "description": description,
    }


@router.get("/assets", response_class=HTMLResponse)
def assets_page(
    request: Request,
    q: str = Query("", max_length=120),
    asset_type: str = Query("", max_length=40),
    criticality: str = Query("", max_length=20),
    environment: str = Query("", max_length=30),
    status: str = Query("", max_length=20),
    page: int = Query(1, ge=1),
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    filter_error = None
    try:
        result = list_assets(
            db=db,
            search=q,
            asset_type=asset_type,
            criticality=criticality,
            environment=environment,
            is_active=status,
            page=page,
        )
    except AssetValidationError as exc:
        filter_error = str(exc)
        status = ""
        result = list_assets(db=db, page=1)

    return templates.TemplateResponse(
        request,
        "assets/index.html",
        base_context(
            current_user,
            result=result,
            stats=get_asset_stats(db),
            status_filter=status,
            pagination_query=asset_query_string(result, status),
            filter_error=filter_error,
        ),
    )


@router.get("/assets/new", response_class=HTMLResponse)
def new_asset_page(
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
):
    return render_asset_form(
        request=request,
        current_user=current_user,
        mode="create",
        form_data=default_asset_form_data(),
    )


@router.post("/assets", response_class=HTMLResponse)
def create_asset_submit(
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
    form_data: dict[str, str] = Depends(asset_form_data),
):
    try:
        asset = create_asset(db=db, **form_data)
        db.commit()
        return RedirectResponse(url=f"/assets/{asset.id}", status_code=303)
    except (AssetValidationError, SQLAlchemyError) as exc:
        db.rollback()
        return render_asset_form(
            request=request,
            current_user=current_user,
            mode="create",
            form_data=form_data,
            error=user_facing_error(exc),
            status_code=400,
        )


@router.get("/assets/{asset_id}/edit", response_class=HTMLResponse)
def edit_asset_page(
    asset_id: str,
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    asset = get_asset_by_id(db, asset_id)
    if asset is None:
        return asset_not_found_response(request, current_user, asset_id)

    return render_asset_form(
        request=request,
        current_user=current_user,
        mode="edit",
        asset=asset,
        form_data=form_data_from_asset(asset),
    )


@router.post("/assets/{asset_id}/edit", response_class=HTMLResponse)
def edit_asset_submit(
    asset_id: str,
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
    form_data: dict[str, str] = Depends(asset_form_data),
):
    try:
        asset = update_asset(db=db, asset_id=asset_id, **form_data)
        if asset is None:
            db.rollback()
            return asset_not_found_response(request, current_user, asset_id)

        db.commit()
        return RedirectResponse(url=f"/assets/{asset.id}", status_code=303)
    except (AssetValidationError, SQLAlchemyError) as exc:
        db.rollback()
        asset = get_asset_by_id(db, asset_id)
        if asset is None:
            return asset_not_found_response(request, current_user, asset_id)
        return render_asset_form(
            request=request,
            current_user=current_user,
            mode="edit",
            asset=asset,
            form_data=form_data,
            error=user_facing_error(exc),
            status_code=400,
        )


@router.get("/assets/{asset_id}", response_class=HTMLResponse)
def asset_detail_page(
    asset_id: str,
    request: Request,
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    asset = get_asset_by_id(db, asset_id)
    if asset is None:
        return asset_not_found_response(request, current_user, asset_id)

    return templates.TemplateResponse(
        request,
        "assets/detail.html",
        base_context(
            current_user,
            asset=asset,
            correlations=get_correlations_for_asset(db, asset.id),
        ),
    )


@router.post("/assets/{asset_id}/disable")
def disable_asset_submit(
    asset_id: str,
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    try:
        asset = disable_asset(db=db, asset_id=asset_id)
        if asset is None:
            db.rollback()
            return asset_not_found_response(request, current_user, asset_id)

        db.commit()
        return RedirectResponse(url=f"/assets/{asset.id}", status_code=303)
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url=f"/assets/{asset_id}", status_code=303)


@router.post("/assets/{asset_id}/enable")
def enable_asset_submit(
    asset_id: str,
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    try:
        asset = enable_asset(db=db, asset_id=asset_id)
        if asset is None:
            db.rollback()
            return asset_not_found_response(request, current_user, asset_id)

        db.commit()
        return RedirectResponse(url=f"/assets/{asset.id}", status_code=303)
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url=f"/assets/{asset_id}", status_code=303)


def base_context(current_user: Utilisateur, **extra):
    context = {
        "current_user": current_user,
        "active_page": "assets",
        "asset_types": get_asset_type_options(),
        "criticalities": get_criticality_options(),
        "environments": get_environment_options(),
        "asset_type_label": asset_type_label,
        "criticality_label": criticality_label,
        "environment_label": environment_label,
        "asset_status_label": asset_status_label,
        "criticality_tone": criticality_tone,
        "environment_tone": environment_tone,
        "status_tone": status_tone,
        "correlation_activity_label": correlation_activity_label,
        "correlation_activity_tone": correlation_activity_tone,
        "correlation_status_label": correlation_status_label,
        "correlation_status_tone": correlation_status_tone,
        "cvss_tone": cvss_tone,
    }
    context.update(extra)
    return context


def render_asset_form(
    *,
    request: Request,
    current_user: Utilisateur,
    mode: str,
    form_data: dict[str, str],
    asset=None,
    error: str | None = None,
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request,
        "assets/form.html",
        base_context(
            current_user,
            mode=mode,
            asset=asset,
            form_data=form_data,
            error=error,
        ),
        status_code=status_code,
    )


def asset_not_found_response(
    request: Request,
    current_user: Utilisateur,
    asset_id: str,
):
    return templates.TemplateResponse(
        request,
        "assets/not_found.html",
        base_context(current_user, asset_id=asset_id),
        status_code=404,
    )


def default_asset_form_data() -> dict[str, str]:
    return {
        "name": "",
        "asset_type": "SERVER",
        "hostname": "",
        "ip_address": "",
        "vendor": "",
        "product": "",
        "product_version": "",
        "operating_system": "",
        "os_version": "",
        "criticality": AssetCriticality.MEDIUM.value,
        "environment": AssetEnvironment.PRODUCTION.value,
        "owner": "",
        "location": "",
        "cpe": "",
        "description": "",
    }


def form_data_from_asset(asset) -> dict[str, str]:
    return {
        "name": asset.name or "",
        "asset_type": asset.asset_type.value,
        "hostname": asset.hostname or "",
        "ip_address": asset.ip_address or "",
        "vendor": asset.vendor or "",
        "product": asset.product or "",
        "product_version": asset.product_version or "",
        "operating_system": asset.operating_system or "",
        "os_version": asset.os_version or "",
        "criticality": asset.criticality.value,
        "environment": asset.environment.value,
        "owner": asset.owner or "",
        "location": asset.location or "",
        "cpe": asset.cpe or "",
        "description": asset.description or "",
    }


def user_facing_error(exc: Exception) -> str:
    if isinstance(exc, AssetValidationError):
        return str(exc)
    return "Impossible d'enregistrer cet actif. Verifiez les donnees saisies."


def asset_query_string(result, status_filter: str) -> str:
    return urlencode(
        {
            "q": result.search,
            "asset_type": result.asset_type,
            "criticality": result.criticality,
            "environment": result.environment,
            "status": status_filter,
        }
    )

"""
Routes d'administration des utilisateurs.
"""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.deps import require_admin_user
from app.core.templating import templates
from app.db.database import get_db
from app.models.user import Utilisateur
from app.services.user_service import (
    UserValidationError,
    change_password,
    create_user,
    disable_user,
    enable_user,
    get_role_options,
    get_status_options,
    get_user_by_id,
    get_user_stats,
    list_users,
    role_label,
    update_user,
    user_status_label,
    user_status_tone,
)

router = APIRouter(tags=["users"])


def user_form_data(
    nom: str = Form(""),
    email: str = Form(""),
    role: str = Form("ANALYSTE"),
    password: str = Form(""),
    password_confirmation: str = Form(""),
    actif: str | None = Form(None),
) -> dict:
    return {
        "nom": nom,
        "email": email,
        "role": role,
        "password": password,
        "password_confirmation": password_confirmation,
        "actif": actif == "on",
    }


@router.get("/users", response_class=HTMLResponse)
def users_page(
    request: Request,
    q: str = Query("", max_length=120),
    role: str = Query("", max_length=20),
    status: str = Query("", max_length=20),
    page: int = Query(1, ge=1),
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    result = list_users(db, search=q, role=role, status=status, page=page)
    return templates.TemplateResponse(
        request,
        "users/index.html",
        base_context(
            current_user,
            result=result,
            stats=get_user_stats(db),
            pagination_query=user_query_string(result),
        ),
    )


@router.get("/users/new", response_class=HTMLResponse)
def new_user_page(
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
):
    return render_user_form(
        request=request,
        current_user=current_user,
        mode="create",
        form_data=default_user_form_data(),
    )


@router.post("/users", response_class=HTMLResponse)
def create_user_submit(
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
    form_data: dict = Depends(user_form_data),
):
    try:
        user = create_user(db=db, **form_data)
        db.commit()
        return RedirectResponse(url=f"/users/{user.id}", status_code=303)
    except (UserValidationError, SQLAlchemyError) as exc:
        db.rollback()
        return render_user_form(
            request=request,
            current_user=current_user,
            mode="create",
            form_data=safe_form_data(form_data),
            error=user_facing_error(exc),
            status_code=400,
        )


@router.get("/users/{user_id}", response_class=HTMLResponse)
def user_detail_page(
    user_id: str,
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    user = get_user_by_id(db, user_id)
    if user is None:
        return user_not_found_response(request, current_user, user_id)

    return render_user_detail(
        request=request,
        current_user=current_user,
        user=user,
    )


@router.get("/users/{user_id}/edit", response_class=HTMLResponse)
def edit_user_page(
    user_id: str,
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    user = get_user_by_id(db, user_id)
    if user is None:
        return user_not_found_response(request, current_user, user_id)

    return render_user_form(
        request=request,
        current_user=current_user,
        mode="edit",
        user=user,
        form_data=form_data_from_user(user),
    )


@router.post("/users/{user_id}/edit", response_class=HTMLResponse)
def edit_user_submit(
    user_id: str,
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
    form_data: dict = Depends(user_form_data),
):
    try:
        user = update_user(
            db=db,
            user_id=user_id,
            nom=form_data["nom"],
            email=form_data["email"],
            role=form_data["role"],
        )
        if user is None:
            db.rollback()
            return user_not_found_response(request, current_user, user_id)
        db.commit()
        return RedirectResponse(url=f"/users/{user.id}", status_code=303)
    except (UserValidationError, SQLAlchemyError) as exc:
        db.rollback()
        user = get_user_by_id(db, user_id)
        if user is None:
            return user_not_found_response(request, current_user, user_id)
        return render_user_form(
            request=request,
            current_user=current_user,
            mode="edit",
            user=user,
            form_data=safe_form_data(form_data),
            error=user_facing_error(exc),
            status_code=400,
        )


@router.post("/users/{user_id}/disable")
def disable_user_submit(
    user_id: str,
    request: Request,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    if user_id == current_user.id:
        user = get_user_by_id(db, user_id)
        return render_user_detail(
            request=request,
            current_user=current_user,
            user=user,
            error="Vous ne pouvez pas desactiver votre propre compte.",
            status_code=400,
        )

    try:
        user = disable_user(db, user_id)
        if user is None:
            db.rollback()
            return RedirectResponse(url="/users", status_code=303)
        db.commit()
        return RedirectResponse(url=f"/users/{user.id}", status_code=303)
    except (UserValidationError, SQLAlchemyError) as exc:
        db.rollback()
        user = get_user_by_id(db, user_id)
        return render_user_detail(
            request=request,
            current_user=current_user,
            user=user,
            error=user_facing_error(exc),
            status_code=400,
        )


@router.post("/users/{user_id}/enable")
def enable_user_submit(
    user_id: str,
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    try:
        user = enable_user(db, user_id)
        if user is None:
            db.rollback()
            return RedirectResponse(url="/users", status_code=303)
        db.commit()
        return RedirectResponse(url=f"/users/{user.id}", status_code=303)
    except SQLAlchemyError:
        db.rollback()
        return RedirectResponse(url=f"/users/{user_id}", status_code=303)


@router.post("/users/{user_id}/reset-password", response_class=HTMLResponse)
def reset_password_submit(
    user_id: str,
    request: Request,
    password: str = Form(""),
    password_confirmation: str = Form(""),
    current_user: Utilisateur = Depends(require_admin_user),
    db: Session = Depends(get_db),
):
    try:
        user = change_password(
            db,
            user_id=user_id,
            password=password,
            password_confirmation=password_confirmation,
        )
        if user is None:
            db.rollback()
            return user_not_found_response(request, current_user, user_id)
        db.commit()
        return RedirectResponse(url=f"/users/{user.id}", status_code=303)
    except (UserValidationError, SQLAlchemyError) as exc:
        db.rollback()
        user = get_user_by_id(db, user_id)
        if user is None:
            return user_not_found_response(request, current_user, user_id)
        return render_user_detail(
            request=request,
            current_user=current_user,
            user=user,
            reset_error=user_facing_error(exc),
            status_code=400,
        )


def base_context(current_user: Utilisateur, **extra):
    context = {
        "current_user": current_user,
        "active_page": "users",
        "role_options": get_role_options(),
        "status_options": get_status_options(),
        "role_label": role_label,
        "user_status_label": user_status_label,
        "user_status_tone": user_status_tone,
    }
    context.update(extra)
    return context


def render_user_form(
    *,
    request: Request,
    current_user: Utilisateur,
    mode: str,
    form_data: dict,
    user: Utilisateur | None = None,
    error: str | None = None,
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request,
        "users/form.html",
        base_context(
            current_user,
            mode=mode,
            user=user,
            form_data=form_data,
            error=error,
        ),
        status_code=status_code,
    )


def render_user_detail(
    *,
    request: Request,
    current_user: Utilisateur,
    user: Utilisateur | None,
    error: str | None = None,
    reset_error: str | None = None,
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request,
        "users/detail.html",
        base_context(
            current_user,
            user=user,
            error=error,
            reset_error=reset_error,
        ),
        status_code=status_code,
    )


def user_not_found_response(
    request: Request,
    current_user: Utilisateur,
    user_id: str,
):
    return render_user_detail(
        request=request,
        current_user=current_user,
        user=None,
        error=f"Utilisateur introuvable: {user_id}",
        status_code=404,
    )


def default_user_form_data() -> dict:
    return {
        "nom": "",
        "email": "",
        "role": "ANALYSTE",
        "password": "",
        "password_confirmation": "",
        "actif": True,
    }


def form_data_from_user(user: Utilisateur) -> dict:
    return {
        "nom": user.nom,
        "email": user.email,
        "role": user.role.value,
        "password": "",
        "password_confirmation": "",
        "actif": user.actif,
    }


def safe_form_data(form_data: dict) -> dict:
    clean = dict(form_data)
    clean["password"] = ""
    clean["password_confirmation"] = ""
    return clean


def user_facing_error(exc: Exception) -> str:
    if isinstance(exc, UserValidationError):
        return str(exc)
    return "Impossible d'enregistrer cet utilisateur."


def user_query_string(result) -> str:
    return urlencode(
        {
            "q": result.search,
            "role": result.role,
            "status": result.status,
        }
    )

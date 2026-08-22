"""
Routes d'authentification : /login (affichage + soumission) et /logout.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.core.csrf import rotate_csrf_token
from app.core.deps import get_current_user
from app.core.templating import templates
from app.db.database import get_db
from app.services.auth_service import authenticate_user

router = APIRouter(tags=["auth"])


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    next: str = "/dashboard",
    db: Session = Depends(get_db),
):
    # Si déjà connecté, inutile de repasser par le login
    if get_current_user(request, db) is not None:
        return RedirectResponse(url="/dashboard", status_code=303)

    return templates.TemplateResponse(
        request,
        "auth/login.html",
        {"error": None, "next": next, "email": ""},
    )


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    next: str = Form("/dashboard"),
    remember: str | None = Form(None),
    db: Session = Depends(get_db),
):
    # Validation basique des champs obligatoires
    if not email.strip() or not password:
        return templates.TemplateResponse(
            request,
            "auth/login.html",
            {
                "error": "Veuillez renseigner votre e-mail et votre mot de passe.",
                "next": next,
                "email": email,
            },
            status_code=400,
        )

    result = authenticate_user(db, email=email, password=password)

    if not result.success:
        return templates.TemplateResponse(
            request,
            "auth/login.html",
            {"error": result.error, "next": next, "email": email},
            status_code=401,
        )

    # Création de la session sécurisée (cookie signé, cf. SessionMiddleware)
    request.session.clear()
    request.session["user_id"] = result.user.id
    rotate_csrf_token(request)
    # Indicateur 'remember me' (utile pour ajuster la durée de session ultérieurement)
    request.session["remember"] = bool(remember)

    safe_next = next if next.startswith("/") else "/dashboard"
    return RedirectResponse(url=safe_next, status_code=303)


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    response = RedirectResponse(url="/login", status_code=303)
    return response


@router.get("/", include_in_schema=False)
def root(request: Request, db: Session = Depends(get_db)):
    if get_current_user(request, db) is not None:
        return RedirectResponse(url="/dashboard", status_code=303)
    return RedirectResponse(url="/login", status_code=303)

"""
Routes de la page Tableau de bord (seule page fonctionnelle de cette
première version, hors authentification).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.core.deps import require_authenticated_user
from app.core.templating import templates
from app.db.database import get_db
from app.models.user import Utilisateur

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(
    request: Request,
    current_user: Utilisateur = Depends(require_authenticated_user),
    db: Session = Depends(get_db),
):
    # Pour cette première version : pas de données réelles issues de la
    # collecte DGSSI. On affiche des compteurs à zéro et un tableau vide,
    # sans jamais inventer de fausses alertes.
    stats = {
        "alertes_actives": 0,
        "alertes_critiques": 0,
        "vulnerabilites_detectees": 0,
        "actifs_surveilles": 0,
    }
    dernieres_alertes: list = []

    return templates.TemplateResponse(
        request,
        "dashboard/index.html",
        {
            "current_user": current_user,
            "active_page": "dashboard",
            "stats": stats,
            "dernieres_alertes": dernieres_alertes,
        },
    )

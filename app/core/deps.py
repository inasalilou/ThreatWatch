"""
Dépendances FastAPI liées à l'authentification par session.

`get_current_user`      -> renvoie l'utilisateur connecté ou None
`require_authenticated_user` -> protège une route (redirige vers /login si non connecté)
"""
from __future__ import annotations

from fastapi import Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.db.database import get_db
from app.models.user import RoleUtilisateur, Utilisateur


class RedirectToLogin(StarletteHTTPException):
    """Exception dédiée : signale qu'il faut rediriger vers /login."""

    def __init__(self, next_url: str | None = None):
        super().__init__(status_code=303)
        self.next_url = next_url


def get_current_user(
    request: Request, db: Session = Depends(get_db)
) -> Utilisateur | None:
    """Récupère l'utilisateur associé à la session courante, si elle existe."""
    user_id = request.session.get("user_id")
    if not user_id:
        return None

    user = db.get(Utilisateur, user_id)
    # Session invalide si l'utilisateur a été supprimé ou désactivé entre-temps
    if user is None or not user.actif:
        request.session.clear()
        return None

    return user


def require_authenticated_user(
    request: Request, db: Session = Depends(get_db)
) -> Utilisateur:
    """
    Dépendance à utiliser sur toute route protégée.

    Lève une redirection HTTP 303 vers /login (avec ?next=<url d'origine>)
    si l'utilisateur n'est pas authentifié.
    """
    user = get_current_user(request, db)
    if user is None:
        raise RedirectToLogin(next_url=str(request.url.path))
    return user


def require_admin_user(
    current_user: Utilisateur = Depends(require_authenticated_user),
) -> Utilisateur:
    """Autorise uniquement les administrateurs connectes."""
    if current_user.role != RoleUtilisateur.ADMIN:
        raise StarletteHTTPException(status_code=403, detail="Acces admin requis")
    return current_user

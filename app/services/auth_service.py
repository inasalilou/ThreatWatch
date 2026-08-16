"""
Service d'authentification.

Contient la logique métier (vérification des identifiants, mise à jour de
la date de dernière connexion), indépendante du framework web.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from app.core.security import verify_password
from app.models.user import Utilisateur


class AuthResult:
    """Résultat structuré d'une tentative de connexion."""

    def __init__(self, success: bool, user: Utilisateur | None = None, error: str | None = None):
        self.success = success
        self.user = user
        self.error = error


def authenticate_user(db: Session, email: str, password: str) -> AuthResult:
    """
    Vérifie les identifiants d'un utilisateur.

    Retourne un AuthResult avec un message d'erreur générique dans tous les
    cas d'échec (email inconnu, mot de passe incorrect, compte inactif) afin
    de ne pas donner d'indice à un attaquant sur l'existence d'un compte.
    """
    email_normalise = email.strip().lower()
    user = (
        db.query(Utilisateur)
        .filter(Utilisateur.email == email_normalise)
        .first()
    )

    generic_error = "Adresse e-mail ou mot de passe incorrect."

    if user is None:
        return AuthResult(success=False, error=generic_error)

    if not verify_password(password, user.mot_de_passe_hash):
        return AuthResult(success=False, error=generic_error)

    if not user.actif:
        return AuthResult(
            success=False,
            error="Ce compte utilisateur est désactivé.",
        )

    user.derniere_connexion = datetime.utcnow()
    db.add(user)
    db.commit()
    db.refresh(user)

    return AuthResult(success=True, user=user)

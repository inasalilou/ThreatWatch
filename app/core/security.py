"""
Utilitaires liés à la sécurité des mots de passe.

On utilise directement la bibliothèque `bcrypt` (plutôt que passlib, qui a
des soucis de compatibilité avec les versions récentes de bcrypt).
"""
from __future__ import annotations

import bcrypt

# bcrypt tronque silencieusement au-delà de 72 octets : on borne nous-mêmes
# pour éviter les surprises et donner un message clair si dépassement.
_MAX_PASSWORD_BYTES = 72


def hash_password(plain_password: str) -> str:
    """Retourne le hash bcrypt (str) d'un mot de passe en clair."""
    if len(plain_password.encode("utf-8")) > _MAX_PASSWORD_BYTES:
        raise ValueError("Le mot de passe est trop long (72 octets maximum).")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifie qu'un mot de passe en clair correspond au hash stocké."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"), hashed_password.encode("utf-8")
        )
    except (ValueError, TypeError):
        # Hash corrompu ou format inattendu -> on considère l'échec, sans planter
        return False

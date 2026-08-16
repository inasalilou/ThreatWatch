"""
Modèle Utilisateur.

Champs alignés sur le diagramme de classes du projet (id, nom, email, role,
actif), complétés par les champs nécessaires à l'authentification
(mot_de_passe_hash, dates).
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class RoleUtilisateur(str, enum.Enum):
    ADMIN = "ADMIN"
    ANALYSTE = "ANALYSTE"


class Utilisateur(Base):
    __tablename__ = "utilisateurs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    nom: Mapped[str] = mapped_column(String(150), nullable=False)
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    mot_de_passe_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[RoleUtilisateur] = mapped_column(
        Enum(RoleUtilisateur), nullable=False, default=RoleUtilisateur.ANALYSTE
    )
    actif: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    date_creation: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    derniere_connexion: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )

    def __repr__(self) -> str:  # utile en debug
        return f"<Utilisateur {self.email} ({self.role.value})>"

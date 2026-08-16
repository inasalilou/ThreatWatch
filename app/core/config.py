"""
Configuration centrale de l'application.

Les valeurs sensibles, comme l'URL PostgreSQL et la cle de session, sont lues
depuis .env. Le mot de passe PostgreSQL ne doit jamais etre ecrit en dur dans
le code Python.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent

load_dotenv(BASE_DIR / ".env")


class Settings:
    # --- General ---
    APP_NAME: str = "ThreatWatch"
    APP_SUBTITLE: str = "Veille • Détection • Alerte • Réponse"
    ENV: str = os.getenv("ENV", "development")

    # --- Base de donnees ---
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://postgres:MOT_DE_PASSE_POSTGRES@localhost:5432/threatwatch",
    )

    # --- Securite / session ---
    SESSION_SECRET_KEY: str = os.getenv(
        "SESSION_SECRET_KEY", "dev-secret-key-a-changer-en-production"
    )
    SESSION_COOKIE_NAME: str = "soc_session"
    # Duree de vie de la session (en secondes) : 8h
    SESSION_MAX_AGE: int = int(os.getenv("SESSION_MAX_AGE", 8 * 60 * 60))
    # En production (HTTPS), forcer le cookie "secure"
    SESSION_HTTPS_ONLY: bool = os.getenv("SESSION_HTTPS_ONLY", "false").lower() == "true"


settings = Settings()

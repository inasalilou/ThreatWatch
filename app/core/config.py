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

    # --- Collecte DGSSI ---
    DGSSI_SOURCE_URL: str = os.getenv(
        "DGSSI_SOURCE_URL",
        "https://www.dgssi.gov.ma/fr/bulletins-securite",
    )
    DGSSI_HTTP_TIMEOUT: float = float(os.getenv("DGSSI_HTTP_TIMEOUT", "30"))
    DGSSI_USER_AGENT: str = os.getenv(
        "DGSSI_USER_AGENT",
        "ThreatWatch/0.2 (+https://github.com/inasalilou/ThreatWatch)",
    )

    # --- Synchronisation automatique DGSSI ---
    DGSSI_SYNC_ENABLED: bool = os.getenv("DGSSI_SYNC_ENABLED", "false").lower() == "true"
    DGSSI_SYNC_INTERVAL_MINUTES: int = int(
        os.getenv("DGSSI_SYNC_INTERVAL_MINUTES", "60")
    )
    DGSSI_SYNC_ON_STARTUP: bool = (
        os.getenv("DGSSI_SYNC_ON_STARTUP", "false").lower() == "true"
    )

    # --- Enrichissement CVE via NVD API 2.0 ---
    NVD_API_BASE_URL: str = os.getenv(
        "NVD_API_BASE_URL",
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
    )
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    NVD_HTTP_TIMEOUT: float = float(os.getenv("NVD_HTTP_TIMEOUT", "30"))
    NVD_USER_AGENT: str = os.getenv("NVD_USER_AGENT", "ThreatWatch/0.3")
    NVD_REQUEST_DELAY_SECONDS: float = float(
        os.getenv("NVD_REQUEST_DELAY_SECONDS", "6")
    )
    NVD_BATCH_SIZE: int = int(os.getenv("NVD_BATCH_SIZE", "5"))

    # --- Notifications email SMTP ---
    SMTP_ENABLED: bool = os.getenv("SMTP_ENABLED", "false").lower() == "true"
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "")
    SMTP_FROM_NAME: str = os.getenv("SMTP_FROM_NAME", "ThreatWatch")
    SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
    SMTP_TIMEOUT: float = float(os.getenv("SMTP_TIMEOUT", "15"))
    SOC_NOTIFICATION_EMAIL: str = os.getenv("SOC_NOTIFICATION_EMAIL", "")


settings = Settings()

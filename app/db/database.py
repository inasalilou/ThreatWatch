"""
Initialisation de SQLAlchemy : engine, SessionLocal, Base déclarative.
"""
from __future__ import annotations

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings

connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    # nécessaire pour utiliser SQLite avec plusieurs threads (FastAPI/uvicorn)
    connect_args = {"check_same_thread": False}

engine = create_engine(settings.DATABASE_URL, connect_args=connect_args, future=True)

SessionLocal = sessionmaker(
    bind=engine, autoflush=False, autocommit=False, future=True
)


class Base(DeclarativeBase):
    """Classe de base déclarative pour tous les modèles ORM."""
    pass


def get_db():
    """Dependency FastAPI : fournit une session DB et la ferme proprement."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_safe_database_url() -> str:
    """Retourne l'URL de connexion en masquant le mot de passe."""
    return make_url(settings.DATABASE_URL).render_as_string(hide_password=True)


def test_database_connection() -> None:
    """
    Verifie que SQLAlchemy arrive a communiquer avec la base.

    L'exception remontee ne contient pas l'URL complete afin d'eviter
    d'afficher le mot de passe dans le terminal.
    """
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        safe_url = get_safe_database_url()
        raise RuntimeError(
            f"Connexion PostgreSQL impossible avec DATABASE_URL={safe_url}. "
            "Verifiez le mot de passe, le port 5432, le service PostgreSQL "
            "et l'existence de la base threatwatch."
        ) from exc


def create_database_tables() -> None:
    """Cree les tables manquantes sans supprimer les tables existantes."""
    # Import necessaire pour enregistrer les modeles SQLAlchemy dans Base.
    from app.models import alert  # noqa: F401
    from app.models import app_setting  # noqa: F401
    from app.models import user  # noqa: F401
    from app.models import alert_treatment  # noqa: F401
    from app.models import notification  # noqa: F401
    from app.models import threat_source  # noqa: F401
    from app.models import asset, security_bulletin, sync_history, vulnerability  # noqa: F401
    from app.models import asset_vulnerability_correlation  # noqa: F401
    from app.models import vulnerability_affected_product  # noqa: F401

    test_database_connection()
    Base.metadata.create_all(bind=engine)

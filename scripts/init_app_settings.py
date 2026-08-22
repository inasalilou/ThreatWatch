"""
Initialise les parametres applicatifs non sensibles.

Le script est idempotent : il cree les cles manquantes sans ecraser les valeurs
deja modifiees par un administrateur.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.database import SessionLocal, create_database_tables, get_safe_database_url
from app.services.settings_service import initialize_default_settings


def main() -> int:
    print(
        "Initialisation app_settings avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )
    try:
        create_database_tables()
        db = SessionLocal()
        try:
            created = initialize_default_settings(db)
            db.commit()
        finally:
            db.close()
    except Exception as exc:
        print("ERREUR: initialisation app_settings impossible.")
        print(f"Detail technique: {exc.__class__.__name__}")
        return 1

    print(f"Parametres crees: {len(created)}")
    print("Initialisation app_settings: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

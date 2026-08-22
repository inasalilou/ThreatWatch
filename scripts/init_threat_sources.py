"""
Initialise les sources de veille persistantes.

Phase 6.3: cree uniquement DGSSI / maCERT si absente.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy.exc import SQLAlchemyError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, get_safe_database_url, test_database_connection  # noqa: E402
from app.services.threat_source_service import initialize_default_threat_sources  # noqa: E402


def main() -> int:
    print(f"Initialisation sources de veille avec DATABASE_URL={get_safe_database_url()}")
    try:
        test_database_connection()
        with SessionLocal() as db:
            source, created = initialize_default_threat_sources(db)
            db.commit()
            if created:
                print("DGSSI source created")
            else:
                print("DGSSI source already exists")
            print(f"ID={source.id}")
            print(f"Code={source.code}")
            print(f"URL={source.base_url}")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

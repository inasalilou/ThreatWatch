"""
Cree les tables SQLAlchemy manquantes dans la base configuree.

Operation non destructive : aucune table existante n'est supprimee.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.database import create_database_tables, get_safe_database_url


def main() -> int:
    print(f"Creation des tables manquantes avec DATABASE_URL={get_safe_database_url()}")
    try:
        create_database_tables()
    except Exception as exc:
        print(
            "ERREUR: creation des tables impossible. "
            "Verifiez la connexion PostgreSQL et les droits de l'utilisateur postgres."
        )
        print(f"Detail technique: {exc.__class__.__name__}")
        return 1

    print("Tables SQLAlchemy pretes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

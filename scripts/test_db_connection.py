"""
Teste la connexion ThreatWatch -> SQLAlchemy -> psycopg -> PostgreSQL.

Ce script n'affiche jamais le mot de passe contenu dans DATABASE_URL.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.database import get_safe_database_url, test_database_connection


def main() -> int:
    print(f"Test de connexion avec DATABASE_URL={get_safe_database_url()}")
    try:
        test_database_connection()
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1

    print("Connexion PostgreSQL OK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
Verifie que les tables de la phase 2 existent dans PostgreSQL.

Le script inspecte les tables, colonnes et contraintes principales sans
afficher le mot de passe contenu dans DATABASE_URL.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import inspect

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.database import engine, get_safe_database_url, test_database_connection


EXPECTED_TABLES = {
    "security_bulletins": {
        "columns": {
            "id",
            "external_id",
            "reference",
            "title",
            "summary",
            "description",
            "bulletin_type",
            "severity",
            "impact_level",
            "publication_date",
            "source",
            "source_url",
            "canonical_key",
            "raw_content",
            "created_at",
            "updated_at",
        },
        "unique_constraints": {
            "uq_security_bulletins_source_reference",
            "uq_security_bulletins_canonical_key",
        },
    },
    "bulletin_cves": {
        "columns": {"id", "bulletin_id", "cve_id", "created_at"},
        "unique_constraints": {"uq_bulletin_cves_bulletin_cve"},
        "foreign_keys": {("bulletin_id", "security_bulletins", "id")},
    },
    "sync_history": {
        "columns": {
            "id",
            "source",
            "started_at",
            "finished_at",
            "status",
            "items_found",
            "items_created",
            "items_updated",
            "error_message",
            "created_at",
        },
        "unique_constraints": set(),
    },
}


def main() -> int:
    print(f"Verification des tables phase 2 avec DATABASE_URL={get_safe_database_url()}")

    try:
        test_database_connection()
        inspector = inspect(engine)
        existing_tables = set(inspector.get_table_names())
    except Exception as exc:
        print("ERREUR: impossible d'inspecter la base PostgreSQL.")
        print(f"Detail technique: {exc.__class__.__name__}")
        return 1

    success = True
    for table_name, expected in EXPECTED_TABLES.items():
        if table_name not in existing_tables:
            print(f"MANQUANTE: table {table_name}")
            success = False
            continue

        columns = {column["name"] for column in inspector.get_columns(table_name)}
        missing_columns = expected["columns"] - columns
        if missing_columns:
            print(
                f"INCOMPLETE: table {table_name}, colonnes manquantes: "
                f"{', '.join(sorted(missing_columns))}"
            )
            success = False
        else:
            print(f"OK: table {table_name}, colonnes attendues presentes.")

        unique_constraints = {
            constraint["name"]
            for constraint in inspector.get_unique_constraints(table_name)
            if constraint.get("name")
        }
        missing_constraints = expected["unique_constraints"] - unique_constraints
        if missing_constraints:
            print(
                f"INCOMPLETE: table {table_name}, contraintes uniques manquantes: "
                f"{', '.join(sorted(missing_constraints))}"
            )
            success = False
        elif expected["unique_constraints"]:
            print(f"OK: table {table_name}, contraintes uniques attendues presentes.")

        expected_foreign_keys = expected.get("foreign_keys", set())
        foreign_keys = set()
        for foreign_key in inspector.get_foreign_keys(table_name):
            constrained_columns = foreign_key.get("constrained_columns") or []
            referred_columns = foreign_key.get("referred_columns") or []
            if constrained_columns and referred_columns:
                foreign_keys.add(
                    (
                        constrained_columns[0],
                        foreign_key.get("referred_table"),
                        referred_columns[0],
                    )
                )

        missing_foreign_keys = expected_foreign_keys - foreign_keys
        if missing_foreign_keys:
            formatted_keys = [
                f"{column} -> {referred_table}.{referred_column}"
                for column, referred_table, referred_column in sorted(missing_foreign_keys)
            ]
            print(
                f"INCOMPLETE: table {table_name}, cles etrangeres manquantes: "
                f"{', '.join(formatted_keys)}"
            )
            success = False
        elif expected_foreign_keys:
            print(f"OK: table {table_name}, cles etrangeres attendues presentes.")

    if not success:
        return 1

    print("Tables phase 2 verifiees avec succes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

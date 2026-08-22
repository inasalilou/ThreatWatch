"""
Verification locale de la phase 4.2.1.

Le script controle la table des produits/CPE affectes sans modifier les donnees
et sans lancer d'enrichissement NVD.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import func, inspect, select
from sqlalchemy.exc import SQLAlchemyError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, engine, get_safe_database_url, test_database_connection
from app.models.vulnerability import Vulnerability
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct


EXPECTED_COLUMNS = {
    "id",
    "vulnerability_id",
    "cpe",
    "cpe_part",
    "vendor",
    "product",
    "version",
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
    "vulnerable",
    "created_at",
}

EXPECTED_INDEXES = {
    "ix_vuln_affected_products_vulnerability_id",
    "ix_vuln_affected_products_cpe",
    "ix_vuln_affected_products_vendor_product",
}

EXPECTED_UNIQUE_CONSTRAINT = "uq_vuln_affected_products_cpe_range"


def main() -> int:
    print(
        "Verification phase 4.2 produits affectes avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        if not check_table_structure():
            return 1

        with SessionLocal() as db:
            total = count_affected_products(db)
            vulnerabilities_with_products = count_vulnerabilities_with_products(db)
            duplicates = count_duplicate_affected_products(db)
            orphan_rows = count_orphan_rows(db)

            print(f"Affected products total: {total}")
            print(
                "Vulnerabilities with affected products: "
                f"{vulnerabilities_with_products}"
            )
            print(f"Duplicates: {duplicates}")
            print(f"Orphan rows: {orphan_rows}")

            if duplicates != 0 or orphan_rows != 0:
                print("PHASE 4.2 AFFECTED PRODUCTS CHECK: FAILED")
                return 1

        print("PHASE 4.2 AFFECTED PRODUCTS CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR PostgreSQL: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def check_table_structure() -> bool:
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    if "vulnerability_affected_products" not in tables:
        print("Affected products table: MANQUANTE")
        return False

    columns = {
        column["name"]
        for column in inspector.get_columns("vulnerability_affected_products")
    }
    missing_columns = EXPECTED_COLUMNS - columns
    if missing_columns:
        print(
            "Affected products table: INCOMPLETE, colonnes manquantes: "
            + ", ".join(sorted(missing_columns))
        )
        return False

    if not check_foreign_key(inspector):
        return False

    indexes = {
        index["name"]
        for index in inspector.get_indexes("vulnerability_affected_products")
        if index.get("name")
    }
    missing_indexes = EXPECTED_INDEXES - indexes
    if missing_indexes:
        print(
            "Affected products table: index manquants: "
            + ", ".join(sorted(missing_indexes))
        )
        return False

    unique_constraints = {
        constraint["name"]
        for constraint in inspector.get_unique_constraints(
            "vulnerability_affected_products"
        )
        if constraint.get("name")
    }
    if EXPECTED_UNIQUE_CONSTRAINT not in unique_constraints:
        print("Affected products table: contrainte unique manquante")
        return False

    print("Affected products table: OK")
    return True


def check_foreign_key(inspector) -> bool:
    foreign_keys = inspector.get_foreign_keys("vulnerability_affected_products")
    for foreign_key in foreign_keys:
        if (
            foreign_key.get("referred_table") == "vulnerabilities"
            and foreign_key.get("constrained_columns") == ["vulnerability_id"]
            and foreign_key.get("referred_columns") == ["id"]
        ):
            print("Affected products FK: OK")
            return True

    print("Affected products FK: MANQUANTE")
    return False


def count_affected_products(db) -> int:
    return db.scalar(select(func.count(VulnerabilityAffectedProduct.id))) or 0


def count_vulnerabilities_with_products(db) -> int:
    return (
        db.scalar(
            select(func.count(func.distinct(VulnerabilityAffectedProduct.vulnerability_id)))
        )
        or 0
    )


def count_duplicate_affected_products(db) -> int:
    grouped = (
        select(
            VulnerabilityAffectedProduct.vulnerability_id,
            VulnerabilityAffectedProduct.cpe,
            VulnerabilityAffectedProduct.version_start_including,
            VulnerabilityAffectedProduct.version_start_excluding,
            VulnerabilityAffectedProduct.version_end_including,
            VulnerabilityAffectedProduct.version_end_excluding,
        )
        .group_by(
            VulnerabilityAffectedProduct.vulnerability_id,
            VulnerabilityAffectedProduct.cpe,
            VulnerabilityAffectedProduct.version_start_including,
            VulnerabilityAffectedProduct.version_start_excluding,
            VulnerabilityAffectedProduct.version_end_including,
            VulnerabilityAffectedProduct.version_end_excluding,
        )
        .having(func.count(VulnerabilityAffectedProduct.id) > 1)
        .subquery()
    )
    return db.scalar(select(func.count()).select_from(grouped)) or 0


def count_orphan_rows(db) -> int:
    return (
        db.scalar(
            select(func.count(VulnerabilityAffectedProduct.id))
            .select_from(VulnerabilityAffectedProduct)
            .outerjoin(
                Vulnerability,
                VulnerabilityAffectedProduct.vulnerability_id == Vulnerability.id,
            )
            .where(Vulnerability.id.is_(None))
        )
        or 0
    )


if __name__ == "__main__":
    raise SystemExit(main())

"""
Verification locale de la phase 3.2.1/3.2.2.

Le script ne fait aucun appel externe et ne modifie aucune donnee. Il controle
la table vulnerabilities, les statuts d'enrichissement et la couverture des CVE
deja presentes dans bulletin_cves.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import func, inspect, select
from sqlalchemy.exc import SQLAlchemyError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, engine, get_safe_database_url, test_database_connection
from app.models.security_bulletin import BulletinCVE
from app.models.vulnerability import EnrichmentStatus, Vulnerability


EXPECTED_COLUMNS = {
    "id",
    "cve_id",
    "description",
    "cvss_score",
    "cvss_severity",
    "cvss_vector",
    "cvss_version",
    "cwes",
    "references",
    "published_at",
    "modified_at",
    "enrichment_source",
    "enrichment_status",
    "enrichment_error",
    "last_enrichment_at",
    "created_at",
    "updated_at",
}


def main() -> int:
    print(
        "Verification phase 3.2 modele local avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        if not check_table_structure():
            return 1

        with SessionLocal() as db:
            bulletin_cve_ids = load_unique_bulletin_cve_ids(db)
            vulnerability_cve_ids = load_vulnerability_cve_ids(db)
            missing_cves = sorted(bulletin_cve_ids - vulnerability_cve_ids)
            duplicate_cve_ids = count_duplicate_vulnerability_cve_ids(db)

            status_counts = {
                status: count_vulnerabilities_by_status(db, status)
                for status in EnrichmentStatus
            }

            print(f"BulletinCVE uniques: {len(bulletin_cve_ids)}")
            print(f"Vulnerabilities: {len(vulnerability_cve_ids)}")
            print(f"Vulnerabilities PENDING: {status_counts[EnrichmentStatus.PENDING]}")
            print(f"Vulnerabilities SUCCESS: {status_counts[EnrichmentStatus.SUCCESS]}")
            print(f"Vulnerabilities NOT_FOUND: {status_counts[EnrichmentStatus.NOT_FOUND]}")
            print(f"Vulnerabilities FAILED: {status_counts[EnrichmentStatus.FAILED]}")
            print(f"Doublons cve_id: {duplicate_cve_ids}")
            print(f"CVE BulletinCVE sans Vulnerability: {len(missing_cves)}")

            if missing_cves[:5]:
                print("Exemples CVE manquantes: " + ", ".join(missing_cves[:5]))

            status_total = sum(status_counts.values())
            success = (
                len(bulletin_cve_ids) == len(vulnerability_cve_ids)
                and len(missing_cves) == 0
                and duplicate_cve_ids == 0
                and status_total == len(vulnerability_cve_ids)
            )

            if not success:
                print("PHASE 3.2 LOCAL MODEL CHECK: FAILED")
                return 1

            print("PHASE 3.2 LOCAL MODEL CHECK: OK")
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
    if "vulnerabilities" not in tables:
        print("Vulnerability table: MANQUANTE")
        return False

    columns = {column["name"] for column in inspector.get_columns("vulnerabilities")}
    missing_columns = EXPECTED_COLUMNS - columns
    if missing_columns:
        print(
            "Vulnerability table: INCOMPLETE, colonnes manquantes: "
            + ", ".join(sorted(missing_columns))
        )
        return False

    unique_constraints = {
        constraint["name"]
        for constraint in inspector.get_unique_constraints("vulnerabilities")
        if constraint.get("name")
    }
    if "uq_vulnerabilities_cve_id" not in unique_constraints:
        print("Vulnerability table: contrainte unique cve_id manquante")
        return False

    print("Vulnerability table: OK")
    return True


def load_unique_bulletin_cve_ids(db) -> set[str]:
    rows = db.execute(select(func.distinct(BulletinCVE.cve_id))).scalars()
    return {normalize_cve_id(cve_id) for cve_id in rows if normalize_cve_id(cve_id)}


def load_vulnerability_cve_ids(db) -> set[str]:
    rows = db.execute(select(Vulnerability.cve_id)).scalars()
    return {normalize_cve_id(cve_id) for cve_id in rows if normalize_cve_id(cve_id)}


def count_duplicate_vulnerability_cve_ids(db) -> int:
    grouped = (
        select(Vulnerability.cve_id)
        .group_by(Vulnerability.cve_id)
        .having(func.count(Vulnerability.id) > 1)
        .subquery()
    )
    return db.scalar(select(func.count()).select_from(grouped)) or 0


def count_vulnerabilities_by_status(db, status: EnrichmentStatus) -> int:
    return (
        db.scalar(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.enrichment_status == status
            )
        )
        or 0
    )


def normalize_cve_id(cve_id: str | None) -> str:
    if not cve_id:
        return ""
    return cve_id.strip().upper()


if __name__ == "__main__":
    raise SystemExit(main())

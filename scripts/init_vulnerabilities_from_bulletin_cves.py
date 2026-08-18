"""
Initialise la table vulnerabilities depuis les CVE deja presentes.

Operation idempotente et non destructive :
- lit les CVE uniques de bulletin_cves ;
- cree uniquement les Vulnerability manquantes ;
- initialise chaque nouvelle ligne avec enrichment_status=PENDING ;
- n'appelle aucune API externe.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, create_database_tables, get_safe_database_url
from app.models.security_bulletin import BulletinCVE
from app.models.vulnerability import EnrichmentStatus, Vulnerability


def main() -> int:
    print(
        "Initialisation des vulnerabilities depuis bulletin_cves avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        create_database_tables()
        with SessionLocal() as db:
            cve_ids = load_unique_bulletin_cve_ids(db)
            existing_cve_ids = load_existing_vulnerability_cve_ids(db)
            missing_cve_ids = sorted(cve_ids - existing_cve_ids)

            for cve_id in missing_cve_ids:
                db.add(
                    Vulnerability(
                        cve_id=cve_id,
                        enrichment_status=EnrichmentStatus.PENDING,
                    )
                )

            db.commit()

            print(f"CVE uniques BulletinCVE: {len(cve_ids)}")
            print(f"Vulnerabilities deja existantes: {len(existing_cve_ids)}")
            print(f"Vulnerabilities creees: {len(missing_cve_ids)}")
            print("Initialisation terminee.")
            return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR PostgreSQL: {exc}")
        try:
            db.rollback()  # type: ignore[name-defined]
        except Exception:
            pass
        return 1
    except Exception as exc:
        print(f"ERREUR: {exc.__class__.__name__}: {exc}")
        return 1


def load_unique_bulletin_cve_ids(db) -> set[str]:
    rows = db.execute(select(func.distinct(BulletinCVE.cve_id))).scalars()
    return {normalize_cve_id(cve_id) for cve_id in rows if normalize_cve_id(cve_id)}


def load_existing_vulnerability_cve_ids(db) -> set[str]:
    rows = db.execute(select(Vulnerability.cve_id)).scalars()
    return {normalize_cve_id(cve_id) for cve_id in rows if normalize_cve_id(cve_id)}


def normalize_cve_id(cve_id: str | None) -> str:
    if not cve_id:
        return ""
    return cve_id.strip().upper()


if __name__ == "__main__":
    raise SystemExit(main())

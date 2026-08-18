"""
Verification read-only de la phase 3.1 Vulnerabilites / CVE.

Le script ne cree, ne modifie et ne supprime aucune donnee. Il controle les
volumes, les CVE uniques et les principales requetes du service.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.db.database import SessionLocal, get_safe_database_url, test_database_connection
from app.models.security_bulletin import BulletinCVE
from app.services.vulnerability_service import (
    get_vulnerability_detail,
    get_vulnerability_stats,
    list_vulnerabilities,
)


def main() -> int:
    print(
        "Verification phase 3.1 Vulnerabilites avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        with SessionLocal() as db:
            total_cve_rows = db.scalar(select(func.count(BulletinCVE.id))) or 0
            total_unique_cves = (
                db.scalar(select(func.count(func.distinct(BulletinCVE.cve_id)))) or 0
            )
            multi_bulletin_cves = count_multi_bulletin_cves(db)

            stats = get_vulnerability_stats(db)
            result = list_vulnerabilities(db=db, page=1, per_page=5)

            print(f"Lignes bulletin_cves: {total_cve_rows}")
            print(f"CVE uniques directes: {total_unique_cves}")
            print(f"CVE multi-bulletins directes: {multi_bulletin_cves}")
            print(f"CVE uniques service: {stats.total_unique_cves}")
            print(f"CVE multi-bulletins service: {stats.multi_bulletin_cves}")
            print(f"Resultats premiere page service: {len(result.items)}")

            if stats.total_unique_cves != total_unique_cves:
                print("ERREUR: incoherence sur le nombre de CVE uniques.")
                return 1

            if stats.multi_bulletin_cves != multi_bulletin_cves:
                print("ERREUR: incoherence sur les CVE multi-bulletins.")
                return 1

            if total_unique_cves and not result.items:
                print("ERREUR: la liste paginee ne retourne aucune CVE.")
                return 1

            if result.items:
                sample_cve_id = result.items[0].cve_id
                detail = get_vulnerability_detail(db, sample_cve_id)
                if detail is None or detail.bulletin_count < 1:
                    print(f"ERREUR: detail introuvable pour {sample_cve_id}.")
                    return 1
                print(
                    "Detail exemple: "
                    f"{detail.cve_id} associee a {detail.bulletin_count} bulletin(s)."
                )
            else:
                print("INFO: aucune CVE disponible, requetes service executees a vide.")

            print("PHASE 3 VULNERABILITIES CHECK: OK")
            return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR PostgreSQL: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def count_multi_bulletin_cves(db) -> int:
    grouped = (
        select(BulletinCVE.cve_id)
        .group_by(BulletinCVE.cve_id)
        .having(func.count(func.distinct(BulletinCVE.bulletin_id)) > 1)
        .subquery()
    )
    return db.scalar(select(func.count()).select_from(grouped)) or 0


if __name__ == "__main__":
    raise SystemExit(main())

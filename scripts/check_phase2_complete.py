"""
Verification read-only de la phase 2 DGSSI.

Le script ne cree, ne modifie et ne supprime aucune donnee. Il lit PostgreSQL
pour controler les volumes, le dernier historique et les doublons logiques.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.db.database import SessionLocal, get_safe_database_url
from app.models.security_bulletin import BulletinCVE, SecurityBulletin
from app.models.sync_history import SyncHistory


def main() -> int:
    print(
        "Verification phase 2 complete avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        with SessionLocal() as db:
            total_bulletins = db.scalar(select(func.count(SecurityBulletin.id))) or 0
            total_cves = db.scalar(select(func.count(BulletinCVE.id))) or 0
            total_syncs = db.scalar(select(func.count(SyncHistory.id))) or 0
            latest_sync = db.scalar(
                select(SyncHistory).order_by(SyncHistory.started_at.desc()).limit(1)
            )

            duplicate_references = _count_duplicate_source_references(db)
            duplicate_keys = _count_duplicate_canonical_keys(db)
            duplicate_cves = _count_duplicate_bulletin_cves(db)

            print(f"Bulletins: {total_bulletins}")
            print(f"CVE associees: {total_cves}")
            print(f"Synchronisations: {total_syncs}")

            if latest_sync is None:
                print("Derniere synchronisation: aucune")
            else:
                print(
                    "Derniere synchronisation: "
                    f"{latest_sync.source} {latest_sync.status.value} "
                    f"debut={latest_sync.started_at} "
                    f"fin={latest_sync.finished_at} "
                    f"detectes={latest_sync.items_found} "
                    f"nouveaux={latest_sync.items_created} "
                    f"mis_a_jour={latest_sync.items_updated}"
                )
                if latest_sync.error_message:
                    print(f"Derniere erreur: {latest_sync.error_message}")

            if duplicate_references or duplicate_keys or duplicate_cves:
                print("ERREUR: doublons detectes")
                print(f"- doublons source/reference: {duplicate_references}")
                print(f"- doublons canonical_key: {duplicate_keys}")
                print(f"- doublons bulletin/CVE: {duplicate_cves}")
                return 1

            print("OK: phase 2 DGSSI complete verifiee sans doublons.")
            return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR PostgreSQL: {exc}")
        return 1


def _count_duplicate_source_references(db) -> int:
    grouped = (
        select(func.count())
        .select_from(SecurityBulletin)
        .group_by(SecurityBulletin.source, SecurityBulletin.reference)
        .having(func.count(SecurityBulletin.id) > 1)
    ).subquery()
    return db.scalar(select(func.count()).select_from(grouped)) or 0


def _count_duplicate_canonical_keys(db) -> int:
    grouped = (
        select(func.count())
        .select_from(SecurityBulletin)
        .group_by(SecurityBulletin.canonical_key)
        .having(func.count(SecurityBulletin.id) > 1)
    ).subquery()
    return db.scalar(select(func.count()).select_from(grouped)) or 0


def _count_duplicate_bulletin_cves(db) -> int:
    grouped = (
        select(func.count())
        .select_from(BulletinCVE)
        .group_by(BulletinCVE.bulletin_id, BulletinCVE.cve_id)
        .having(func.count(BulletinCVE.id) > 1)
    ).subquery()
    return db.scalar(select(func.count()).select_from(grouped)) or 0


if __name__ == "__main__":
    raise SystemExit(main())

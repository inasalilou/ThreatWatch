"""
Controle en lecture seule les donnees DGSSI importees.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.database import SessionLocal, test_database_connection
from app.models.security_bulletin import BulletinCVE, SecurityBulletin
from app.models.sync_history import SyncHistory


def main() -> int:
    try:
        test_database_connection()
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1

    db = SessionLocal()
    try:
        total_bulletins = db.scalar(select(func.count(SecurityBulletin.id))) or 0
        total_cves = db.scalar(select(func.count(BulletinCVE.id))) or 0
        total_syncs = db.scalar(select(func.count(SyncHistory.id))) or 0

        latest_bulletins = (
            db.execute(
                select(SecurityBulletin)
                .options(selectinload(SecurityBulletin.cves))
                .order_by(SecurityBulletin.created_at.desc())
                .limit(5)
            )
            .scalars()
            .all()
        )
        latest_sync = (
            db.execute(
                select(SyncHistory)
                .order_by(SyncHistory.started_at.desc())
                .limit(1)
            )
            .scalar_one_or_none()
        )
    finally:
        db.close()

    print("========================================")
    print("ThreatWatch - Donnees DGSSI")
    print("========================================")
    print("")
    print(f"Security bulletins : {total_bulletins}")
    print(f"Bulletin CVE : {total_cves}")
    print(f"Sync history : {total_syncs}")
    print("")
    print("Derniers bulletins :")
    if latest_bulletins:
        for bulletin in latest_bulletins:
            cve_count = len(bulletin.cves)
            print(
                f"- {bulletin.reference} | {bulletin.publication_date} | "
                f"{bulletin.severity or 'Non evalue'} | {cve_count} CVE | {bulletin.title}"
            )
    else:
        print("- Aucun")

    print("")
    print("Derniere synchronisation :")
    if latest_sync:
        finished_at = latest_sync.finished_at.isoformat(sep=" ") if latest_sync.finished_at else "Non terminee"
        print(f"- Source : {latest_sync.source}")
        print(f"- Statut : {latest_sync.status.value}")
        print(f"- Debut : {latest_sync.started_at.isoformat(sep=' ')}")
        print(f"- Fin : {finished_at}")
        print(f"- Elements detectes : {latest_sync.items_found}")
        print(f"- Nouveaux elements : {latest_sync.items_created}")
        print(f"- Elements mis a jour : {latest_sync.items_updated}")
        if latest_sync.error_message:
            print(f"- Erreur : {latest_sync.error_message}")
    else:
        print("- Aucune")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

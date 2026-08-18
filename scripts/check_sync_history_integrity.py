"""
Diagnostic read-only de l'historique des synchronisations DGSSI.

Le script ne cree, ne modifie et ne supprime aucune donnee. Il signale les
synchronisations ouvertes et distingue celles qui semblent recentes de celles
qui sont probablement restees ouvertes apres interruption du processus.
"""
from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.db.database import SessionLocal, get_safe_database_url, test_database_connection
from app.models.sync_history import SyncHistory


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verifie l'integrite read-only de sync_history."
    )
    parser.add_argument(
        "--stale-minutes",
        type=int,
        default=10,
        help="Age apres lequel une synchronisation ouverte est consideree suspecte.",
    )
    args = parser.parse_args()

    print(
        "Diagnostic SyncHistory avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        with SessionLocal() as db:
            now = datetime.now(UTC).replace(tzinfo=None)
            stale_before = now - timedelta(minutes=max(args.stale_minutes, 1))

            total_runs = db.scalar(select(func.count(SyncHistory.id))) or 0
            open_syncs = (
                db.execute(
                    select(SyncHistory)
                    .where(SyncHistory.finished_at.is_(None))
                    .order_by(SyncHistory.started_at.desc())
                )
                .scalars()
                .all()
            )
            stale_syncs = [
                sync for sync in open_syncs if sync.started_at < stale_before
            ]
            latest_sync = db.scalar(
                select(SyncHistory).order_by(SyncHistory.started_at.desc()).limit(1)
            )

            print(f"Synchronisations tracees: {total_runs}")
            print(f"Synchronisations ouvertes: {len(open_syncs)}")
            print(
                "Synchronisations ouvertes suspectes "
                f"(>{max(args.stale_minutes, 1)} min): {len(stale_syncs)}"
            )

            if latest_sync:
                print(
                    "Derniere synchronisation: "
                    f"id={latest_sync.id} status={latest_sync.status.value} "
                    f"debut={latest_sync.started_at} fin={latest_sync.finished_at} "
                    f"detectes={latest_sync.items_found} "
                    f"nouveaux={latest_sync.items_created}"
                )

            if open_syncs:
                print("Synchronisations ouvertes:")
                for sync in open_syncs:
                    age_seconds = int((now - sync.started_at).total_seconds())
                    marker = "SUSPECTE" if sync in stale_syncs else "RECENTE"
                    print(
                        f"- {marker} id={sync.id} status={sync.status.value} "
                        f"debut={sync.started_at} age={age_seconds}s "
                        f"detectes={sync.items_found} "
                        f"nouveaux={sync.items_created} "
                        f"erreur={sync.error_message or '-'}"
                    )

            if stale_syncs:
                print("SYNC HISTORY INTEGRITY CHECK: WARNING")
            else:
                print("SYNC HISTORY INTEGRITY CHECK: OK")
            return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR PostgreSQL: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""
Lance une synchronisation manuelle DGSSI vers PostgreSQL.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.database import SessionLocal, create_database_tables
from app.services.dgssi_collector import DGSSICollector
from app.services.synchronization_service import sync_dgssi_bulletins


def main() -> int:
    parser = argparse.ArgumentParser(description="Synchronise les bulletins DGSSI.")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Nombre maximum de bulletins DGSSI a traiter.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Timeout HTTP en secondes pour la collecte DGSSI.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    print("========================================")
    print("ThreatWatch - Synchronisation DGSSI")
    print("========================================")
    print("")

    create_database_tables()
    db = SessionLocal()
    try:
        collector = DGSSICollector(timeout=args.timeout)
        result = sync_dgssi_bulletins(db=db, collector=collector, limit=args.limit)
    finally:
        db.close()

    print("Connexion DGSSI OK." if result.status.value != "FAILED" else "Connexion DGSSI en erreur.")
    print("")
    print(f"Bulletins detectes : {result.items_found}")
    print(f"Bulletins traites : {result.items_processed}")
    print("")
    print(f"Nouveaux bulletins : {result.items_created}")
    print(f"Bulletins deja connus : {result.items_known}")
    print(f"CVE enregistrees : {result.cves_created}")
    print("")
    print(f"Synchronisation : {result.status.value}")
    print(f"Historique ID : {result.sync_history_id}")

    if result.errors:
        print("")
        print("Erreurs :")
        for error in result.errors:
            print(f"- {error}")

    return 0 if result.status.value in {"SUCCESS", "PARTIAL"} else 1


if __name__ == "__main__":
    raise SystemExit(main())

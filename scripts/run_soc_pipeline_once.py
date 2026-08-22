"""
Execute une fois le pipeline SOC automatique.

Script manuel : pas de boucle, pas de scheduler. Les appels NVD reels restent
limites par --limit et par le delai configure.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.database import SessionLocal, get_safe_database_url, test_database_connection
from app.services.soc_orchestration_service import process_pending_security_pipeline


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute une fois le pipeline SOC ThreatWatch.")
    parser.add_argument("--limit", type=int, default=None, help="Nombre maximum de CVE a traiter.")
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="Inclure les CVE FAILED dans ce cycle manuel.",
    )
    args = parser.parse_args()

    print(f"Pipeline SOC ThreatWatch avec DATABASE_URL={get_safe_database_url()}")
    try:
        test_database_connection()
        db = SessionLocal()
        try:
            result = process_pending_security_pipeline(
                db,
                limit=args.limit,
                include_failed_retry=args.retry_failed,
            )
        finally:
            db.close()
    except Exception as exc:
        print("ERREUR: pipeline SOC impossible.")
        print(f"Detail technique: {exc.__class__.__name__}")
        return 1

    print("PIPELINE SOC TERMINE")
    print(f"  disabled                  : {result.disabled}")
    print(f"  selected_vulnerabilities  : {result.selected_vulnerabilities}")
    print(f"  enriched_success          : {result.enriched_success}")
    print(f"  enriched_not_found        : {result.enriched_not_found}")
    print(f"  enriched_failed           : {result.enriched_failed}")
    print(f"  assets_checked            : {result.assets_checked}")
    print(f"  matches                   : {result.matches}")
    print(f"  possible_matches          : {result.possible_matches}")
    print(f"  no_matches                : {result.no_matches}")
    print(f"  unknown                   : {result.unknown}")
    print(f"  correlations_created      : {result.correlations_created}")
    print(f"  correlations_updated      : {result.correlations_updated}")
    print(f"  alerts_created_or_updated : {result.alerts_created_or_updated}")
    print(f"  notifications_created_or_updated: {result.notifications_created_or_updated}")
    print(f"  duration_seconds          : {result.duration_seconds}")
    if result.errors:
        print(f"  errors                    : {len(result.errors)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
Enrichissement NVD par lot controle.

Le batch reste manuel, sequentiel et limite. Il reutilise l'enrichissement
unitaire valide en phase 3.2.3 et ne lance aucun scheduler.
"""
from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import case, select
from sqlalchemy.exc import SQLAlchemyError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.core.config import settings
from app.db.database import SessionLocal, get_safe_database_url, test_database_connection
from app.models.vulnerability import EnrichmentStatus, Vulnerability
from app.services.cve_enrichment_service import enrich_single_cve
from app.services.nvd_client import NVDClient

MAX_BATCH_LIMIT = 100


@dataclass
class BatchSummary:
    selected: int = 0
    processed: int = 0
    success: int = 0
    not_found: int = 0
    failed: int = 0
    interrupted: bool = False


def main() -> int:
    args = parse_args()
    limit = validate_limit(args.limit)
    delay_seconds = validate_delay(args.delay)

    print("Batch NVD ThreatWatch")
    print(f"DATABASE_URL={get_safe_database_url()}")
    print(f"NVD API key: {'configuree' if settings.NVD_API_KEY else 'non configuree'}")
    print(f"Limite demandee: {limit}")
    print(f"Delai entre requetes: {delay_seconds:g} seconde(s)")
    print(f"Mode dry-run: {'oui' if args.dry_run else 'non'}")
    print(f"Retry FAILED: {'oui' if args.retry_failed else 'non'}")

    try:
        test_database_connection()
        with SessionLocal() as db:
            selected_cves = select_cves_for_batch(
                db=db,
                limit=limit,
                retry_failed=args.retry_failed,
            )

        print(f"CVE selectionnees: {len(selected_cves)}")
        if not selected_cves:
            print("Aucune CVE eligible.")
            return 0

        if args.dry_run:
            print("CVE qui seraient enrichies:")
            for cve_id in selected_cves:
                print(f"- {cve_id}")
            print("DRY RUN: aucune modification effectuee.")
            return 0

        summary = run_batch(
            cve_ids=selected_cves,
            delay_seconds=delay_seconds,
        )
        print_summary(summary)
        return 0 if not summary.interrupted else 130
    except ValueError as exc:
        print(f"ERREUR: {exc}")
        return 1
    except SQLAlchemyError as exc:
        print(f"ERREUR PostgreSQL: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def parse_args():
    parser = argparse.ArgumentParser(
        description="Enrichit un petit lot de CVE ThreatWatch via NVD API 2.0."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=max(settings.NVD_BATCH_SIZE, 1),
        help=f"Nombre maximal de CVE a traiter, maximum {MAX_BATCH_LIMIT}.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=max(settings.NVD_REQUEST_DELAY_SECONDS, 0),
        help="Delai en secondes entre deux appels NVD.",
    )
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="Inclut les CVE FAILED apres les PENDING.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Affiche les CVE selectionnees sans appel NVD ni modification DB.",
    )
    return parser.parse_args()


def validate_limit(limit: int) -> int:
    if limit <= 0:
        raise ValueError("--limit doit etre strictement positif.")
    if limit > MAX_BATCH_LIMIT:
        raise ValueError(f"--limit ne peut pas depasser {MAX_BATCH_LIMIT}.")
    return limit


def validate_delay(delay: float) -> float:
    if delay < 0:
        raise ValueError("--delay ne peut pas etre negatif.")
    return delay


def select_cves_for_batch(db, limit: int, retry_failed: bool) -> list[str]:
    statuses = [EnrichmentStatus.PENDING]
    if retry_failed:
        statuses.append(EnrichmentStatus.FAILED)

    # Ordre stable : les PENDING sont traitees avant les FAILED, puis les plus
    # anciennes entrees. Une relance continue donc naturellement sur les
    # prochaines CVE encore eligibles.
    rows = db.execute(
        select(Vulnerability.cve_id)
        .where(Vulnerability.enrichment_status.in_(statuses))
        .order_by(
            case(
                (Vulnerability.enrichment_status == EnrichmentStatus.PENDING, 0),
                (Vulnerability.enrichment_status == EnrichmentStatus.FAILED, 1),
                else_=2,
            ),
            Vulnerability.created_at.asc(),
            Vulnerability.cve_id.asc(),
        )
        .limit(limit)
    ).scalars()
    return list(rows)


def run_batch(cve_ids: list[str], delay_seconds: float) -> BatchSummary:
    summary = BatchSummary(selected=len(cve_ids))
    started_at = time.monotonic()
    client = NVDClient()

    try:
        for index, cve_id in enumerate(cve_ids, start=1):
            print("")
            print(f"[{index}/{len(cve_ids)}] {cve_id}")
            with SessionLocal() as db:
                result = enrich_single_cve(db=db, cve_id=cve_id, client=client)

            summary.processed += 1
            if result.new_status == EnrichmentStatus.SUCCESS:
                summary.success += 1
            elif result.new_status == EnrichmentStatus.NOT_FOUND:
                summary.not_found += 1
            elif result.new_status == EnrichmentStatus.FAILED:
                summary.failed += 1

            print(f"Ancien statut: {result.old_status.value}")
            print(f"Resultat: {result.new_status.value}")
            print(f"CVSS: {result.cvss_score if result.cvss_score is not None else '-'}")
            print(f"Severity: {result.cvss_severity or '-'}")
            if result.error_message:
                print(f"Erreur: {result.error_message}")

            if index < len(cve_ids) and delay_seconds > 0:
                print(f"Attente NVD: {delay_seconds:g} seconde(s)...")
                time.sleep(delay_seconds)
    except KeyboardInterrupt:
        summary.interrupted = True
        print("")
        print("Interruption utilisateur detectee. Arret propre du batch.")

    duration_seconds = int(time.monotonic() - started_at)
    print(f"Duree mesuree: {duration_seconds}s")
    return summary


def print_summary(summary: BatchSummary) -> None:
    print("")
    print("===================================")
    print("ENRICHISSEMENT NVD TERMINE")
    print("===================================")
    print(f"Selectionnees: {summary.selected}")
    print(f"Traitees: {summary.processed}")
    print(f"SUCCESS: {summary.success}")
    print(f"NOT_FOUND: {summary.not_found}")
    print(f"FAILED: {summary.failed}")
    if summary.interrupted:
        print("Statut batch: INTERROMPU")
    else:
        print("Statut batch: TERMINE")


if __name__ == "__main__":
    raise SystemExit(main())

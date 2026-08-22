r"""
Traite une CVE existante contre les actifs actifs et persiste uniquement les
resultats MATCH/POSSIBLE_MATCH via le service de persistance existant.

Usage:
    .\.venv\Scripts\python.exe scripts\process_existing_cve_correlation.py CVE-2026-16627

Le script ne cree jamais directement d'Alert ni de Notification. Ces effets
restent delegues a persist_correlation_result() et aux services existants.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, get_safe_database_url, test_database_connection  # noqa: E402
from app.models.alert import Alert  # noqa: E402
from app.models.asset import Asset  # noqa: E402
from app.models.asset_vulnerability_correlation import AssetVulnerabilityCorrelation  # noqa: E402
from app.models.notification import Notification  # noqa: E402
from app.models.vulnerability import Vulnerability  # noqa: E402
from app.services.correlation_persistence_service import persist_correlation_result  # noqa: E402
from app.services.correlation_service import (  # noqa: E402
    AffectedProductEvaluation,
    AssetVulnerabilityCorrelationResult,
    CorrelationStatus,
    evaluate_asset_vulnerability,
)


PERSISTABLE_STATUSES = {CorrelationStatus.MATCH, CorrelationStatus.POSSIBLE_MATCH}


@dataclass
class ProcessingCounters:
    matches: int = 0
    possible_matches: int = 0
    correlations_created_or_updated: int = 0
    alerts_created_or_updated: int = 0
    notifications_created_or_updated: int = 0


def main() -> int:
    args = parse_args()
    cve_id = args.cve_id.strip().upper()

    print("ThreatWatch - traitement controle de correlation CVE existante")
    print(f"DATABASE_URL={get_safe_database_url()}")
    print(f"CVE cible={cve_id}")
    print("")

    try:
        test_database_connection()
        with SessionLocal() as db:
            vulnerability = load_vulnerability(db, cve_id)
            if vulnerability is None:
                print(f"ERREUR: Vulnerability introuvable pour {cve_id}")
                db.rollback()
                return 1

            assets = load_active_assets(db)
            print_vulnerability_summary(vulnerability)
            print(f"Actifs actifs charges: {len(assets)}")
            print("")

            counters = ProcessingCounters()
            for asset in assets:
                result = evaluate_asset_vulnerability(asset, vulnerability)
                print_asset_result(asset, result)
                process_result(db, result, counters)

            db.commit()
            print_summary(counters)
            return 0
    except Exception as exc:
        print(f"ERREUR: {exc}")
        return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evalue et persiste les correlations MATCH/POSSIBLE_MATCH d'une CVE existante.",
    )
    parser.add_argument("cve_id", help="Identifiant CVE, exemple CVE-2026-16627")
    return parser.parse_args()


def load_vulnerability(db, cve_id: str) -> Vulnerability | None:
    return db.execute(
        select(Vulnerability)
        .options(selectinload(Vulnerability.affected_products))
        .where(Vulnerability.cve_id == cve_id)
    ).scalar_one_or_none()


def load_active_assets(db) -> list[Asset]:
    return list(
        db.execute(
            select(Asset)
            .where(Asset.is_active.is_(True))
            .order_by(Asset.name.asc(), Asset.id.asc())
        ).scalars()
    )


def process_result(
    db,
    result: AssetVulnerabilityCorrelationResult,
    counters: ProcessingCounters,
) -> None:
    if result.status == CorrelationStatus.MATCH:
        counters.matches += 1
    elif result.status == CorrelationStatus.POSSIBLE_MATCH:
        counters.possible_matches += 1

    if result.status not in PERSISTABLE_STATUSES:
        print("  persistence: skipped")
        print("")
        return

    before_notification_count = count_notifications_for_asset_vulnerability(
        db,
        result.asset_id,
        result.vulnerability_id,
    )
    correlation = persist_correlation_result(db, result)
    if correlation is None:
        print("  persistence: aucun objet retourne")
        print("")
        return

    counters.correlations_created_or_updated += 1
    print(f"  correlation: {correlation.id} ({correlation.status.value})")

    alert = find_alert_by_correlation(db, correlation.id)
    if result.status == CorrelationStatus.MATCH and alert is not None:
        counters.alerts_created_or_updated += 1
        after_notification_count = count_notifications_for_alert(db, alert.id)
        created_or_updated_notifications = max(
            after_notification_count - before_notification_count,
            0,
        )
        counters.notifications_created_or_updated += created_or_updated_notifications
        print(f"  alert: {alert.id} ({alert.priority_level.value})")
        print(f"  notifications_delta: {created_or_updated_notifications}")
    else:
        print("  alert: -")
        print("  notifications_delta: 0")
    print("")


def print_vulnerability_summary(vulnerability: Vulnerability) -> None:
    print("=== Vulnerability ===")
    print(f"cve_id: {vulnerability.cve_id}")
    print(f"enrichment_status: {enum_value(vulnerability.enrichment_status)}")
    print(f"cvss_score: {value_or_dash(vulnerability.cvss_score)}")
    print(f"cvss_severity: {value_or_dash(vulnerability.cvss_severity)}")
    print(f"affected_products: {len(vulnerability.affected_products or [])}")
    print("")


def print_asset_result(asset: Asset, result: AssetVulnerabilityCorrelationResult) -> None:
    primary = select_primary_evaluation(result)
    print(f"--- Asset: {asset.name} ---")
    print(
        "  asset: "
        f"vendor={value_or_dash(asset.vendor)}, "
        f"product={value_or_dash(asset.product)}, "
        f"version={value_or_dash(asset.product_version)}"
    )
    print(f"  result: {enum_value(result.status)}")
    print(f"  reason: {result.reason}")
    if primary is not None:
        print(f"  vendor_result: {enum_value(primary.vendor_result)}")
        print(f"  product_result: {enum_value(primary.product_result)}")
        print(f"  version_result: {enum_value(primary.version_result)}")
        print(f"  cpe_result: {enum_value(primary.cpe_result)}")


def select_primary_evaluation(
    result: AssetVulnerabilityCorrelationResult,
) -> AffectedProductEvaluation | None:
    if result.matched_affected_product_id:
        for evaluation in result.affected_product_results:
            if evaluation.affected_product_id == result.matched_affected_product_id:
                return evaluation

    for evaluation in result.affected_product_results:
        if evaluation.status == result.status:
            return evaluation

    if result.affected_product_results:
        return result.affected_product_results[0]
    return None


def find_alert_by_correlation(db, correlation_id: str) -> Alert | None:
    return db.execute(
        select(Alert).where(Alert.correlation_id == correlation_id)
    ).scalar_one_or_none()


def count_notifications_for_alert(db, alert_id: str) -> int:
    return (
        db.scalar(select(func.count(Notification.id)).where(Notification.alert_id == alert_id))
        or 0
    )


def count_notifications_for_asset_vulnerability(
    db,
    asset_id: str | None,
    vulnerability_id: str | None,
) -> int:
    if not asset_id or not vulnerability_id:
        return 0
    return (
        db.scalar(
            select(func.count(Notification.id))
            .join(Alert, Notification.alert_id == Alert.id)
            .where(
                Alert.asset_id == asset_id,
                Alert.vulnerability_id == vulnerability_id,
            )
        )
        or 0
    )


def print_summary(counters: ProcessingCounters) -> None:
    print("=== Resume ===")
    print(f"matches: {counters.matches}")
    print(f"possible_matches: {counters.possible_matches}")
    print(
        "correlations_created_or_updated: "
        f"{counters.correlations_created_or_updated}"
    )
    print(f"alerts_created_or_updated: {counters.alerts_created_or_updated}")
    print(
        "notifications_created_or_updated: "
        f"{counters.notifications_created_or_updated}"
    )


def enum_value(value) -> str:
    return getattr(value, "value", str(value or "")).strip() or "-"


def value_or_dash(value) -> str:
    if value is None:
        return "-"
    text = str(value)
    return text if text else "-"


if __name__ == "__main__":
    raise SystemExit(main())

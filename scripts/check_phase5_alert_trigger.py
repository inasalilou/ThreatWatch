"""
Verification locale de la phase 5.4.

Controle le declenchement evenementiel des alertes depuis la persistance des
correlations MATCH. Aucun batch global, aucun scheduler, rollback final.
"""
from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, get_safe_database_url, test_database_connection  # noqa: E402
from app.models.alert import Alert, AlertPriority, AlertStatus  # noqa: E402
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType  # noqa: E402
from app.models.asset_vulnerability_correlation import (  # noqa: E402
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.vulnerability import EnrichmentStatus, Vulnerability  # noqa: E402
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct  # noqa: E402
from app.services.alert_service import close_alert, resolve_alert, start_alert  # noqa: E402
from app.services.correlation_persistence_service import (  # noqa: E402
    evaluate_and_persist_asset_vulnerability,
)
from app.services.correlation_service import CorrelationStatus  # noqa: E402


def main() -> int:
    print(
        "Verification phase 5.4 declenchement alertes avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        with SessionLocal() as db:
            checks = [
                check_new_match_creates_alert(db),
                check_match_reevaluation_no_duplicate(db),
                check_possible_match_creates_no_alert(db),
                check_no_match_creates_no_new_alert(db),
                check_inactive_asset_creates_no_alert(db),
                check_closed_alert_not_reopened(db),
            ]
            if not all(checks):
                return 1
            db.rollback()

        print("PHASE 5.4 ALERT TRIGGER CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR SQLAlchemy: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def check_new_match_creates_alert(db) -> bool:
    asset, vulnerability = create_asset_vulnerability_pair(db, "NEW-MATCH")
    result = evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    correlation = get_pair_correlation(db, asset.id, vulnerability.id)
    alert = get_alert_for_correlation(db, correlation.id if correlation else "")

    if (
        result.status != CorrelationStatus.MATCH
        or correlation is None
        or correlation.status != CorrelationPersistenceStatus.MATCH
        or alert is None
        or alert.status != AlertStatus.NEW
        or alert.priority_level != AlertPriority.CRITICAL
    ):
        print("MATCH nouveau -> alerte creee: FAILED")
        return False

    print("MATCH nouveau -> alerte creee: OK")
    return True


def check_match_reevaluation_no_duplicate(db) -> bool:
    asset, vulnerability = create_asset_vulnerability_pair(db, "REEVAL")
    evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    correlation = get_pair_correlation(db, asset.id, vulnerability.id)
    first_alert = get_alert_for_correlation(db, correlation.id)
    first_alert_id = first_alert.id

    evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    second_alert = get_alert_for_correlation(db, correlation.id)

    if (
        second_alert is None
        or second_alert.id != first_alert_id
        or count_alerts_for_correlation(db, correlation.id) != 1
    ):
        print("MATCH reevalue -> pas de doublon: FAILED")
        return False

    print("MATCH reevalue -> meme alerte sans doublon: OK")
    return True


def check_possible_match_creates_no_alert(db) -> bool:
    asset, vulnerability = create_asset_vulnerability_pair(
        db,
        "POSSIBLE",
        product_version=None,
    )
    result = evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    correlation = get_pair_correlation(db, asset.id, vulnerability.id)

    if (
        result.status != CorrelationStatus.POSSIBLE_MATCH
        or correlation is None
        or count_alerts_for_correlation(db, correlation.id) != 0
    ):
        print("POSSIBLE_MATCH -> aucune alerte: FAILED")
        return False

    print("POSSIBLE_MATCH -> aucune alerte: OK")
    return True


def check_no_match_creates_no_new_alert(db) -> bool:
    asset, vulnerability = create_asset_vulnerability_pair(db, "NO-MATCH")
    evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    correlation = get_pair_correlation(db, asset.id, vulnerability.id)
    initial_alert_count = count_alerts_for_correlation(db, correlation.id)

    asset.product_version = "3.0.0"
    result = evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    after_alert_count = count_alerts_for_correlation(db, correlation.id)

    if (
        result.status != CorrelationStatus.NO_MATCH
        or correlation.status != CorrelationPersistenceStatus.NO_MATCH
        or correlation.is_active
        or initial_alert_count != 1
        or after_alert_count != 1
    ):
        print("NO_MATCH -> aucune nouvelle alerte: FAILED")
        return False

    print("NO_MATCH -> aucune nouvelle alerte: OK")
    return True


def check_inactive_asset_creates_no_alert(db) -> bool:
    asset, vulnerability = create_asset_vulnerability_pair(db, "INACTIVE")
    asset.is_active = False
    result = evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    correlation = get_pair_correlation(db, asset.id, vulnerability.id)

    if (
        result.status != CorrelationStatus.UNKNOWN
        or correlation is not None
        or count_alerts_for_asset_vulnerability(db, asset.id, vulnerability.id) != 0
    ):
        print("Actif inactif -> aucune alerte: FAILED")
        return False

    print("Actif inactif -> aucune alerte: OK")
    return True


def check_closed_alert_not_reopened(db) -> bool:
    asset, vulnerability = create_asset_vulnerability_pair(db, "CLOSED")
    evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    correlation = get_pair_correlation(db, asset.id, vulnerability.id)
    alert = get_alert_for_correlation(db, correlation.id)

    start_alert(db, alert.id)
    resolve_alert(db, alert.id)
    close_alert(db, alert.id)
    closed_alert_id = alert.id

    evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    db.refresh(alert)

    if (
        count_alerts_for_correlation(db, correlation.id) != 1
        or alert.id != closed_alert_id
        or alert.status != AlertStatus.CLOSED
        or alert.is_active is not False
    ):
        print("CLOSED existante non rouverte: FAILED")
        return False

    print("CLOSED existante non rouverte: OK")
    return True


def create_asset_vulnerability_pair(
    db,
    suffix: str,
    product_version: str | None = "1.5.0",
) -> tuple[Asset, Vulnerability]:
    token = uuid4().hex[:8].upper()
    asset = Asset(
        name=f"TEST-TRIGGER-{suffix}-{token}",
        asset_type=AssetType.APPLICATION,
        vendor="TriggerVendor",
        product="TriggerProduct",
        product_version=product_version,
        criticality=AssetCriticality.CRITICAL,
        environment=AssetEnvironment.PRODUCTION,
        is_active=True,
    )
    vulnerability = Vulnerability(
        cve_id=f"CVE-2097-{token[:4]}",
        description="Vulnerabilite de test pour declenchement alerte.",
        cvss_score=Decimal("9.8"),
        cvss_severity="CRITICAL",
        enrichment_status=EnrichmentStatus.SUCCESS,
    )
    affected_product = VulnerabilityAffectedProduct(
        cpe=f"cpe:2.3:a:triggervendor:triggerproduct:*:*:*:*:*:*:*:*:{token}",
        cpe_part="a",
        vendor="TriggerVendor",
        product="TriggerProduct",
        version="*",
        version_start_including="1.0.0",
        version_start_excluding="",
        version_end_including="",
        version_end_excluding="2.0.0",
        vulnerable=True,
    )
    vulnerability.affected_products.append(affected_product)
    db.add_all([asset, vulnerability])
    db.flush()
    return asset, vulnerability


def get_pair_correlation(
    db,
    asset_id: str,
    vulnerability_id: str,
) -> AssetVulnerabilityCorrelation | None:
    return db.execute(
        select(AssetVulnerabilityCorrelation).where(
            AssetVulnerabilityCorrelation.asset_id == asset_id,
            AssetVulnerabilityCorrelation.vulnerability_id == vulnerability_id,
        )
    ).scalar_one_or_none()


def get_alert_for_correlation(db, correlation_id: str) -> Alert | None:
    return db.execute(
        select(Alert).where(Alert.correlation_id == correlation_id)
    ).scalar_one_or_none()


def count_alerts_for_correlation(db, correlation_id: str) -> int:
    return (
        db.scalar(select(func.count(Alert.id)).where(Alert.correlation_id == correlation_id))
        or 0
    )


def count_alerts_for_asset_vulnerability(
    db,
    asset_id: str,
    vulnerability_id: str,
) -> int:
    return (
        db.scalar(
            select(func.count(Alert.id)).where(
                Alert.asset_id == asset_id,
                Alert.vulnerability_id == vulnerability_id,
            )
        )
        or 0
    )


if __name__ == "__main__":
    raise SystemExit(main())

"""
Verification locale de la phase 5.1.

Le script controle la table alerts et la creation controlee depuis une
correlation MATCH. Les donnees positives sont annulees par rollback final.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import func, inspect, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, engine, get_safe_database_url, test_database_connection
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType
from app.models.asset_vulnerability_correlation import (
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.vulnerability import Vulnerability
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct
from app.services.alert_service import create_alert_from_correlation, list_alerts
from app.services.correlation_persistence_service import (
    evaluate_and_persist_asset_vulnerability,
)


TEST_CVE_ID = "CVE-2025-58057"

EXPECTED_COLUMNS = {
    "id",
    "correlation_id",
    "asset_id",
    "vulnerability_id",
    "title",
    "description",
    "severity",
    "status",
    "source",
    "reason",
    "first_detected_at",
    "last_seen_at",
    "is_active",
    "created_at",
    "updated_at",
}

EXPECTED_INDEXES = {
    "ix_alerts_asset_id",
    "ix_alerts_vulnerability_id",
    "ix_alerts_status",
    "ix_alerts_severity",
    "ix_alerts_is_active",
}

EXPECTED_UNIQUE_CONSTRAINT = "uq_alerts_correlation_id"


def main() -> int:
    print(
        "Verification phase 5.1 alertes avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        if not check_table_structure():
            return 1

        with SessionLocal() as db:
            print_counts(db)
            vulnerability = load_test_vulnerability(db)
            if vulnerability is None:
                print(f"CVE de test introuvable: {TEST_CVE_ID}")
                return 1

            if not check_alert_creation_rules(db, vulnerability):
                return 1
            if not check_list_alerts(db):
                return 1

            db.rollback()

        print("PHASE 5.1 ALERTS CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR PostgreSQL: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def check_table_structure() -> bool:
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    if "alerts" not in tables:
        print("Alert table: MANQUANTE")
        return False

    columns = {column["name"] for column in inspector.get_columns("alerts")}
    missing_columns = EXPECTED_COLUMNS - columns
    if missing_columns:
        print(
            "Alert table: INCOMPLETE, colonnes manquantes: "
            + ", ".join(sorted(missing_columns))
        )
        return False

    if not check_foreign_keys(inspector):
        return False

    indexes = {
        index["name"]
        for index in inspector.get_indexes("alerts")
        if index.get("name")
    }
    missing_indexes = EXPECTED_INDEXES - indexes
    if missing_indexes:
        print("Alert table: index manquants: " + ", ".join(sorted(missing_indexes)))
        return False

    unique_constraints = {
        constraint["name"]
        for constraint in inspector.get_unique_constraints("alerts")
        if constraint.get("name")
    }
    if EXPECTED_UNIQUE_CONSTRAINT not in unique_constraints:
        print("Alert table: contrainte unique correlation_id manquante")
        return False

    print("Alert table: OK")
    return True


def check_foreign_keys(inspector) -> bool:
    expected = {
        ("correlation_id", "asset_vulnerability_correlations", "id"),
        ("asset_id", "assets", "id"),
        ("vulnerability_id", "vulnerabilities", "id"),
    }
    found = set()
    for foreign_key in inspector.get_foreign_keys("alerts"):
        constrained_columns = foreign_key.get("constrained_columns") or []
        referred_columns = foreign_key.get("referred_columns") or []
        if len(constrained_columns) == 1 and len(referred_columns) == 1:
            found.add(
                (
                    constrained_columns[0],
                    foreign_key.get("referred_table"),
                    referred_columns[0],
                )
            )

    missing = expected - found
    if missing:
        print("Alert FK: MANQUANTE")
        return False

    print("Alert FK: OK")
    return True


def print_counts(db) -> None:
    print(f"Alerts total: {count_alerts(db)}")
    print(f"Active alerts: {count_alerts(db, is_active=True)}")
    print(f"Inactive alerts: {count_alerts(db, is_active=False)}")
    print(f"Alert duplicates: {count_duplicate_alerts(db)}")
    print(f"Alert orphans: {count_orphans(db)}")
    if count_duplicate_alerts(db) != 0 or count_orphans(db) != 0:
        raise RuntimeError("Incoherence detectee dans les alertes existantes.")


def check_alert_creation_rules(db, vulnerability: Vulnerability) -> bool:
    affected_product = select_netty_affected_product(vulnerability)
    if affected_product is None:
        print("Alert rules: FAILED (produit Netty introuvable)")
        return False

    vulnerable_version = choose_vulnerable_version(affected_product)
    safe_version = choose_safe_version(affected_product)
    if vulnerable_version is None or safe_version is None:
        print("Alert rules: FAILED (bornes Netty insuffisantes)")
        return False

    if not check_match_creates_alert(db, vulnerability, vulnerable_version):
        return False
    if not check_possible_match_refused(db, vulnerability):
        return False
    if not check_no_match_refused(db, vulnerability, vulnerable_version, safe_version):
        return False
    if not check_inactive_asset_refused(db, vulnerability):
        return False

    print("Alert creation rules: OK")
    return True


def check_match_creates_alert(db, vulnerability: Vulnerability, vulnerable_version: str) -> bool:
    asset = create_test_asset(db, "MATCH", "Netty", "Netty", vulnerable_version)
    evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    correlation = get_pair_correlation(db, asset.id, vulnerability.id)

    alert = create_alert_from_correlation(db, correlation.id)
    if alert is None:
        print("Creation depuis MATCH: FAILED")
        return False

    if (
        alert.status != AlertStatus.NEW
        or alert.severity != AlertSeverity(vulnerability.cvss_severity)
        or alert.source != "CORRELATION"
        or not alert.is_active
        or alert.first_detected_at != correlation.first_detected_at
    ):
        print("Creation depuis MATCH: FAILED")
        return False

    original_first_detected_at = alert.first_detected_at
    original_last_seen_at = alert.last_seen_at
    correlation.last_evaluated_at = original_last_seen_at + timedelta(minutes=5)
    alert_again = create_alert_from_correlation(db, correlation.id)

    if alert_again.id != alert.id:
        print("Reevaluation MATCH: FAILED (doublon)")
        return False
    if count_alerts_for_correlation(db, correlation.id) != 1:
        print("Anti-doublon: FAILED")
        return False
    if alert_again.first_detected_at != original_first_detected_at:
        print("Reevaluation MATCH: FAILED (first_detected_at ecrase)")
        return False
    if alert_again.last_seen_at <= original_last_seen_at:
        print("Reevaluation MATCH: FAILED (last_seen_at non mis a jour)")
        return False

    print("Creation depuis MATCH: OK")
    print("Reevaluation MATCH sans doublon: OK")
    print("last_seen_at update: OK")
    return True


def check_possible_match_refused(db, vulnerability: Vulnerability) -> bool:
    asset = create_test_asset(db, "POSSIBLE", "Netty", "Netty", None)
    evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    correlation = get_pair_correlation(db, asset.id, vulnerability.id)

    alert = create_alert_from_correlation(db, correlation.id)
    if alert is not None or count_alerts_for_correlation(db, correlation.id) != 0:
        print("POSSIBLE_MATCH refuse: FAILED")
        return False

    print("POSSIBLE_MATCH refuse: OK")
    return True


def check_no_match_refused(
    db,
    vulnerability: Vulnerability,
    vulnerable_version: str,
    safe_version: str,
) -> bool:
    asset = create_test_asset(db, "NO-MATCH", "Netty", "Netty", safe_version)
    correlation = AssetVulnerabilityCorrelation(
        asset_id=asset.id,
        vulnerability_id=vulnerability.id,
        status=CorrelationPersistenceStatus.NO_MATCH,
        reason="Correlation NO_MATCH de test.",
        first_detected_at=utcnow_naive(),
        last_evaluated_at=utcnow_naive(),
        is_active=False,
    )
    db.add(correlation)
    db.flush()

    alert = create_alert_from_correlation(db, correlation.id)
    if alert is not None or count_alerts_for_correlation(db, correlation.id) != 0:
        print("NO_MATCH refuse: FAILED")
        return False

    print("NO_MATCH refuse: OK")
    return True


def check_inactive_asset_refused(db, vulnerability: Vulnerability) -> bool:
    asset = create_test_asset(db, "INACTIVE-ASSET", "Netty", "Netty", "4.1.124")
    asset.is_active = False
    correlation = AssetVulnerabilityCorrelation(
        asset_id=asset.id,
        vulnerability_id=vulnerability.id,
        status=CorrelationPersistenceStatus.MATCH,
        reason="Correlation MATCH de test sur actif inactif.",
        first_detected_at=utcnow_naive(),
        last_evaluated_at=utcnow_naive(),
        is_active=True,
    )
    db.add(correlation)
    db.flush()

    alert = create_alert_from_correlation(db, correlation.id)
    if alert is not None or count_alerts_for_correlation(db, correlation.id) != 0:
        print("Actif inactif refuse: FAILED")
        return False

    print("Actif inactif refuse: OK")
    return True


def check_list_alerts(db) -> bool:
    result = list_alerts(db, search="TEST-ALERT-MATCH", status="NEW", is_active="active")
    if result.total < 1 or not result.items:
        print("list_alerts: FAILED")
        return False

    alert_item = result.items[0]
    checks = [
        list_alerts(db, severity=alert_item.alert.severity.value).total >= 1,
        list_alerts(db, asset=alert_item.asset.name).total >= 1,
        list_alerts(db, cve=alert_item.vulnerability.cve_id).total >= 1,
        list_alerts(db, per_page=1).per_page == 1,
    ]
    if not all(checks):
        print("list_alerts filters: FAILED")
        return False

    print("list_alerts: OK")
    return True


def load_test_vulnerability(db) -> Vulnerability | None:
    return db.execute(
        select(Vulnerability)
        .options(selectinload(Vulnerability.affected_products))
        .where(Vulnerability.cve_id == TEST_CVE_ID)
    ).scalar_one_or_none()


def create_test_asset(
    db,
    suffix: str,
    vendor: str | None,
    product: str | None,
    product_version: str | None,
) -> Asset:
    asset = Asset(
        name=f"TEST-ALERT-{suffix}",
        asset_type=AssetType.APPLICATION,
        vendor=vendor,
        product=product,
        product_version=product_version,
        criticality=AssetCriticality.HIGH,
        environment=AssetEnvironment.TEST,
        is_active=True,
    )
    db.add(asset)
    db.flush()
    return asset


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


def count_alerts(db, is_active: bool | None = None) -> int:
    statement = select(func.count(Alert.id))
    if is_active is not None:
        statement = statement.where(Alert.is_active == is_active)
    return db.scalar(statement) or 0


def count_alerts_for_correlation(db, correlation_id: str) -> int:
    return (
        db.scalar(select(func.count(Alert.id)).where(Alert.correlation_id == correlation_id))
        or 0
    )


def count_duplicate_alerts(db) -> int:
    grouped = (
        select(Alert.correlation_id)
        .group_by(Alert.correlation_id)
        .having(func.count(Alert.id) > 1)
        .subquery()
    )
    return db.scalar(select(func.count()).select_from(grouped)) or 0


def count_orphans(db) -> int:
    correlation_orphans = (
        db.scalar(
            select(func.count(Alert.id))
            .select_from(Alert)
            .outerjoin(
                AssetVulnerabilityCorrelation,
                Alert.correlation_id == AssetVulnerabilityCorrelation.id,
            )
            .where(AssetVulnerabilityCorrelation.id.is_(None))
        )
        or 0
    )
    asset_orphans = (
        db.scalar(
            select(func.count(Alert.id))
            .select_from(Alert)
            .outerjoin(Asset, Alert.asset_id == Asset.id)
            .where(Asset.id.is_(None))
        )
        or 0
    )
    vulnerability_orphans = (
        db.scalar(
            select(func.count(Alert.id))
            .select_from(Alert)
            .outerjoin(Vulnerability, Alert.vulnerability_id == Vulnerability.id)
            .where(Vulnerability.id.is_(None))
        )
        or 0
    )
    return correlation_orphans + asset_orphans + vulnerability_orphans


def select_netty_affected_product(
    vulnerability: Vulnerability,
) -> VulnerabilityAffectedProduct | None:
    for affected_product in vulnerability.affected_products:
        if (
            affected_product.vulnerable is True
            and (affected_product.vendor or "").lower() == "netty"
            and (affected_product.product or "").lower() == "netty"
        ):
            return affected_product
    return None


def choose_vulnerable_version(
    affected_product: VulnerabilityAffectedProduct,
) -> str | None:
    if affected_product.version_start_including:
        return affected_product.version_start_including
    if affected_product.version_start_excluding:
        return increment_last_numeric_segment(affected_product.version_start_excluding)
    if affected_product.version_end_including:
        return affected_product.version_end_including
    if affected_product.version_end_excluding:
        return decrement_last_numeric_segment(affected_product.version_end_excluding)
    if affected_product.version and affected_product.version not in {"*", "-"}:
        return affected_product.version
    return None


def choose_safe_version(
    affected_product: VulnerabilityAffectedProduct,
) -> str | None:
    if affected_product.version_end_excluding:
        return affected_product.version_end_excluding
    if affected_product.version_end_including:
        return increment_last_numeric_segment(affected_product.version_end_including)
    if affected_product.version_start_excluding:
        return affected_product.version_start_excluding
    if affected_product.version_start_including:
        return decrement_last_numeric_segment(affected_product.version_start_including)
    return "9999.0.0"


def increment_last_numeric_segment(version: str) -> str | None:
    return adjust_last_numeric_segment(version, 1)


def decrement_last_numeric_segment(version: str) -> str | None:
    return adjust_last_numeric_segment(version, -1)


def adjust_last_numeric_segment(version: str, delta: int) -> str | None:
    parts = version.split(".")
    for index in range(len(parts) - 1, -1, -1):
        if parts[index].isdigit():
            adjusted = int(parts[index]) + delta
            if adjusted < 0:
                return None
            parts[index] = str(adjusted)
            return ".".join(parts)
    return None


def utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


if __name__ == "__main__":
    raise SystemExit(main())

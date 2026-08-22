"""
Verification locale de la phase 4.3.2.

Le script controle la structure de la table puis teste la persistance dans une
transaction annulee a la fin. Aucun actif ou match de test ne reste en base.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import func, inspect, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, engine, get_safe_database_url, test_database_connection
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType
from app.models.asset_vulnerability_correlation import (
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.vulnerability import Vulnerability
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct
from app.services.correlation_persistence_service import (
    evaluate_and_persist_asset_vulnerability,
    persist_correlation_result,
)
from app.services.correlation_service import CorrelationStatus, evaluate_asset_vulnerability


TEST_CVE_ID = "CVE-2025-58057"

EXPECTED_COLUMNS = {
    "id",
    "asset_id",
    "vulnerability_id",
    "status",
    "reason",
    "matched_affected_product_id",
    "vendor_result",
    "product_result",
    "version_result",
    "cpe_result",
    "first_detected_at",
    "last_evaluated_at",
    "is_active",
    "created_at",
    "updated_at",
}

EXPECTED_INDEXES = {
    "ix_asset_vulnerability_correlations_asset_id",
    "ix_asset_vulnerability_correlations_vulnerability_id",
    "ix_asset_vulnerability_correlations_status",
    "ix_asset_vulnerability_correlations_is_active",
}

EXPECTED_UNIQUE_CONSTRAINT = (
    "uq_asset_vulnerability_correlations_asset_vulnerability"
)


def main() -> int:
    print(
        "Verification phase 4.3 persistance correlations avec "
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

            if not check_real_assets_do_not_create_correlations(db, vulnerability):
                return 1
            if not check_persistence_rules(db, vulnerability):
                return 1

            db.rollback()

        print("PHASE 4.3 CORRELATION PERSISTENCE CHECK: OK")
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
    if "asset_vulnerability_correlations" not in tables:
        print("Correlation table: MANQUANTE")
        return False

    columns = {
        column["name"]
        for column in inspector.get_columns("asset_vulnerability_correlations")
    }
    missing_columns = EXPECTED_COLUMNS - columns
    if missing_columns:
        print(
            "Correlation table: INCOMPLETE, colonnes manquantes: "
            + ", ".join(sorted(missing_columns))
        )
        return False

    if not check_foreign_keys(inspector):
        return False

    indexes = {
        index["name"]
        for index in inspector.get_indexes("asset_vulnerability_correlations")
        if index.get("name")
    }
    missing_indexes = EXPECTED_INDEXES - indexes
    if missing_indexes:
        print(
            "Correlation table: index manquants: "
            + ", ".join(sorted(missing_indexes))
        )
        return False

    unique_constraints = {
        constraint["name"]
        for constraint in inspector.get_unique_constraints(
            "asset_vulnerability_correlations"
        )
        if constraint.get("name")
    }
    if EXPECTED_UNIQUE_CONSTRAINT not in unique_constraints:
        print("Correlation table: contrainte unique manquante")
        return False

    print("Correlation table: OK")
    return True


def check_foreign_keys(inspector) -> bool:
    expected = {
        ("asset_id", "assets", "id"),
        ("vulnerability_id", "vulnerabilities", "id"),
        (
            "matched_affected_product_id",
            "vulnerability_affected_products",
            "id",
        ),
    }
    found = set()

    for foreign_key in inspector.get_foreign_keys("asset_vulnerability_correlations"):
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
        print("Correlation FK: MANQUANTE")
        return False

    print("Correlation FK: OK")
    return True


def print_counts(db) -> None:
    print(f"Correlation total: {count_correlations(db)}")
    print(f"Active correlations: {count_correlations(db, is_active=True)}")
    print(f"Inactive correlations: {count_correlations(db, is_active=False)}")
    print(f"Duplicates: {count_duplicates(db)}")
    print(f"Orphans: {count_orphans(db)}")

    if count_duplicates(db) != 0 or count_orphans(db) != 0:
        raise RuntimeError("Incoherence detectee dans les correlations existantes.")


def load_test_vulnerability(db) -> Vulnerability | None:
    return db.execute(
        select(Vulnerability)
        .options(selectinload(Vulnerability.affected_products))
        .where(Vulnerability.cve_id == TEST_CVE_ID)
    ).scalar_one_or_none()


def check_real_assets_do_not_create_correlations(db, vulnerability: Vulnerability) -> bool:
    real_assets = (
        db.execute(select(Asset).where(Asset.is_active.is_(True)).order_by(Asset.name))
        .scalars()
        .all()
    )
    before_count = count_correlations(db)

    print("Real assets controlled test:")
    for asset in real_assets:
        result = evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
        print(f"- {asset.name} -> {result.status.value}")

    after_count = count_correlations(db)
    if after_count != before_count:
        print("Real assets controlled test: FAILED (ligne inattendue creee)")
        return False

    print("Real assets controlled test: OK")
    return True


def check_persistence_rules(db, vulnerability: Vulnerability) -> bool:
    netty_product = select_netty_affected_product(vulnerability)
    if netty_product is None:
        print("Persistence rules: FAILED (produit Netty introuvable)")
        return False

    vulnerable_version = choose_vulnerable_version(netty_product)
    safe_version = choose_safe_version(netty_product)
    if vulnerable_version is None or safe_version is None:
        print("Persistence rules: FAILED (bornes Netty insuffisantes)")
        return False

    if not check_match_creation_and_idempotence(
        db, vulnerability, vulnerable_version
    ):
        return False
    if not check_possible_to_match_upgrade(db, vulnerability, vulnerable_version):
        return False
    if not check_no_match_deactivation(db, vulnerability, vulnerable_version, safe_version):
        return False
    if not check_unknown_keeps_active(db, vulnerability, vulnerable_version):
        return False

    print("Persistence rules: OK")
    return True


def check_match_creation_and_idempotence(
    db,
    vulnerability: Vulnerability,
    vulnerable_version: str,
) -> bool:
    asset = create_test_asset(db, "MATCH", "Netty", "Netty", vulnerable_version)
    result = evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    if result.status != CorrelationStatus.MATCH:
        print("Creation MATCH: FAILED")
        return False

    correlation = get_pair_correlation(db, asset.id, vulnerability.id)
    if correlation is None or correlation.status != CorrelationPersistenceStatus.MATCH:
        print("Creation MATCH: FAILED")
        return False
    first_detected_at = correlation.first_detected_at

    evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    if count_pair_correlations(db, asset.id, vulnerability.id) != 1:
        print("Reevaluation MATCH: FAILED (doublon)")
        return False

    correlation = get_pair_correlation(db, asset.id, vulnerability.id)
    if correlation.first_detected_at != first_detected_at:
        print("Reevaluation MATCH: FAILED (first_detected_at ecrase)")
        return False

    print("Creation MATCH: OK")
    print("Reevaluation MATCH: OK")
    return True


def check_possible_to_match_upgrade(
    db,
    vulnerability: Vulnerability,
    vulnerable_version: str,
) -> bool:
    asset = create_test_asset(db, "UPGRADE", "Netty", "Netty", None)
    result = evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    if result.status != CorrelationStatus.POSSIBLE_MATCH:
        print("Upgrade POSSIBLE_MATCH -> MATCH: FAILED (etat initial)")
        return False

    correlation = get_pair_correlation(db, asset.id, vulnerability.id)
    if (
        correlation is None
        or correlation.status != CorrelationPersistenceStatus.POSSIBLE_MATCH
        or not correlation.is_active
    ):
        print("Upgrade POSSIBLE_MATCH -> MATCH: FAILED (ligne initiale)")
        return False

    asset.product_version = vulnerable_version
    result = evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    correlation = get_pair_correlation(db, asset.id, vulnerability.id)
    if (
        result.status != CorrelationStatus.MATCH
        or correlation.status != CorrelationPersistenceStatus.MATCH
        or count_pair_correlations(db, asset.id, vulnerability.id) != 1
    ):
        print("Upgrade POSSIBLE_MATCH -> MATCH: FAILED")
        return False

    print("Upgrade POSSIBLE_MATCH -> MATCH: OK")
    return True


def check_no_match_deactivation(
    db,
    vulnerability: Vulnerability,
    vulnerable_version: str,
    safe_version: str,
) -> bool:
    asset = create_test_asset(db, "NO-MATCH", "Netty", "Netty", vulnerable_version)
    evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)

    asset.product_version = safe_version
    result = evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
    correlation = get_pair_correlation(db, asset.id, vulnerability.id)
    if (
        result.status != CorrelationStatus.NO_MATCH
        or correlation is None
        or correlation.status != CorrelationPersistenceStatus.NO_MATCH
        or correlation.is_active
    ):
        print("NO_MATCH apres MATCH: FAILED")
        return False

    print("NO_MATCH apres MATCH: OK")
    return True


def check_unknown_keeps_active(
    db,
    vulnerability: Vulnerability,
    vulnerable_version: str,
) -> bool:
    asset = create_test_asset(db, "UNKNOWN", "Netty", "Netty", vulnerable_version)
    evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)

    correlation = get_pair_correlation(db, asset.id, vulnerability.id)
    previous_status = correlation.status
    previous_reason = correlation.reason
    previous_last_evaluated_at = correlation.last_evaluated_at

    asset.vendor = None
    asset.product = None
    asset.product_version = None
    asset.cpe = None
    result = evaluate_asset_vulnerability(asset, vulnerability)
    if result.status != CorrelationStatus.UNKNOWN:
        print("UNKNOWN: FAILED (etat attendu non obtenu)")
        return False

    persist_correlation_result(db, result)
    correlation = get_pair_correlation(db, asset.id, vulnerability.id)
    if (
        correlation.status != previous_status
        or correlation.reason != previous_reason
        or correlation.last_evaluated_at != previous_last_evaluated_at
        or not correlation.is_active
    ):
        print("UNKNOWN: FAILED (correlation active modifiee)")
        return False

    print("UNKNOWN ne desactive pas: OK")
    return True


def create_test_asset(
    db,
    suffix: str,
    vendor: str | None,
    product: str | None,
    product_version: str | None,
) -> Asset:
    asset = Asset(
        name=f"TEST-CORR-{suffix}",
        asset_type=AssetType.APPLICATION,
        vendor=vendor,
        product=product,
        product_version=product_version,
        criticality=AssetCriticality.MEDIUM,
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


def count_pair_correlations(db, asset_id: str, vulnerability_id: str) -> int:
    return (
        db.scalar(
            select(func.count(AssetVulnerabilityCorrelation.id)).where(
                AssetVulnerabilityCorrelation.asset_id == asset_id,
                AssetVulnerabilityCorrelation.vulnerability_id == vulnerability_id,
            )
        )
        or 0
    )


def count_correlations(db, is_active: bool | None = None) -> int:
    statement = select(func.count(AssetVulnerabilityCorrelation.id))
    if is_active is not None:
        statement = statement.where(AssetVulnerabilityCorrelation.is_active == is_active)
    return db.scalar(statement) or 0


def count_duplicates(db) -> int:
    grouped = (
        select(
            AssetVulnerabilityCorrelation.asset_id,
            AssetVulnerabilityCorrelation.vulnerability_id,
        )
        .group_by(
            AssetVulnerabilityCorrelation.asset_id,
            AssetVulnerabilityCorrelation.vulnerability_id,
        )
        .having(func.count(AssetVulnerabilityCorrelation.id) > 1)
        .subquery()
    )
    return db.scalar(select(func.count()).select_from(grouped)) or 0


def count_orphans(db) -> int:
    asset_orphans = (
        db.scalar(
            select(func.count(AssetVulnerabilityCorrelation.id))
            .select_from(AssetVulnerabilityCorrelation)
            .outerjoin(Asset, AssetVulnerabilityCorrelation.asset_id == Asset.id)
            .where(Asset.id.is_(None))
        )
        or 0
    )
    vulnerability_orphans = (
        db.scalar(
            select(func.count(AssetVulnerabilityCorrelation.id))
            .select_from(AssetVulnerabilityCorrelation)
            .outerjoin(
                Vulnerability,
                AssetVulnerabilityCorrelation.vulnerability_id == Vulnerability.id,
            )
            .where(Vulnerability.id.is_(None))
        )
        or 0
    )
    affected_product_orphans = (
        db.scalar(
            select(func.count(AssetVulnerabilityCorrelation.id))
            .select_from(AssetVulnerabilityCorrelation)
            .outerjoin(
                VulnerabilityAffectedProduct,
                AssetVulnerabilityCorrelation.matched_affected_product_id
                == VulnerabilityAffectedProduct.id,
            )
            .where(
                AssetVulnerabilityCorrelation.matched_affected_product_id.is_not(None),
                VulnerabilityAffectedProduct.id.is_(None),
            )
        )
        or 0
    )
    return asset_orphans + vulnerability_orphans + affected_product_orphans


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


if __name__ == "__main__":
    raise SystemExit(main())

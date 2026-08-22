"""
Verification locale de la phase 4.4.1.

Le script teste les fonctions de lecture utilisees par les pages detail avec
une correlation temporaire annulee par rollback final.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, get_safe_database_url, test_database_connection
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType
from app.models.asset_vulnerability_correlation import CorrelationPersistenceStatus
from app.models.vulnerability import Vulnerability
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct
from app.services.correlation_persistence_service import (
    evaluate_and_persist_asset_vulnerability,
)
from app.services.correlation_query_service import (
    get_correlations_for_asset,
    get_correlations_for_vulnerability,
)


TEST_CVE_ID = "CVE-2025-58057"


def main() -> int:
    print(
        "Verification phase 4.4 correlation UI data avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        with SessionLocal() as db:
            vulnerability = load_test_vulnerability(db)
            if vulnerability is None:
                print(f"CVE de test introuvable: {TEST_CVE_ID}")
                return 1

            affected_product = select_netty_affected_product(vulnerability)
            if affected_product is None:
                print("UI data check: FAILED (produit Netty introuvable)")
                return 1

            vulnerable_version = choose_vulnerable_version(affected_product)
            if vulnerable_version is None:
                print("UI data check: FAILED (version vulnerable introuvable)")
                return 1

            asset = create_test_asset(db, vulnerable_version)
            result = evaluate_and_persist_asset_vulnerability(db, asset, vulnerability)
            if result.status.value != "MATCH":
                print("UI data check: FAILED (MATCH attendu)")
                return 1

            asset_correlations = get_correlations_for_asset(db, asset.id)
            vulnerability_correlations = get_correlations_for_vulnerability(
                db,
                vulnerability.id,
            )

            print(f"Temporary asset: {asset.name}")
            print(f"Asset correlations returned: {len(asset_correlations)}")
            print(
                "Vulnerability correlations returned: "
                f"{len(vulnerability_correlations)}"
            )

            if not asset_correlations:
                print("UI data check: FAILED (asset correlations vides)")
                return 1
            if not any(item.asset_id == asset.id for item in vulnerability_correlations):
                print("UI data check: FAILED (vulnerability correlations incompletes)")
                return 1

            asset_view = asset_correlations[0]
            if (
                asset_view.cve_id != TEST_CVE_ID
                or asset_view.status != CorrelationPersistenceStatus.MATCH
                or not asset_view.is_active
            ):
                print("UI data check: FAILED (donnees asset incorrectes)")
                return 1

            vulnerability_view = next(
                item for item in vulnerability_correlations if item.asset_id == asset.id
            )
            if (
                vulnerability_view.asset_name != asset.name
                or vulnerability_view.status != CorrelationPersistenceStatus.MATCH
                or not vulnerability_view.is_active
            ):
                print("UI data check: FAILED (donnees vulnerability incorrectes)")
                return 1

            db.rollback()

        print("PHASE 4.4 CORRELATION UI DATA CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR PostgreSQL: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def load_test_vulnerability(db) -> Vulnerability | None:
    return db.execute(
        select(Vulnerability)
        .options(selectinload(Vulnerability.affected_products))
        .where(Vulnerability.cve_id == TEST_CVE_ID)
    ).scalar_one_or_none()


def create_test_asset(db, product_version: str) -> Asset:
    asset = Asset(
        name="TEST-CORR-UI-NETTY",
        asset_type=AssetType.APPLICATION,
        vendor="Netty",
        product="Netty",
        product_version=product_version,
        criticality=AssetCriticality.MEDIUM,
        environment=AssetEnvironment.TEST,
        is_active=True,
    )
    db.add(asset)
    db.flush()
    return asset


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

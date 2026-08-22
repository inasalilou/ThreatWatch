"""
Verification locale de la phase 4.1.1.

Le script controle la table assets, les enums et le service metier. Les tests
de creation/modification sont executes dans une transaction annulee a la fin.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import func, inspect, select
from sqlalchemy.exc import SQLAlchemyError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, engine, get_safe_database_url, test_database_connection
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType
from app.services.asset_service import (
    AssetValidationError,
    create_asset,
    disable_asset,
    enable_asset,
    list_assets,
    update_asset,
)


EXPECTED_COLUMNS = {
    "id",
    "name",
    "hostname",
    "ip_address",
    "asset_type",
    "vendor",
    "product",
    "product_version",
    "operating_system",
    "os_version",
    "criticality",
    "environment",
    "owner",
    "location",
    "cpe",
    "description",
    "is_active",
    "created_at",
    "updated_at",
}

EXPECTED_INDEXES = {
    "ix_assets_name",
    "ix_assets_asset_type",
    "ix_assets_criticality",
    "ix_assets_environment",
    "ix_assets_is_active",
    "ix_assets_vendor_product",
    "ix_assets_cpe",
}


def main() -> int:
    print(
        "Verification phase 4.1 actifs avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        if not check_table_structure():
            return 1
        if not check_enums():
            return 1

        with SessionLocal() as db:
            total_assets = count_assets(db)
            active_assets = count_assets(db, is_active=True)
            inactive_assets = count_assets(db, is_active=False)
            result = list_assets(db=db, page=1, per_page=5)

            print(f"Assets total: {total_assets}")
            print(f"Assets actifs: {active_assets}")
            print(f"Assets inactifs: {inactive_assets}")
            print(
                "Asset service query: "
                + ("OK" if result.total == total_assets else "FAILED")
            )
            if result.total != total_assets:
                return 1

        if not check_service_validation():
            return 1

        print("PHASE 4.1 ASSETS CHECK: OK")
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
    if "assets" not in tables:
        print("Asset table: MANQUANTE")
        return False

    columns = {column["name"] for column in inspector.get_columns("assets")}
    missing_columns = EXPECTED_COLUMNS - columns
    if missing_columns:
        print(
            "Asset table: INCOMPLETE, colonnes manquantes: "
            + ", ".join(sorted(missing_columns))
        )
        return False

    indexes = {
        index["name"]
        for index in inspector.get_indexes("assets")
        if index.get("name")
    }
    missing_indexes = EXPECTED_INDEXES - indexes
    if missing_indexes:
        print(
            "Asset table: index manquants: "
            + ", ".join(sorted(missing_indexes))
        )
        return False

    print("Asset table: OK")
    return True


def check_enums() -> bool:
    success = (
        AssetType.SERVER.value == "SERVER"
        and AssetCriticality.MEDIUM.value == "MEDIUM"
        and AssetEnvironment.PRODUCTION.value == "PRODUCTION"
    )
    print("Asset enums: " + ("OK" if success else "FAILED"))
    return success


def count_assets(db, is_active: bool | None = None) -> int:
    statement = select(func.count(Asset.id))
    if is_active is not None:
        statement = statement.where(Asset.is_active == is_active)
    return db.scalar(statement) or 0


def check_service_validation() -> bool:
    with SessionLocal() as db:
        try:
            asset = create_asset(
                db,
                name="Phase 4.1 rollback asset",
                asset_type=AssetType.SERVER,
                hostname=" srv-test-01 ",
                ip_address="192.168.1.10",
                vendor=" Microsoft ",
                product=" Windows Server ",
                product_version="2022",
            )
            if asset.name != "Phase 4.1 rollback asset":
                print("Asset service validation: FAILED")
                return False
            if asset.hostname != "srv-test-01" or asset.ip_address != "192.168.1.10":
                print("Asset service validation: FAILED")
                return False
            if asset.criticality != AssetCriticality.MEDIUM:
                print("Asset service validation: FAILED")
                return False
            if asset.environment != AssetEnvironment.PRODUCTION:
                print("Asset service validation: FAILED")
                return False
            if asset.is_active is not True:
                print("Asset service validation: FAILED")
                return False

            updated = update_asset(
                db,
                asset.id,
                name="Phase 4.1 rollback asset updated",
                criticality="HIGH",
                environment="TEST",
            )
            if updated is None or updated.created_at != asset.created_at:
                print("Asset service validation: FAILED")
                return False
            if updated.criticality != AssetCriticality.HIGH:
                print("Asset service validation: FAILED")
                return False

            disabled = disable_asset(db, asset.id)
            if disabled is None or disabled.is_active is not False:
                print("Asset service validation: FAILED")
                return False

            enabled = enable_asset(db, asset.id)
            if enabled is None or enabled.is_active is not True:
                print("Asset service validation: FAILED")
                return False

            if not rejects_invalid_values(db):
                return False

            print("Asset service validation: OK")
            return True
        finally:
            db.rollback()


def rejects_invalid_values(db) -> bool:
    checks = [
        (
            "IP invalide",
            lambda: create_asset(
                db,
                name="Invalid IP",
                asset_type=AssetType.SERVER,
                ip_address="999.999.999.999",
            ),
        ),
        (
            "name vide",
            lambda: create_asset(db, name="   ", asset_type=AssetType.SERVER),
        ),
        (
            "asset_type invalide",
            lambda: create_asset(db, name="Invalid type", asset_type="BAD_TYPE"),
        ),
        (
            "criticality invalide",
            lambda: create_asset(
                db,
                name="Invalid criticality",
                asset_type=AssetType.SERVER,
                criticality="URGENT",
            ),
        ),
        (
            "environment invalide",
            lambda: create_asset(
                db,
                name="Invalid environment",
                asset_type=AssetType.SERVER,
                environment="STAGING",
            ),
        ),
    ]

    for label, action in checks:
        try:
            action()
        except AssetValidationError:
            continue
        print(f"Asset service validation: FAILED ({label} accepte)")
        return False

    return True


if __name__ == "__main__":
    raise SystemExit(main())

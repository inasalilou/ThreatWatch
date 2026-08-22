"""
Verification locale de la phase 4.4.2.

Controle la liste globale des correlations, ses filtres, la pagination et la
route /correlations. Les donnees positives sont creees dans une transaction
annulee a la fin.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload
from starlette.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.core.deps import require_authenticated_user
from app.db.database import SessionLocal, get_safe_database_url, test_database_connection
from app.main import app
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType
from app.models.asset_vulnerability_correlation import AssetVulnerabilityCorrelation
from app.models.user import RoleUtilisateur, Utilisateur
from app.models.vulnerability import Vulnerability
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct
from app.services.correlation_persistence_service import (
    evaluate_and_persist_asset_vulnerability,
)
from app.services.correlation_query_service import (
    get_correlation_stats,
    list_correlations,
)


TEST_CVE_ID = "CVE-2025-58057"


def main() -> int:
    print(
        "Verification phase 4.4 page correlations avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        with SessionLocal() as db:
            if not check_empty_behavior(db):
                return 1

            vulnerability = load_test_vulnerability(db)
            if vulnerability is None:
                print(f"CVE de test introuvable: {TEST_CVE_ID}")
                return 1

            if not check_positive_listing_with_rollback(db, vulnerability):
                return 1
            if count_duplicates(db) != 0:
                print("Duplicates: FAILED")
                return 1

            db.rollback()

        if not check_route_access():
            return 1

        print("PHASE 4.4 CORRELATIONS PAGE CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR PostgreSQL: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def check_empty_behavior(db) -> bool:
    result = list_correlations(db)
    stats = get_correlation_stats(db)
    duplicates = count_duplicates(db)

    print(f"Current correlations: {result.total}")
    print(f"Current active MATCH: {stats.active_match}")
    print(f"Current active POSSIBLE_MATCH: {stats.active_possible_match}")
    print(f"Current inactive correlations: {stats.inactive_correlations}")
    print(f"Duplicates: {duplicates}")

    if duplicates != 0:
        return False
    if result.page != 1 or result.total_pages < 1:
        print("Empty behavior: FAILED")
        return False

    print("Empty behavior: OK")
    return True


def check_positive_listing_with_rollback(db, vulnerability: Vulnerability) -> bool:
    affected_product = select_netty_affected_product(vulnerability)
    if affected_product is None:
        print("Positive listing: FAILED (produit Netty introuvable)")
        return False

    vulnerable_version = choose_vulnerable_version(affected_product)
    safe_version = choose_safe_version(affected_product)
    if vulnerable_version is None or safe_version is None:
        print("Positive listing: FAILED (bornes Netty insuffisantes)")
        return False

    match_asset = create_test_asset(
        db,
        suffix="MATCH",
        vendor="Netty",
        product="Netty",
        product_version=vulnerable_version,
        criticality=AssetCriticality.CRITICAL,
        environment=AssetEnvironment.PRODUCTION,
    )
    inactive_asset = create_test_asset(
        db,
        suffix="INACTIVE-HISTORY",
        vendor="Netty",
        product="Netty",
        product_version=vulnerable_version,
        criticality=AssetCriticality.HIGH,
        environment=AssetEnvironment.TEST,
    )

    evaluate_and_persist_asset_vulnerability(db, match_asset, vulnerability)
    evaluate_and_persist_asset_vulnerability(db, inactive_asset, vulnerability)
    inactive_asset.product_version = safe_version
    evaluate_and_persist_asset_vulnerability(db, inactive_asset, vulnerability)

    checks = [
        (
            "list default",
            lambda: list_correlations(db).total >= 1,
        ),
        (
            "search",
            lambda: any(
                item.asset_id == match_asset.id
                for item in list_correlations(db, query="TEST-CORR-PAGE-MATCH").items
            ),
        ),
        (
            "status MATCH",
            lambda: all(
                item.status.value == "MATCH"
                for item in list_correlations(db, status="MATCH").items
            ),
        ),
        (
            "criticality",
            lambda: any(
                item.asset_id == match_asset.id
                for item in list_correlations(db, criticality="CRITICAL").items
            ),
        ),
        (
            "environment",
            lambda: any(
                item.asset_id == match_asset.id
                for item in list_correlations(db, environment="PRODUCTION").items
            ),
        ),
        (
            "cvss",
            lambda: list_correlations(
                db,
                cvss_severity=vulnerability.cvss_severity or "",
            ).total
            >= 1,
        ),
        (
            "inactive",
            lambda: any(
                item.asset_id == inactive_asset.id
                for item in list_correlations(db, activity="inactive").items
            ),
        ),
        (
            "pagination",
            lambda: list_correlations(db, per_page=1).per_page == 1
            and list_correlations(db, per_page=1).total_pages >= 1,
        ),
    ]

    for label, check in checks:
        if not check():
            print(f"Positive listing: FAILED ({label})")
            return False

    stats = get_correlation_stats(db)
    if stats.active_match < 1 or stats.inactive_correlations < 1:
        print("Counters: FAILED")
        return False

    print("Positive listing with rollback: OK")
    print("Counters: OK")
    return True


def check_route_access() -> bool:
    client = TestClient(app, follow_redirects=False)
    response = client.get("/correlations")
    if response.status_code != 303 or "/login" not in response.headers.get(
        "location",
        "",
    ):
        print("Route unauthenticated: FAILED")
        return False

    admin = build_user("Admin Route", RoleUtilisateur.ADMIN)
    if not route_with_user_returns_200(admin):
        print("Route ADMIN: FAILED")
        return False

    analyst = build_user("Analyste Route", RoleUtilisateur.ANALYSTE)
    if not route_with_user_returns_200(analyst):
        print("Route ANALYSTE: FAILED")
        return False

    print("Route unauthenticated redirect: OK")
    print("Route ADMIN: OK")
    print("Route ANALYSTE: OK")
    return True


def route_with_user_returns_200(user: Utilisateur) -> bool:
    app.dependency_overrides[require_authenticated_user] = lambda: user
    try:
        client = TestClient(app, follow_redirects=False)
        response = client.get("/correlations")
        return response.status_code == 200
    finally:
        app.dependency_overrides.pop(require_authenticated_user, None)


def build_user(name: str, role: RoleUtilisateur) -> Utilisateur:
    return Utilisateur(
        id=f"route-{role.value.lower()}",
        nom=name,
        email=f"{role.value.lower()}@example.test",
        mot_de_passe_hash="not-used",
        role=role,
        actif=True,
    )


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
    criticality: AssetCriticality,
    environment: AssetEnvironment,
) -> Asset:
    asset = Asset(
        name=f"TEST-CORR-PAGE-{suffix}",
        asset_type=AssetType.APPLICATION,
        vendor=vendor,
        product=product,
        product_version=product_version,
        criticality=criticality,
        environment=environment,
        is_active=True,
    )
    db.add(asset)
    db.flush()
    return asset


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

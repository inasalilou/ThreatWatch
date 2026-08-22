"""
Verification locale de la phase 4.3.1.

Le script evalue une seule CVE contre les actifs actifs puis execute quelques
tests synthetiques en memoire. Aucune donnee n'est inseree ou modifiee.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, get_safe_database_url, test_database_connection
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType
from app.models.vulnerability import Vulnerability
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct
from app.services.correlation_service import (
    CorrelationStatus,
    AssetVulnerabilityCorrelationResult,
    correlate_vulnerability,
    evaluate_asset_vulnerability,
)


DEFAULT_CVE_ID = "CVE-2025-58057"


def main() -> int:
    cve_id = normalize_cve_arg()
    print(
        "Verification phase 4.3 correlation avec "
        f"DATABASE_URL={get_safe_database_url()}"
    )

    try:
        test_database_connection()
        with SessionLocal() as db:
            vulnerability = load_vulnerability(db, cve_id)
            if vulnerability is None:
                print(f"CVE introuvable: {cve_id}")
                return 1

            affected_count = len(vulnerability.affected_products)
            active_assets = count_active_assets(db)
            real_results = correlate_vulnerability(db, cve_id)

            print("Correlation engine: OK")
            print(f"CVE: {cve_id}")
            print(f"Affected products: {affected_count}")
            print(f"Active assets: {active_assets}")
            print("")
            print("Real assets:")
            for result in real_results:
                print_result(result)

            print("")
            print("Synthetic tests:")
            if not run_synthetic_tests(vulnerability):
                return 1

            db.rollback()

        print("")
        print("PHASE 4.3 CORRELATION CHECK: OK")
        return 0
    except SQLAlchemyError as exc:
        print(f"ERREUR PostgreSQL: {exc}")
        return 1
    except RuntimeError as exc:
        print(f"ERREUR: {exc}")
        return 1


def normalize_cve_arg() -> str:
    if len(sys.argv) > 2:
        print("Usage: .\\.venv\\Scripts\\python.exe scripts\\check_phase4_correlation.py CVE-YYYY-NNNN")
        raise SystemExit(1)
    if len(sys.argv) == 2:
        return sys.argv[1].strip().upper()
    return DEFAULT_CVE_ID


def load_vulnerability(db, cve_id: str) -> Vulnerability | None:
    return db.execute(
        select(Vulnerability)
        .options(selectinload(Vulnerability.affected_products))
        .where(Vulnerability.cve_id == cve_id)
    ).scalar_one_or_none()


def count_active_assets(db) -> int:
    return db.scalar(select(func.count(Asset.id)).where(Asset.is_active.is_(True))) or 0


def print_result(result: AssetVulnerabilityCorrelationResult) -> None:
    print(f"{result.asset_name} -> {result.status.value}")
    print(f"  Reason: {result.reason}")


def run_synthetic_tests(vulnerability: Vulnerability) -> bool:
    netty_product = select_netty_affected_product(vulnerability)
    if netty_product is None:
        print("Synthetic tests: FAILED (produit netty introuvable)")
        return False

    vulnerable_version = choose_vulnerable_version(netty_product)
    safe_version = choose_safe_version(netty_product)
    if vulnerable_version is None or safe_version is None:
        print("Synthetic tests: FAILED (bornes Netty insuffisantes)")
        return False

    tests = [
        (
            "Apache vs Netty",
            build_synthetic_asset(
                name="TEST-APACHE",
                vendor="Apache",
                product="HTTP Server",
                product_version=vulnerable_version,
            ),
            CorrelationStatus.NO_MATCH,
        ),
        (
            f"Netty vulnerable version ({vulnerable_version})",
            build_synthetic_asset(
                name="TEST-NETTY-VULNERABLE",
                vendor="Netty",
                product="Netty",
                product_version=vulnerable_version,
            ),
            CorrelationStatus.MATCH,
        ),
        (
            f"Netty safe version ({safe_version})",
            build_synthetic_asset(
                name="TEST-NETTY-SAFE",
                vendor="Netty",
                product="Netty",
                product_version=safe_version,
            ),
            CorrelationStatus.NO_MATCH,
        ),
        (
            "Netty unknown version",
            build_synthetic_asset(
                name="TEST-NETTY-UNKNOWN-VERSION",
                vendor="Netty",
                product="Netty",
                product_version=None,
            ),
            CorrelationStatus.POSSIBLE_MATCH,
        ),
        (
            "Insufficient asset data",
            build_synthetic_asset(
                name="TEST-INSUFFICIENT",
                vendor=None,
                product=None,
                product_version=None,
            ),
            CorrelationStatus.UNKNOWN,
        ),
    ]

    for label, asset, expected_status in tests:
        result = evaluate_asset_vulnerability(asset, vulnerability)
        print(f"{label} -> {result.status.value}")
        print(f"  Reason: {result.reason}")
        if result.status != expected_status:
            print(
                "Synthetic tests: FAILED "
                f"({label}: attendu {expected_status.value}, obtenu {result.status.value})"
            )
            return False

    return True


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


def build_synthetic_asset(
    name: str,
    vendor: str | None,
    product: str | None,
    product_version: str | None,
) -> Asset:
    return Asset(
        id=f"synthetic-{name.lower()}",
        name=name,
        asset_type=AssetType.APPLICATION,
        vendor=vendor,
        product=product,
        product_version=product_version,
        criticality=AssetCriticality.MEDIUM,
        environment=AssetEnvironment.TEST,
        is_active=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())

r"""
Diagnostic read-only de correlation pour une CVE deja enrichie.

Usage:
    .\.venv\Scripts\python.exe scripts\test_existing_cve_correlation.py CVE-2026-15748

Le script appelle uniquement evaluate_asset_vulnerability(). Il ne persiste
aucune correlation, ne cree aucune alerte et ne commit jamais la session.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import selectinload

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, get_safe_database_url, test_database_connection  # noqa: E402
from app.models.asset import Asset  # noqa: E402
from app.models.vulnerability import Vulnerability  # noqa: E402
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct  # noqa: E402
from app.services.correlation_service import (  # noqa: E402
    AffectedProductEvaluation,
    AssetVulnerabilityCorrelationResult,
    evaluate_asset_vulnerability,
)


def main() -> int:
    args = parse_args()
    cve_id = args.cve_id.strip().upper()

    print("ThreatWatch - test read-only de correlation CVE")
    print(f"DATABASE_URL={get_safe_database_url()}")
    print(f"CVE cible={cve_id}")
    print("")

    try:
        test_database_connection()
        with SessionLocal() as db:
            vulnerability = load_vulnerability(db, cve_id)
            if vulnerability is None:
                print(f"ERREUR: vulnerability introuvable pour {cve_id}")
                db.rollback()
                return 1

            print_vulnerability(vulnerability)
            assets = load_active_assets(db)
            print_assets_header(assets)

            for asset in assets:
                result = evaluate_asset_vulnerability(asset, vulnerability)
                print_asset_result(asset, vulnerability.affected_products, result)

            db.rollback()
        print("READ-ONLY CHECK: OK (aucun commit, aucune persistance)")
        return 0
    except Exception as exc:
        print(f"ERREUR: {exc}")
        return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Teste en lecture seule la correlation entre une CVE et les actifs actifs.",
    )
    parser.add_argument("cve_id", help="Identifiant CVE, exemple CVE-2026-15748")
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


def print_vulnerability(vulnerability: Vulnerability) -> None:
    print("=== Vulnerability ===")
    print(f"cve_id: {vulnerability.cve_id}")
    print(f"enrichment_status: {enum_value(vulnerability.enrichment_status)}")
    print(f"cvss_score: {value_or_dash(vulnerability.cvss_score)}")
    print(f"cvss_severity: {value_or_dash(vulnerability.cvss_severity)}")
    print("")

    print("=== VulnerabilityAffectedProduct ===")
    affected_products = list(vulnerability.affected_products or [])
    print(f"count: {len(affected_products)}")
    if not affected_products:
        print("Aucun produit affecte charge pour cette CVE.")
        print("")
        return

    for index, product in enumerate(affected_products, start=1):
        print(f"[{index}] id: {product.id}")
        print(f"    vendor: {value_or_dash(product.vendor)}")
        print(f"    product: {value_or_dash(product.product)}")
        print(f"    version: {value_or_dash(product.version)}")
        print(f"    version_start_including: {value_or_dash(product.version_start_including)}")
        print(f"    version_start_excluding: {value_or_dash(product.version_start_excluding)}")
        print(f"    version_end_including: {value_or_dash(product.version_end_including)}")
        print(f"    version_end_excluding: {value_or_dash(product.version_end_excluding)}")
        print(f"    vulnerable: {product.vulnerable}")
        print(f"    cpe: {value_or_dash(product.cpe)}")
    print("")


def print_assets_header(assets: list[Asset]) -> None:
    print("=== Assets actifs ===")
    print(f"count: {len(assets)}")
    print("")


def print_asset_result(
    asset: Asset,
    affected_products: list[VulnerabilityAffectedProduct],
    result: AssetVulnerabilityCorrelationResult,
) -> None:
    print(f"--- Asset: {asset.name} ---")
    print(f"asset_id: {asset.id}")
    print(f"vendor: {value_or_dash(asset.vendor)}")
    print(f"product: {value_or_dash(asset.product)}")
    print(f"version: {value_or_dash(asset.product_version)}")
    print(f"cpe: {value_or_dash(asset.cpe)}")
    print(f"result: {enum_value(result.status)}")
    print(f"reason: {result.reason}")

    primary = select_primary_evaluation(result)
    if primary is None:
        print("vendor_result: -")
        print("product_result: -")
        print("version_result: -")
        print("cpe_result: -")
    else:
        print(f"vendor_result: {enum_value(primary.vendor_result)}")
        print(f"product_result: {enum_value(primary.product_result)}")
        print(f"version_result: {enum_value(primary.version_result)}")
        print(f"cpe_result: {enum_value(primary.cpe_result)}")

    if result.affected_product_results:
        print("affected_product_evaluations:")
        products_by_id = {product.id: product for product in affected_products}
        for index, evaluation in enumerate(result.affected_product_results, start=1):
            product = products_by_id.get(evaluation.affected_product_id or "")
            print(f"  [{index}] affected_product_id: {value_or_dash(evaluation.affected_product_id)}")
            if product is not None:
                print(f"      affected_vendor: {value_or_dash(product.vendor)}")
                print(f"      affected_product: {value_or_dash(product.product)}")
                print(f"      affected_version: {value_or_dash(product.version)}")
                print(f"      affected_cpe: {value_or_dash(product.cpe)}")
            print(f"      status: {enum_value(evaluation.status)}")
            print(f"      reason: {evaluation.reason}")
            print(f"      vendor_result: {enum_value(evaluation.vendor_result)}")
            print(f"      product_result: {enum_value(evaluation.product_result)}")
            print(f"      version_result: {enum_value(evaluation.version_result)}")
            print(f"      cpe_result: {enum_value(evaluation.cpe_result)}")
    else:
        print("affected_product_evaluations: 0")
    print("")


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


def enum_value(value) -> str:
    return getattr(value, "value", str(value or "")).strip() or "-"


def value_or_dash(value) -> str:
    if value is None:
        return "-"
    text = str(value)
    return text if text else "-"


if __name__ == "__main__":
    raise SystemExit(main())

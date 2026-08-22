r"""
Liste des CVE enrichies qui possedent des produits affectes en base.

Usage:
    .\.venv\Scripts\python.exe scripts\find_cve_with_affected_products.py

Read-only: appelle uniquement evaluate_asset_vulnerability(), sans persister
de correlation, sans creer d'alerte et sans commit.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from app.db.database import SessionLocal, get_safe_database_url, test_database_connection  # noqa: E402
from app.models.asset import Asset  # noqa: E402
from app.models.vulnerability import EnrichmentStatus, Vulnerability  # noqa: E402
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct  # noqa: E402
from app.services.correlation_service import (  # noqa: E402
    AffectedProductEvaluation,
    AssetVulnerabilityCorrelationResult,
    evaluate_asset_vulnerability,
)


MAX_CVES = 20
TARGET_ASSET_NAMES = ("SRV-WEB-01", "SRV-DB-01", "WP-FORMINATOR-TEST")


def main() -> int:
    print("ThreatWatch - CVE enrichies avec produits affectes")
    print(f"DATABASE_URL={get_safe_database_url()}")
    print(f"Limite: {MAX_CVES} CVE")
    print("")

    try:
        test_database_connection()
        with SessionLocal() as db:
            assets = load_target_active_assets(db)
            all_vulnerabilities = load_vulnerabilities(db)
            vulnerabilities = select_display_vulnerabilities(all_vulnerabilities, assets)
            print_header(vulnerabilities, assets)

            if not vulnerabilities:
                print("Aucune CVE SUCCESS avec VulnerabilityAffectedProduct trouvee.")
                db.rollback()
                return 0

            compatible_candidates = []
            for vulnerability in vulnerabilities:
                has_signal = print_vulnerability_block(vulnerability, assets)
                if has_signal:
                    compatible_candidates.append(vulnerability.cve_id)

            print_summary(compatible_candidates)
            db.rollback()
        print("READ-ONLY CHECK: OK (aucun commit, aucune alerte creee)")
        return 0
    except Exception as exc:
        print(f"ERREUR: {exc}")
        return 1


def load_vulnerabilities(db) -> list[Vulnerability]:
    ranked_ids = (
        select(
            Vulnerability.id,
            func.count(VulnerabilityAffectedProduct.id).label("affected_count"),
        )
        .join(
            VulnerabilityAffectedProduct,
            VulnerabilityAffectedProduct.vulnerability_id == Vulnerability.id,
        )
        .where(Vulnerability.enrichment_status == EnrichmentStatus.SUCCESS)
        .group_by(Vulnerability.id)
        .order_by(
            Vulnerability.cvss_score.desc().nullslast(),
            func.count(VulnerabilityAffectedProduct.id).desc(),
            Vulnerability.cve_id.asc(),
        )
        .subquery()
    )

    return list(
        db.execute(
            select(Vulnerability)
            .join(ranked_ids, Vulnerability.id == ranked_ids.c.id)
            .options(selectinload(Vulnerability.affected_products))
            .order_by(
                Vulnerability.cvss_score.desc().nullslast(),
                ranked_ids.c.affected_count.desc(),
                Vulnerability.cve_id.asc(),
            )
        ).scalars()
    )


def select_display_vulnerabilities(
    vulnerabilities: list[Vulnerability],
    assets: list[Asset],
) -> list[Vulnerability]:
    compatible = []
    others = []
    for vulnerability in vulnerabilities:
        if has_match_signal(vulnerability, assets):
            compatible.append(vulnerability)
        else:
            others.append(vulnerability)
    return (compatible + others)[:MAX_CVES]


def has_match_signal(vulnerability: Vulnerability, assets: list[Asset]) -> bool:
    for asset in assets:
        status = enum_value(evaluate_asset_vulnerability(asset, vulnerability).status)
        if status in {"MATCH", "POSSIBLE_MATCH"}:
            return True
    return False


def load_target_active_assets(db) -> list[Asset]:
    return list(
        db.execute(
            select(Asset)
            .where(
                Asset.is_active.is_(True),
                Asset.name.in_(TARGET_ASSET_NAMES),
            )
            .order_by(Asset.name.asc(), Asset.id.asc())
        ).scalars()
    )


def print_header(vulnerabilities: list[Vulnerability], assets: list[Asset]) -> None:
    print("=== Selection DB ===")
    print(f"CVE affichees: {len(vulnerabilities)}")
    print("Critere: enrichment_status=SUCCESS et affected_products >= 1")
    print("")
    print("=== Assets actifs compares ===")
    if not assets:
        print("Aucun des actifs cibles n'est actif/present.")
    for asset in assets:
        print(
            f"- {asset.name}: vendor={value_or_dash(asset.vendor)}, "
            f"product={value_or_dash(asset.product)}, "
            f"version={value_or_dash(asset.product_version)}, "
            f"cpe={value_or_dash(asset.cpe)}"
        )
    print("")


def print_vulnerability_block(
    vulnerability: Vulnerability,
    assets: list[Asset],
) -> bool:
    affected_products = list(vulnerability.affected_products or [])
    print(f"=== {vulnerability.cve_id} ===")
    print(f"cvss_score: {value_or_dash(vulnerability.cvss_score)}")
    print(f"cvss_severity: {value_or_dash(vulnerability.cvss_severity)}")
    print(f"affected products: {len(affected_products)}")
    print("")

    print("Produits affectes:")
    for index, product in enumerate(affected_products, start=1):
        print(f"  [{index}]")
        print(f"    vendor: {value_or_dash(product.vendor)}")
        print(f"    product: {value_or_dash(product.product)}")
        print(f"    version: {value_or_dash(product.version)}")
        print(f"    version_start_including: {value_or_dash(product.version_start_including)}")
        print(f"    version_start_excluding: {value_or_dash(product.version_start_excluding)}")
        print(f"    version_end_including: {value_or_dash(product.version_end_including)}")
        print(f"    version_end_excluding: {value_or_dash(product.version_end_excluding)}")
        print(f"    cpe: {value_or_dash(product.cpe)}")
    print("")

    has_signal = False
    print("Comparaison avec actifs existants:")
    if not assets:
        print("  Aucun actif cible actif a comparer.")
    for asset in assets:
        result = evaluate_asset_vulnerability(asset, vulnerability)
        primary = select_primary_evaluation(result)
        status = enum_value(result.status)
        if status in {"MATCH", "POSSIBLE_MATCH"}:
            has_signal = True
        print(f"  - {asset.name}: {status}")
        print(f"    asset vendor/product/version: {value_or_dash(asset.vendor)} / {value_or_dash(asset.product)} / {value_or_dash(asset.product_version)}")
        print(f"    reason: {result.reason}")
        if primary is not None:
            print(f"    vendor_result: {enum_value(primary.vendor_result)}")
            print(f"    product_result: {enum_value(primary.product_result)}")
            print(f"    version_result: {enum_value(primary.version_result)}")
            print(f"    cpe_result: {enum_value(primary.cpe_result)}")
    print("")
    return has_signal


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


def print_summary(compatible_candidates: list[str]) -> None:
    print("=== Synthese ===")
    if compatible_candidates:
        print("CVE semblant compatibles avec au moins un actif existant:")
        for cve_id in compatible_candidates:
            print(f"- {cve_id}")
    else:
        print("Aucune des CVE affichees ne donne MATCH/POSSIBLE_MATCH avec les actifs cibles.")
    print("")


def enum_value(value) -> str:
    return getattr(value, "value", str(value or "")).strip() or "-"


def value_or_dash(value) -> str:
    if value is None:
        return "-"
    text = str(value)
    return text if text else "-"


if __name__ == "__main__":
    raise SystemExit(main())

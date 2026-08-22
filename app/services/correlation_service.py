"""
Moteur de correlation en lecture seule Asset <-> Vulnerability.

La phase 4.3.1 evalue les correspondances en memoire uniquement. Elle ne
persiste aucun match, ne cree aucune alerte et ne calcule aucun score SOC.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.vulnerability_affected_product import VulnerabilityAffectedProduct
from app.services.correlation_normalization_service import (
    MatchResult,
    cpe_matches,
    parse_cpe_23,
    product_matches,
    vendor_matches,
    version_matches,
)


class CorrelationStatus(str, enum.Enum):
    MATCH = "MATCH"
    POSSIBLE_MATCH = "POSSIBLE_MATCH"
    NO_MATCH = "NO_MATCH"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class AffectedProductEvaluation:
    status: CorrelationStatus
    reason: str
    affected_product_id: str | None = None
    cpe_result: MatchResult = MatchResult.UNKNOWN
    vendor_result: MatchResult = MatchResult.UNKNOWN
    product_result: MatchResult = MatchResult.UNKNOWN
    version_result: MatchResult = MatchResult.UNKNOWN


@dataclass(frozen=True)
class AssetVulnerabilityCorrelationResult:
    asset_id: str | None
    asset_name: str
    vulnerability_id: str | None
    cve_id: str
    status: CorrelationStatus
    reason: str
    matched_affected_product_id: str | None = None
    asset_criticality: str | None = None
    asset_environment: str | None = None
    affected_product_results: list[AffectedProductEvaluation] = field(
        default_factory=list
    )


def evaluate_asset_vulnerability(
    asset: Asset,
    vulnerability: Vulnerability,
) -> AssetVulnerabilityCorrelationResult:
    if getattr(asset, "is_active", True) is False:
        return build_result(
            asset=asset,
            vulnerability=vulnerability,
            status=CorrelationStatus.UNKNOWN,
            reason="Actif inactif ignore par la correlation operationnelle.",
            evaluations=[],
        )

    affected_products = [
        product
        for product in getattr(vulnerability, "affected_products", []) or []
        if product.vulnerable is True
    ]
    if not affected_products:
        return build_result(
            asset=asset,
            vulnerability=vulnerability,
            status=CorrelationStatus.UNKNOWN,
            reason="Aucun produit vulnerable exploitable n'est disponible pour cette CVE.",
            evaluations=[],
        )

    evaluations = [
        evaluate_affected_product(asset, affected_product)
        for affected_product in affected_products
    ]
    return aggregate_evaluations(asset, vulnerability, evaluations)


def evaluate_affected_product(
    asset: Asset,
    affected_product: VulnerabilityAffectedProduct,
) -> AffectedProductEvaluation:
    if affected_product.vulnerable is not True:
        return AffectedProductEvaluation(
            status=CorrelationStatus.UNKNOWN,
            reason="Entree NVD marquee vulnerable=false ignoree pour un match direct.",
            affected_product_id=affected_product.id,
        )

    cpe_result = evaluate_cpe(asset, affected_product)
    if cpe_result == MatchResult.MATCH:
        version_result = evaluate_version(asset, affected_product)
        if version_result == MatchResult.MATCH:
            return AffectedProductEvaluation(
                status=CorrelationStatus.MATCH,
                reason="CPE compatible et version de l'actif dans la plage vulnerable NVD.",
                affected_product_id=affected_product.id,
                cpe_result=cpe_result,
                version_result=version_result,
            )
        if version_result == MatchResult.NO_MATCH:
            return AffectedProductEvaluation(
                status=CorrelationStatus.NO_MATCH,
                reason="CPE compatible mais version de l'actif hors de la plage vulnerable.",
                affected_product_id=affected_product.id,
                cpe_result=cpe_result,
                version_result=version_result,
            )
        return AffectedProductEvaluation(
            status=CorrelationStatus.POSSIBLE_MATCH,
            reason="CPE compatible mais version de l'actif inconnue ou non comparable.",
            affected_product_id=affected_product.id,
            cpe_result=cpe_result,
            version_result=version_result,
        )

    vendor_result = vendor_matches(asset.vendor, affected_product.vendor)
    product_result = product_matches(asset.product, affected_product.product)

    if vendor_result == MatchResult.NO_MATCH or product_result == MatchResult.NO_MATCH:
        return AffectedProductEvaluation(
            status=CorrelationStatus.NO_MATCH,
            reason="Vendor ou produit different de la configuration vulnerable NVD.",
            affected_product_id=affected_product.id,
            cpe_result=cpe_result,
            vendor_result=vendor_result,
            product_result=product_result,
        )

    if vendor_result == MatchResult.UNKNOWN or product_result == MatchResult.UNKNOWN:
        return AffectedProductEvaluation(
            status=CorrelationStatus.UNKNOWN,
            reason="Informations vendor/product insuffisantes pour conclure.",
            affected_product_id=affected_product.id,
            cpe_result=cpe_result,
            vendor_result=vendor_result,
            product_result=product_result,
        )

    version_result = evaluate_version(asset, affected_product)
    if version_result == MatchResult.MATCH:
        return AffectedProductEvaluation(
            status=CorrelationStatus.MATCH,
            reason="Vendor, produit et version correspondent a une configuration vulnerable NVD.",
            affected_product_id=affected_product.id,
            cpe_result=cpe_result,
            vendor_result=vendor_result,
            product_result=product_result,
            version_result=version_result,
        )
    if version_result == MatchResult.NO_MATCH:
        return AffectedProductEvaluation(
            status=CorrelationStatus.NO_MATCH,
            reason="Vendor et produit correspondent, mais la version est hors plage vulnerable.",
            affected_product_id=affected_product.id,
            cpe_result=cpe_result,
            vendor_result=vendor_result,
            product_result=product_result,
            version_result=version_result,
        )
    return AffectedProductEvaluation(
        status=CorrelationStatus.POSSIBLE_MATCH,
        reason="Produit correspondant mais version de l'actif inconnue ou non comparable.",
        affected_product_id=affected_product.id,
        cpe_result=cpe_result,
        vendor_result=vendor_result,
        product_result=product_result,
        version_result=version_result,
    )


def evaluate_cpe(
    asset: Asset,
    affected_product: VulnerabilityAffectedProduct,
) -> MatchResult:
    if not asset.cpe or not affected_product.cpe:
        return MatchResult.UNKNOWN
    return cpe_matches(asset.cpe, affected_product.cpe)


def evaluate_version(
    asset: Asset,
    affected_product: VulnerabilityAffectedProduct,
) -> MatchResult:
    asset_version = asset.product_version or extract_version_from_cpe(asset.cpe)
    return version_matches(
        asset_version=asset_version,
        cpe_version=affected_product.version,
        version_start_including=affected_product.version_start_including,
        version_start_excluding=affected_product.version_start_excluding,
        version_end_including=affected_product.version_end_including,
        version_end_excluding=affected_product.version_end_excluding,
    )


def extract_version_from_cpe(cpe: str | None) -> str | None:
    parsed = parse_cpe_23(cpe)
    if parsed is None:
        return None
    return parsed.version


def aggregate_evaluations(
    asset: Asset,
    vulnerability: Vulnerability,
    evaluations: list[AffectedProductEvaluation],
) -> AssetVulnerabilityCorrelationResult:
    for evaluation in evaluations:
        if evaluation.status == CorrelationStatus.MATCH:
            return build_result(
                asset=asset,
                vulnerability=vulnerability,
                status=CorrelationStatus.MATCH,
                reason=evaluation.reason,
                evaluations=evaluations,
                matched_affected_product_id=evaluation.affected_product_id,
            )

    for evaluation in evaluations:
        if evaluation.status == CorrelationStatus.POSSIBLE_MATCH:
            return build_result(
                asset=asset,
                vulnerability=vulnerability,
                status=CorrelationStatus.POSSIBLE_MATCH,
                reason=evaluation.reason,
                evaluations=evaluations,
                matched_affected_product_id=evaluation.affected_product_id,
            )

    if evaluations and all(
        evaluation.status == CorrelationStatus.NO_MATCH for evaluation in evaluations
    ):
        return build_result(
            asset=asset,
            vulnerability=vulnerability,
            status=CorrelationStatus.NO_MATCH,
            reason="Toutes les configurations vulnerables evaluables sont incompatibles avec l'actif.",
            evaluations=evaluations,
        )

    return build_result(
        asset=asset,
        vulnerability=vulnerability,
        status=CorrelationStatus.UNKNOWN,
        reason="Les informations disponibles ne permettent pas de conclure sans risque.",
        evaluations=evaluations,
    )


def build_result(
    asset: Asset,
    vulnerability: Vulnerability,
    status: CorrelationStatus,
    reason: str,
    evaluations: list[AffectedProductEvaluation],
    matched_affected_product_id: str | None = None,
) -> AssetVulnerabilityCorrelationResult:
    return AssetVulnerabilityCorrelationResult(
        asset_id=getattr(asset, "id", None),
        asset_name=getattr(asset, "name", "") or "-",
        vulnerability_id=getattr(vulnerability, "id", None),
        cve_id=getattr(vulnerability, "cve_id", "") or "-",
        status=status,
        reason=reason,
        matched_affected_product_id=matched_affected_product_id,
        asset_criticality=enum_value(getattr(asset, "criticality", None)),
        asset_environment=enum_value(getattr(asset, "environment", None)),
        affected_product_results=evaluations,
    )


def enum_value(value) -> str | None:
    if value is None:
        return None
    return getattr(value, "value", str(value))


def correlate_vulnerability(
    db: Session,
    cve_id: str,
) -> list[AssetVulnerabilityCorrelationResult]:
    vulnerability = db.execute(
        select(Vulnerability)
        .options(selectinload(Vulnerability.affected_products))
        .where(Vulnerability.cve_id == cve_id.strip().upper())
    ).scalar_one_or_none()
    if vulnerability is None:
        return []

    assets = (
        db.execute(select(Asset).where(Asset.is_active.is_(True)).order_by(Asset.name))
        .scalars()
        .all()
    )
    return [
        evaluate_asset_vulnerability(asset, vulnerability)
        for asset in assets
    ]

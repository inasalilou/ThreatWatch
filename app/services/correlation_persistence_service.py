"""
Persistance controlee des resultats de correlation.

Le calcul reste dans correlation_service.py. Ce module applique uniquement les
regles d'ecriture en base pour MATCH/POSSIBLE_MATCH et la desactivation des
anciennes correlations devenues NO_MATCH.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset_vulnerability_correlation import (
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.vulnerability import Vulnerability
from app.services.correlation_service import (
    AssetVulnerabilityCorrelationResult,
    CorrelationStatus,
    evaluate_asset_vulnerability,
)
from app.services.alert_service import create_alert_from_correlation


PERSISTED_STATUSES = {
    CorrelationStatus.MATCH,
    CorrelationStatus.POSSIBLE_MATCH,
}


def evaluate_and_persist_asset_vulnerability(
    db: Session,
    asset: Asset,
    vulnerability: Vulnerability,
) -> AssetVulnerabilityCorrelationResult:
    result = evaluate_asset_vulnerability(asset, vulnerability)
    persist_correlation_result(db, result)
    return result


def persist_correlation_result(
    db: Session,
    result: AssetVulnerabilityCorrelationResult,
) -> AssetVulnerabilityCorrelation | None:
    if not result.asset_id or not result.vulnerability_id:
        return None

    existing = find_existing_correlation(
        db=db,
        asset_id=result.asset_id,
        vulnerability_id=result.vulnerability_id,
    )

    if result.status in PERSISTED_STATUSES:
        correlation = upsert_relevant_correlation(db, result, existing)
        trigger_alert_for_match(db, correlation)
        return correlation

    if result.status == CorrelationStatus.NO_MATCH:
        if existing is not None and existing.is_active:
            apply_no_match_deactivation(existing, result)
            db.flush()
        return existing

    # UNKNOWN ne desactive pas une preuve precedente : le manque de donnees
    # n'est pas une preuve que la correlation n'existe plus.
    return existing


def trigger_alert_for_match(
    db: Session,
    correlation: AssetVulnerabilityCorrelation,
) -> None:
    if correlation.status != CorrelationPersistenceStatus.MATCH:
        return
    create_alert_from_correlation(db, correlation.id)


def find_existing_correlation(
    db: Session,
    asset_id: str,
    vulnerability_id: str,
) -> AssetVulnerabilityCorrelation | None:
    return db.execute(
        select(AssetVulnerabilityCorrelation).where(
            AssetVulnerabilityCorrelation.asset_id == asset_id,
            AssetVulnerabilityCorrelation.vulnerability_id == vulnerability_id,
        )
    ).scalar_one_or_none()


def upsert_relevant_correlation(
    db: Session,
    result: AssetVulnerabilityCorrelationResult,
    existing: AssetVulnerabilityCorrelation | None,
) -> AssetVulnerabilityCorrelation:
    now = datetime.utcnow()
    details = select_detail_for_persistence(result)

    if existing is None:
        correlation = AssetVulnerabilityCorrelation(
            asset_id=result.asset_id,
            vulnerability_id=result.vulnerability_id,
            status=to_persistence_status(result.status),
            reason=result.reason,
            matched_affected_product_id=result.matched_affected_product_id,
            vendor_result=enum_value(details.vendor_result) if details else None,
            product_result=enum_value(details.product_result) if details else None,
            version_result=enum_value(details.version_result) if details else None,
            cpe_result=enum_value(details.cpe_result) if details else None,
            first_detected_at=now,
            last_evaluated_at=now,
            is_active=True,
        )
        db.add(correlation)
        db.flush()
        return correlation

    existing.status = to_persistence_status(result.status)
    existing.reason = result.reason
    existing.matched_affected_product_id = result.matched_affected_product_id
    existing.vendor_result = enum_value(details.vendor_result) if details else None
    existing.product_result = enum_value(details.product_result) if details else None
    existing.version_result = enum_value(details.version_result) if details else None
    existing.cpe_result = enum_value(details.cpe_result) if details else None
    existing.last_evaluated_at = now
    existing.is_active = True
    db.flush()
    return existing


def apply_no_match_deactivation(
    correlation: AssetVulnerabilityCorrelation,
    result: AssetVulnerabilityCorrelationResult,
) -> None:
    details = select_detail_for_persistence(result)
    correlation.status = CorrelationPersistenceStatus.NO_MATCH
    correlation.reason = result.reason
    correlation.matched_affected_product_id = None
    correlation.vendor_result = enum_value(details.vendor_result) if details else None
    correlation.product_result = enum_value(details.product_result) if details else None
    correlation.version_result = enum_value(details.version_result) if details else None
    correlation.cpe_result = enum_value(details.cpe_result) if details else None
    correlation.last_evaluated_at = datetime.utcnow()
    correlation.is_active = False


def select_detail_for_persistence(result: AssetVulnerabilityCorrelationResult):
    if result.matched_affected_product_id:
        for detail in result.affected_product_results:
            if detail.affected_product_id == result.matched_affected_product_id:
                return detail

    for detail in result.affected_product_results:
        if detail.status == result.status:
            return detail

    if result.affected_product_results:
        return result.affected_product_results[0]
    return None


def to_persistence_status(
    status: CorrelationStatus,
) -> CorrelationPersistenceStatus:
    return CorrelationPersistenceStatus(status.value)


def enum_value(value) -> str | None:
    if value is None:
        return None
    return getattr(value, "value", str(value))

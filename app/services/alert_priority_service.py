"""
Calcul deterministe de priorite SOC pour les alertes.

Le score reste volontairement simple: chaque composante est lisible dans un
rapport et le total est borne entre 0 et 100.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

from app.models.alert import AlertPriority
from app.models.asset import Asset, AssetCriticality, AssetEnvironment
from app.models.asset_vulnerability_correlation import (
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.vulnerability import Vulnerability


CVSS_NULL_POINTS = Decimal("15.00")
SCORE_MIN = Decimal("0.00")
SCORE_MAX = Decimal("100.00")
SCORE_QUANTUM = Decimal("0.01")

ASSET_CRITICALITY_POINTS = {
    AssetCriticality.CRITICAL.value: Decimal("30.00"),
    AssetCriticality.HIGH.value: Decimal("20.00"),
    AssetCriticality.MEDIUM.value: Decimal("10.00"),
    AssetCriticality.LOW.value: Decimal("5.00"),
}

ENVIRONMENT_POINTS = {
    AssetEnvironment.PRODUCTION.value: Decimal("15.00"),
    AssetEnvironment.PREPRODUCTION.value: Decimal("10.00"),
    AssetEnvironment.DEVELOPMENT.value: Decimal("5.00"),
    AssetEnvironment.TEST.value: Decimal("2.00"),
    AssetEnvironment.OTHER.value: Decimal("5.00"),
}

CORRELATION_POINTS = {
    CorrelationPersistenceStatus.MATCH.value: Decimal("5.00"),
    CorrelationPersistenceStatus.POSSIBLE_MATCH.value: Decimal("2.00"),
    CorrelationPersistenceStatus.NO_MATCH.value: Decimal("0.00"),
    CorrelationPersistenceStatus.UNKNOWN.value: Decimal("0.00"),
}


@dataclass(frozen=True)
class AlertPriorityResult:
    score: Decimal
    level: AlertPriority
    reason: str
    cvss_points: Decimal
    asset_criticality_points: Decimal
    environment_points: Decimal
    correlation_points: Decimal


def calculate_alert_priority(
    asset: Asset,
    vulnerability: Vulnerability,
    correlation: AssetVulnerabilityCorrelation,
) -> AlertPriorityResult:
    cvss_points = calculate_cvss_points(vulnerability)
    asset_points = get_mapping_points(
        asset.criticality,
        ASSET_CRITICALITY_POINTS,
        default=ASSET_CRITICALITY_POINTS[AssetCriticality.MEDIUM.value],
    )
    environment_points = get_mapping_points(
        asset.environment,
        ENVIRONMENT_POINTS,
        default=ENVIRONMENT_POINTS[AssetEnvironment.OTHER.value],
    )
    correlation_points = get_mapping_points(
        correlation.status,
        CORRELATION_POINTS,
        default=Decimal("0.00"),
    )

    score = clamp_score(
        cvss_points + asset_points + environment_points + correlation_points
    )
    level = priority_level_from_score(score)
    reason = build_priority_reason(
        level=level,
        vulnerability=vulnerability,
        asset=asset,
        correlation=correlation,
        cvss_points=cvss_points,
        asset_points=asset_points,
        environment_points=environment_points,
        correlation_points=correlation_points,
        score=score,
    )

    return AlertPriorityResult(
        score=score,
        level=level,
        reason=reason,
        cvss_points=cvss_points,
        asset_criticality_points=asset_points,
        environment_points=environment_points,
        correlation_points=correlation_points,
    )


def calculate_cvss_points(vulnerability: Vulnerability) -> Decimal:
    if vulnerability.cvss_score is None:
        return CVSS_NULL_POINTS

    try:
        cvss_score = Decimal(str(vulnerability.cvss_score))
    except (InvalidOperation, ValueError):
        return CVSS_NULL_POINTS

    cvss_score = min(max(cvss_score, Decimal("0.00")), Decimal("10.00"))
    return quantize_score(cvss_score * Decimal("5.00"))


def priority_level_from_score(score: Decimal) -> AlertPriority:
    if score >= Decimal("80.00"):
        return AlertPriority.CRITICAL
    if score >= Decimal("60.00"):
        return AlertPriority.HIGH
    if score >= Decimal("40.00"):
        return AlertPriority.MEDIUM
    return AlertPriority.LOW


def build_priority_reason(
    *,
    level: AlertPriority,
    vulnerability: Vulnerability,
    asset: Asset,
    correlation: AssetVulnerabilityCorrelation,
    cvss_points: Decimal,
    asset_points: Decimal,
    environment_points: Decimal,
    correlation_points: Decimal,
    score: Decimal,
) -> str:
    cvss_label = (
        f"CVSS {vulnerability.cvss_score}"
        if vulnerability.cvss_score is not None
        else "CVSS absent"
    )
    return (
        f"Priorite {level.value} calculee: {cvss_label} ({format_points(cvss_points)}), "
        f"actif {enum_value(asset.criticality)} ({format_points(asset_points)}), "
        f"environnement {enum_value(asset.environment)} "
        f"({format_points(environment_points)}), correlation "
        f"{enum_value(correlation.status)} ({format_points(correlation_points)}), "
        f"total {format_points(score)}."
    )


def get_mapping_points(value, mapping: dict[str, Decimal], default: Decimal) -> Decimal:
    return mapping.get(enum_value(value), default)


def enum_value(value) -> str:
    raw_value = getattr(value, "value", value)
    return (raw_value or "").strip().upper()


def clamp_score(score: Decimal) -> Decimal:
    return quantize_score(min(max(score, SCORE_MIN), SCORE_MAX))


def quantize_score(score: Decimal) -> Decimal:
    return score.quantize(SCORE_QUANTUM, rounding=ROUND_HALF_UP)


def format_points(value: Decimal) -> str:
    normalized = value.quantize(SCORE_QUANTUM, rounding=ROUND_HALF_UP)
    if normalized == normalized.to_integral():
        return str(int(normalized))
    return str(normalized)

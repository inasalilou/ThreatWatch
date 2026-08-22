"""
Lecture des correlations persistantes pour l'interface.

Ce service ne lance aucun recalcul et ne contacte aucun service externe. Il lit
uniquement les correlations deja enregistrees en base.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
import math

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType
from app.models.asset_vulnerability_correlation import (
    AssetVulnerabilityCorrelation,
    CorrelationPersistenceStatus,
)
from app.models.vulnerability import Vulnerability


DISPLAY_STATUSES = (
    CorrelationPersistenceStatus.MATCH,
    CorrelationPersistenceStatus.POSSIBLE_MATCH,
)
PER_PAGE = 20


@dataclass(frozen=True)
class AssetCorrelationView:
    correlation_id: str
    vulnerability_id: str
    cve_id: str
    status: CorrelationPersistenceStatus
    reason: str | None
    cvss_score: Decimal | None
    cvss_severity: str | None
    cvss_version: str | None
    first_detected_at: datetime
    last_evaluated_at: datetime
    is_active: bool


@dataclass(frozen=True)
class VulnerabilityCorrelationView:
    correlation_id: str
    asset_id: str
    asset_name: str
    asset_type: AssetType
    vendor: str | None
    product: str | None
    product_version: str | None
    criticality: AssetCriticality
    environment: AssetEnvironment
    status: CorrelationPersistenceStatus
    reason: str | None
    first_detected_at: datetime
    last_evaluated_at: datetime
    is_active: bool


@dataclass(frozen=True)
class CorrelationListItem:
    correlation_id: str
    asset_id: str
    asset_name: str
    hostname: str | None
    vendor: str | None
    product: str | None
    product_version: str | None
    criticality: AssetCriticality
    environment: AssetEnvironment
    vulnerability_id: str
    cve_id: str
    status: CorrelationPersistenceStatus
    reason: str | None
    cvss_score: Decimal | None
    cvss_severity: str | None
    cvss_version: str | None
    first_detected_at: datetime
    last_evaluated_at: datetime
    is_active: bool


@dataclass(frozen=True)
class CorrelationSearchResult:
    items: list[CorrelationListItem]
    total: int
    page: int
    per_page: int
    total_pages: int
    query: str
    status: str
    activity: str
    criticality: str
    environment: str
    cvss_severity: str

    @property
    def has_previous(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages


@dataclass(frozen=True)
class CorrelationStats:
    total_correlations: int
    active_match: int
    active_possible_match: int
    inactive_correlations: int


def get_correlations_for_asset(
    db: Session,
    asset_id: str,
    include_inactive: bool = False,
) -> list[AssetCorrelationView]:
    statement = (
        select(AssetVulnerabilityCorrelation, Vulnerability)
        .join(
            Vulnerability,
            AssetVulnerabilityCorrelation.vulnerability_id == Vulnerability.id,
        )
        .where(AssetVulnerabilityCorrelation.asset_id == asset_id)
        .where(AssetVulnerabilityCorrelation.status.in_(DISPLAY_STATUSES))
        .order_by(
            status_rank_expression(),
            AssetVulnerabilityCorrelation.last_evaluated_at.desc(),
            Vulnerability.cve_id.asc(),
        )
    )
    if not include_inactive:
        statement = statement.where(AssetVulnerabilityCorrelation.is_active.is_(True))

    rows = db.execute(statement).all()
    return [
        AssetCorrelationView(
            correlation_id=correlation.id,
            vulnerability_id=vulnerability.id,
            cve_id=vulnerability.cve_id,
            status=correlation.status,
            reason=correlation.reason,
            cvss_score=vulnerability.cvss_score,
            cvss_severity=vulnerability.cvss_severity,
            cvss_version=vulnerability.cvss_version,
            first_detected_at=correlation.first_detected_at,
            last_evaluated_at=correlation.last_evaluated_at,
            is_active=correlation.is_active,
        )
        for correlation, vulnerability in rows
    ]


def get_correlations_for_vulnerability(
    db: Session,
    vulnerability_id: str,
    include_inactive: bool = False,
) -> list[VulnerabilityCorrelationView]:
    statement = (
        select(AssetVulnerabilityCorrelation, Asset)
        .join(Asset, AssetVulnerabilityCorrelation.asset_id == Asset.id)
        .where(AssetVulnerabilityCorrelation.vulnerability_id == vulnerability_id)
        .where(AssetVulnerabilityCorrelation.status.in_(DISPLAY_STATUSES))
        .order_by(
            status_rank_expression(),
            AssetVulnerabilityCorrelation.last_evaluated_at.desc(),
            Asset.name.asc(),
        )
    )
    if not include_inactive:
        statement = statement.where(AssetVulnerabilityCorrelation.is_active.is_(True))

    rows = db.execute(statement).all()
    return [
        VulnerabilityCorrelationView(
            correlation_id=correlation.id,
            asset_id=asset.id,
            asset_name=asset.name,
            asset_type=asset.asset_type,
            vendor=asset.vendor,
            product=asset.product,
            product_version=asset.product_version,
            criticality=asset.criticality,
            environment=asset.environment,
            status=correlation.status,
            reason=correlation.reason,
            first_detected_at=correlation.first_detected_at,
            last_evaluated_at=correlation.last_evaluated_at,
            is_active=correlation.is_active,
        )
        for correlation, asset in rows
    ]


def list_correlations(
    db: Session,
    query: str = "",
    status: str = "",
    activity: str = "active",
    criticality: str = "",
    environment: str = "",
    cvss_severity: str = "",
    page: int = 1,
    per_page: int = PER_PAGE,
) -> CorrelationSearchResult:
    page = max(page, 1)
    per_page = max(per_page, 1)
    cleaned_query = query.strip()
    cleaned_status = status.strip().upper()
    cleaned_activity = normalize_activity_filter(activity)
    cleaned_criticality = criticality.strip().upper()
    cleaned_environment = environment.strip().upper()
    cleaned_cvss_severity = cvss_severity.strip().upper()

    filters = build_correlation_filters(
        query=cleaned_query,
        status=cleaned_status,
        activity=cleaned_activity,
        criticality=cleaned_criticality,
        environment=cleaned_environment,
        cvss_severity=cleaned_cvss_severity,
    )

    base_statement = (
        select(AssetVulnerabilityCorrelation.id)
        .join(Asset, AssetVulnerabilityCorrelation.asset_id == Asset.id)
        .join(
            Vulnerability,
            AssetVulnerabilityCorrelation.vulnerability_id == Vulnerability.id,
        )
        .where(*filters)
    )
    total = db.scalar(select(func.count()).select_from(base_statement.subquery())) or 0
    total_pages = max(math.ceil(total / per_page), 1)
    if page > total_pages:
        page = total_pages

    statement = (
        select(AssetVulnerabilityCorrelation, Asset, Vulnerability)
        .join(Asset, AssetVulnerabilityCorrelation.asset_id == Asset.id)
        .join(
            Vulnerability,
            AssetVulnerabilityCorrelation.vulnerability_id == Vulnerability.id,
        )
        .where(*filters)
        .order_by(
            AssetVulnerabilityCorrelation.is_active.desc(),
            AssetVulnerabilityCorrelation.last_evaluated_at.desc(),
            Vulnerability.cve_id.asc(),
            Asset.name.asc(),
        )
        .limit(per_page)
        .offset((page - 1) * per_page)
    )

    rows = db.execute(statement).all()
    return CorrelationSearchResult(
        items=[
            CorrelationListItem(
                correlation_id=correlation.id,
                asset_id=asset.id,
                asset_name=asset.name,
                hostname=asset.hostname,
                vendor=asset.vendor,
                product=asset.product,
                product_version=asset.product_version,
                criticality=asset.criticality,
                environment=asset.environment,
                vulnerability_id=vulnerability.id,
                cve_id=vulnerability.cve_id,
                status=correlation.status,
                reason=correlation.reason,
                cvss_score=vulnerability.cvss_score,
                cvss_severity=vulnerability.cvss_severity,
                cvss_version=vulnerability.cvss_version,
                first_detected_at=correlation.first_detected_at,
                last_evaluated_at=correlation.last_evaluated_at,
                is_active=correlation.is_active,
            )
            for correlation, asset, vulnerability in rows
        ],
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        query=cleaned_query,
        status=cleaned_status,
        activity=cleaned_activity,
        criticality=cleaned_criticality,
        environment=cleaned_environment,
        cvss_severity=cleaned_cvss_severity,
    )


def get_correlation_stats(db: Session) -> CorrelationStats:
    total_correlations = db.scalar(select(func.count(AssetVulnerabilityCorrelation.id))) or 0
    active_match = (
        db.scalar(
            select(func.count(AssetVulnerabilityCorrelation.id)).where(
                AssetVulnerabilityCorrelation.is_active.is_(True),
                AssetVulnerabilityCorrelation.status == CorrelationPersistenceStatus.MATCH,
            )
        )
        or 0
    )
    active_possible_match = (
        db.scalar(
            select(func.count(AssetVulnerabilityCorrelation.id)).where(
                AssetVulnerabilityCorrelation.is_active.is_(True),
                AssetVulnerabilityCorrelation.status
                == CorrelationPersistenceStatus.POSSIBLE_MATCH,
            )
        )
        or 0
    )
    inactive_correlations = (
        db.scalar(
            select(func.count(AssetVulnerabilityCorrelation.id)).where(
                AssetVulnerabilityCorrelation.is_active.is_(False)
            )
        )
        or 0
    )
    return CorrelationStats(
        total_correlations=total_correlations,
        active_match=active_match,
        active_possible_match=active_possible_match,
        inactive_correlations=inactive_correlations,
    )


def build_correlation_filters(
    query: str = "",
    status: str = "",
    activity: str = "active",
    criticality: str = "",
    environment: str = "",
    cvss_severity: str = "",
):
    filters = []

    if query:
        pattern = f"%{query}%"
        filters.append(
            or_(
                Vulnerability.cve_id.ilike(pattern),
                Asset.name.ilike(pattern),
                Asset.hostname.ilike(pattern),
                Asset.vendor.ilike(pattern),
                Asset.product.ilike(pattern),
            )
        )

    if status in {CorrelationPersistenceStatus.MATCH.value, CorrelationPersistenceStatus.POSSIBLE_MATCH.value}:
        filters.append(AssetVulnerabilityCorrelation.status == status)
    elif activity == "active":
        filters.append(AssetVulnerabilityCorrelation.status.in_(DISPLAY_STATUSES))

    if activity == "active":
        filters.append(AssetVulnerabilityCorrelation.is_active.is_(True))
    elif activity == "inactive":
        filters.append(AssetVulnerabilityCorrelation.is_active.is_(False))

    if criticality in {item.value for item in AssetCriticality}:
        filters.append(Asset.criticality == criticality)

    if environment in {item.value for item in AssetEnvironment}:
        filters.append(Asset.environment == environment)

    if cvss_severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        filters.append(Vulnerability.cvss_severity == cvss_severity)

    return filters


def normalize_activity_filter(value: str) -> str:
    cleaned = value.strip().lower()
    if cleaned in {"active", "inactive", "all"}:
        return cleaned
    return "active"


def get_correlation_status_options() -> list[tuple[str, str]]:
    return [
        (CorrelationPersistenceStatus.MATCH.value, "Correspondance confirmee"),
        (
            CorrelationPersistenceStatus.POSSIBLE_MATCH.value,
            "Correspondance possible",
        ),
    ]


def get_activity_options() -> list[tuple[str, str]]:
    return [
        ("active", "Actives"),
        ("inactive", "Inactives"),
        ("all", "Toutes"),
    ]


def get_cvss_severity_options() -> list[str]:
    return ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def status_rank_expression():
    return case(
        (AssetVulnerabilityCorrelation.status == CorrelationPersistenceStatus.MATCH, 0),
        (
            AssetVulnerabilityCorrelation.status
            == CorrelationPersistenceStatus.POSSIBLE_MATCH,
            1,
        ),
        else_=2,
    )


def correlation_status_label(status: CorrelationPersistenceStatus | str | None) -> str:
    value = enum_value(status)
    return {
        CorrelationPersistenceStatus.MATCH.value: "Correspondance confirmee",
        CorrelationPersistenceStatus.POSSIBLE_MATCH.value: "Correspondance possible",
        CorrelationPersistenceStatus.NO_MATCH.value: "Non correspondant",
        CorrelationPersistenceStatus.UNKNOWN.value: "Inconnu",
    }.get(value or "", "Inconnu")


def correlation_status_tone(status: CorrelationPersistenceStatus | str | None) -> str:
    value = enum_value(status)
    return {
        CorrelationPersistenceStatus.MATCH.value: "tone-critical",
        CorrelationPersistenceStatus.POSSIBLE_MATCH.value: "tone-warning",
        CorrelationPersistenceStatus.NO_MATCH.value: "tone-neutral",
        CorrelationPersistenceStatus.UNKNOWN.value: "tone-neutral",
    }.get(value or "", "tone-neutral")


def correlation_activity_label(is_active: bool) -> str:
    return "Active" if is_active else "Inactive"


def correlation_activity_tone(is_active: bool) -> str:
    return "tone-success" if is_active else "tone-neutral"


def enum_value(value) -> str | None:
    if value is None:
        return None
    return getattr(value, "value", str(value))
